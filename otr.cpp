/*
 * Copyright (C) 2004-2013 ZNC, see the NOTICE file for details.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <znc/IRCNetwork.h>
#include <znc/Client.h>
#include <znc/User.h>
#include <znc/Chan.h>
#include <znc/Modules.h>

extern "C" {
#include <libotr/proto.h>
#include <libotr/message.h>
#include <libotr/userstate.h>
#include <libotr/privkey.h>
#include <libotr/instag.h>
}

#include <iostream>
#include <cstring>
#include <cassert>
#include <list>

/*
 * TODO:
 *
 * every user has different instance of the module
 * does this also work for different networks of one user? - must be but better try it
 * ... but the keys/fps/instags are shared among networks, no?
 * we need to include the network in account names (and possibly have separate key/etc files)
 *
 * check if user is admin using CModule::GetUser && CUser::IsAdmin and print a
 * fat warning if he is not
 *
 * consistent naming, brace style
 *
 * logging - can we detect if it's turned on? can we turn it off? what is
 * logged on the bouncer, plain/ciphertext?
 *
 * encrypt outgoing ACTIONs
 * http://www.cypherpunks.ca/pipermail/otr-dev/2012-December/001520.html
 */

using std::vector;
using std::cout;
using std::list;

//TODO: "prpl-irc"? "IRC"?
#define PROTOCOL_ID "irc"

class COtrTimer : public CTimer {
public:
	COtrTimer(CModule* pModule, unsigned int uInterval)
		: CTimer(pModule, uInterval, /*run forever*/ 0, "OtrTimer", "OTR message poll") {}
	virtual ~COtrTimer() {}
protected:
	virtual void RunJob();
};

class COtrMod : public CModule {
private:
	static OtrlMessageAppOps m_xOtrOps;
	OtrlUserState m_pUserState;
	CString m_sPrivkeyPath;
	CString m_sFPPath;
	CString m_sInsTagPath;
	list<CString> m_Buffer;

public:
	MODCONSTRUCTOR(COtrMod) {}

	bool PutModuleBuffered(const CString &sLine) {
		CUser *user = GetUser();
		bool attached = user->IsUserAttached();
		if (attached) {
			PutModule(sLine);
		} else {
			m_Buffer.push_back(sLine);
		}
		return attached;
	}

	bool PutModuleContext(ConnContext *ctx, const CString& sLine) {
		assert(ctx);
		assert(ctx->username);
		return PutModuleBuffered(CString("[") + ctx->username + "] " + sLine);
	}

	virtual bool OnLoad(const CString& sArgs, CString& sMessage) {
		// Initialize libotr if needed
		static bool otrInitialized = false;
		if (!otrInitialized) {
			OTRL_INIT;
			otrInitialized = true;
		}

		// Initialize userstate
		m_pUserState = otrl_userstate_create();

		m_sPrivkeyPath = GetSavePath() + "/otr.key";
		m_sFPPath = GetSavePath() + "/otr.fp";
		m_sInsTagPath = GetSavePath() + "/otr.instag";
		gcry_error_t err;

		// Load private key
		err = otrl_privkey_read(m_pUserState, m_sPrivkeyPath.c_str());
		if (err == GPG_ERR_NO_ERROR) {
			PutModuleBuffered("Private keys loaded from " + m_sPrivkeyPath + ".");
		} else if (err == gcry_error_from_errno(ENOENT)) {
			PutModuleBuffered("No private key found.");
		} else {
			sMessage = (CString("Failed to load private key: ") + gcry_strerror(err) + ".");
			return false;
		}

		// Load fingerprints
		err = otrl_privkey_read_fingerprints(m_pUserState, m_sFPPath.c_str(), NULL, NULL);
		if (err == GPG_ERR_NO_ERROR) {
			PutModuleBuffered("Fingerprints loaded from " + m_sFPPath + ".");
		} else if (err == gcry_error_from_errno(ENOENT)) {
			PutModuleBuffered("No fingerprint file found.");
		} else {
			sMessage = (CString("Failed to load fingerprints: ") + gcry_strerror(err) + ".");
			return false;
		}

		//  Load instance tags
		err = otrl_instag_read(m_pUserState, m_sInsTagPath.c_str());
		if (err == GPG_ERR_NO_ERROR) {
			PutModuleBuffered("Instance tags loaded from " + m_sInsTagPath + ".");
		} else if (err == gcry_error_from_errno(ENOENT)) {
			PutModuleBuffered("No instance tag file found.");
		} else {
			sMessage = (CString("Failed to load instance tags: ") + gcry_strerror(err) + ".");
			return false;
		}

		//TODO: find out whether it's safe to remove a timer from within its own RunJob()
		//method and if it's ok then use the timer_control callback
		AddTimer(new COtrTimer(this, otrl_message_poll_get_default_interval(m_pUserState)));

		//Initialize commands here using AddCommand()

		return true;
	}

	virtual ~COtrMod() {
		if (m_pUserState)
			otrl_userstate_free(m_pUserState);
	}

	virtual EModRet OnUserMsg(CString& sTarget, CString& sMessage) {
		CIRCNetwork *network = GetNetwork(); //FIXME: can return null in user module
		assert(network);

		// Do not pass the message to libotr if sTarget is a channel
		bool bTargetIsChan;;
		if (sTarget.empty()) {
			bTargetIsChan = true;
		} else if (network->GetChanPrefixes().empty()) {
			// RFC 2811
			bTargetIsChan = (CString("&#!+").find(sTarget[0]) != CString::npos);
		} else {
			bTargetIsChan =
				(network->GetChanPrefixes().find(sTarget[0]) != CString::npos);
		}

		if (bTargetIsChan) {
			return CONTINUE;
		}

		gcry_error_t err;
		char *newmessage = NULL;
		//FIXME: shouldn't we also include the network?
		const char *accountname = GetUser()->GetUserName().c_str();

		/* XXX: Due to a bug in libotr-4.0.0, we cannot pass
		 * OTRL_FRAGMENT_SEND_ALL (fixed in d748757). For now, we send
		 * the message ourselves, without fragmentation.
		 *
		 * I have an idea for workaround but it's fugly.
		 */
		err = otrl_message_sending(m_pUserState, &m_xOtrOps, this, accountname, PROTOCOL_ID,
				sTarget.c_str(), OTRL_INSTAG_BEST /*FIXME*/, sMessage.c_str(),
				NULL, &newmessage, OTRL_FRAGMENT_SEND_SKIP, NULL, NULL, NULL);

		if (err) {
			PutModuleBuffered(CString("otrl_message_sending failed: ") + gcry_strerror(err));
			return HALT;
		}

		assert(newmessage);
		sMessage = CString(newmessage);
		otrl_message_free(newmessage);

		return CONTINUE;
	}

	virtual EModRet OnPrivMsg(CNick& Nick, CString& sMessage) {
		int res;
		char *newmessage = NULL;
		const char *accountname = GetUser()->GetUserName().c_str();
		res = otrl_message_receiving(m_pUserState, &m_xOtrOps, this, accountname,
				PROTOCOL_ID, Nick.GetNick().c_str() /* @server? */,
				sMessage.c_str(), &newmessage, NULL, NULL, NULL, NULL);

		if (res == 1) {
			//PutModule("Received internal OTR message");
			return HALT;
		} else if (res != 0) {
			PutModuleBuffered(CString("otrl_message_receiving: unknown return code ")
					+ CString(res));
			return HALT;
		} else if (newmessage == NULL) {
			//PutModule("Received non-encrypted privmsg");
			return CONTINUE;
		} else {
			//PutModule("Received encrypted privmsg");
			sMessage = CString(newmessage);
			otrl_message_free(newmessage);
			return CONTINUE;
		}
	}

	virtual void OnClientLogin() {
		for (list<CString>::iterator it = m_Buffer.begin();
				it != m_Buffer.end();
				it++) {
			PutModule(*it);
		}
		m_Buffer.clear();
	}

	void TimerFires() {
		//XXX: PutModule doesn't seem to do anything when called from timer context,
		//can that be a problem?
		otrl_message_poll(m_pUserState, &m_xOtrOps, this);
	}

private:
	// libotr callbacks

	static OtrlPolicy otrPolicy(void *opdata, ConnContext *context) {
		return OTRL_POLICY_DEFAULT;
	}

	static void otrCreatePrivkey(void *opdata, const char *accountname, const char *protocol) {
		/* TODO: key generation needs to happen in background thread */
		COtrMod *mod = static_cast<COtrMod*>(opdata);
		assert(mod);
		assert(0 == strcmp(protocol, PROTOCOL_ID));
		assert(mod->m_pUserState);
		assert(!mod->m_sPrivkeyPath.empty());

		mod->PutModuleBuffered("otrCreatePrivkey: this will take a shitload of time, "
				"freezing ZNC.");
		gcry_error_t err;
		err = otrl_privkey_generate(mod->m_pUserState, mod->m_sPrivkeyPath.c_str(),
				accountname, protocol);

		if (err) {
			mod->PutModuleBuffered(CString("otrCreatePrivkey: error: ") +
					gcry_strerror(err) + ".");
		} else {
			mod->PutModuleBuffered("otrCreatePrivkey: done.");
		}
	}

	static int otrIsLoggedIn(void *opdata, const char *accountname, const char *protocol,
			const char *recipient) {
		// 1 = online, 0 = offline, -1 = not sure
		return -1;
	}

	static void otrInjectMessage(void *opdata, const char *accountname, const char *protocol,
			const char *recipient, const char *message) {
		COtrMod *mod = static_cast<COtrMod*>(opdata);
		assert(mod);
		assert(0 == strcmp(protocol, PROTOCOL_ID));

		//TODO: is there a better way to send the message?
		mod->PutIRC(CString("PRIVMSG ") + recipient + " :" + message);
	}

	static void otrUpdateContextList(void *opdata) {
		/* do nothing? */
		COtrMod *mod = static_cast<COtrMod*>(opdata);
		assert(mod);
		mod->PutModuleBuffered("Not implemented: otrUpdateContextList");
	}

	static void otrNewFingerprint(void *opdata, OtrlUserState us, const char *accountname,
			const char *protocol, const char *username, unsigned char fingerprint[20]) {
		/* TODO */
		COtrMod *mod = static_cast<COtrMod*>(opdata);
		assert(mod);
		mod->PutModuleBuffered("Not implemented: otrNewFingerprint");
	}

	static void otrWriteFingerprints(void *opdata) {
		/* TODO: write fingerprints to disk */
		COtrMod *mod = static_cast<COtrMod*>(opdata);
		assert(mod);
		mod->PutModuleBuffered("Not implemented: otrWriteFingerprints");
	}

	static void otrGoneSecure(void *opdata, ConnContext *context) {
		COtrMod *mod = static_cast<COtrMod*>(opdata);
		assert(mod);
		mod->PutModuleContext(context, "Gone SECURE");
	}

	static void otrGoneInsecure(void *opdata, ConnContext *context) {
		COtrMod *mod = static_cast<COtrMod*>(opdata);
		assert(mod);
		mod->PutModuleContext(context, "Gone INSECURE");
	}

	static void otrStillSecure(void *opdata, ConnContext *context, int is_reply) {
		COtrMod *mod = static_cast<COtrMod*>(opdata);
		assert(mod);
		mod->PutModuleContext(context, "Still SECURE");
	}

	static int otrMaxMessageSize(void *opdata, ConnContext *context) {
		return 400; /* TODO */
	}

	static const char* otrAccountName(void *opdata, const char *account, const char *protocol) {
		/* FIXME: It appears that this callback is not used in libotr ...
		 * depending on how is *account allocated and what is done with the
		 * returned value, just returning it might not be a good idea.
		 */
		return account;
	}

	static void otrFreeStringNop(void *opdata, const char *str) {
	}

	static void otrReceiveSymkey(void *opdata, ConnContext *context, unsigned int use,
			const unsigned char *usedata, size_t usedatalen, const unsigned char *symkey) {
		/* We don't have any use for a symmetric key. */
		return;
	}

	static const char* otrErrorMessage(void *opdata, ConnContext *context, OtrlErrorCode err_code) {
		/* TODO: improve the explanations */
		switch (err_code){
		case OTRL_ERRCODE_ENCRYPTION_ERROR:
			return "Error encrypting message.";
		case OTRL_ERRCODE_MSG_NOT_IN_PRIVATE:
			return "Sent an encrypted message to somebody who is not in OTR session.";
		case OTRL_ERRCODE_MSG_UNREADABLE:
			return "Sent an unreadable encrypted message.";
		case OTRL_ERRCODE_MSG_MALFORMED:
			return "Malformed message sent.";
		default:
			return "Unknown error.";
		}
	}

	static void otrHandleSMPEvent(void *opdata, OtrlSMPEvent smp_event, ConnContext *context,
			unsigned short progress_percent, char *question) {
		COtrMod *mod = static_cast<COtrMod*>(opdata);
		assert(mod);
		mod->PutModuleBuffered("Not implemented: otrHandleSMPEvent");
	}

	static void otrHandleMsgEvent(void *opdata, OtrlMessageEvent msg_event, ConnContext *context,
			const char *message, gcry_error_t err) {
		COtrMod *mod = static_cast<COtrMod*>(opdata);
		assert(mod);

		switch (msg_event) {
		case OTRL_MSGEVENT_ENCRYPTION_REQUIRED:
			mod->PutModuleContext(context, "Our policy requires encryption but we are trying "
					"to send an unencrypted message out.");
			break;
		case OTRL_MSGEVENT_ENCRYPTION_ERROR:
			mod->PutModuleContext(context, "An error occured while encrypting a message and "
					"the message was not sent.");
			break;
		case OTRL_MSGEVENT_CONNECTION_ENDED:
			mod->PutModuleContext(context, "Message has not been sent because our buddy has "
					"ended the private conversation. We should either close the "
					"connection, or refresh it.");
			break;
		case OTRL_MSGEVENT_SETUP_ERROR:
			mod->PutModuleContext(context,
					CString("A private conversation could not be set up: ") +
					gcry_strerror(err));
			break;
		case OTRL_MSGEVENT_MSG_REFLECTED:
			mod->PutModuleContext(context, "Received our own OTR messages.");
			break;
		case OTRL_MSGEVENT_MSG_RESENT:
			mod->PutModuleContext(context, "The previous message was resent.");
			break;
		case OTRL_MSGEVENT_RCVDMSG_NOT_IN_PRIVATE:
			mod->PutModuleContext(context, "Received an encrypted message but cannot read it "
					"because no private connection is established yet.");
			break;
		case OTRL_MSGEVENT_RCVDMSG_UNREADABLE:
			mod->PutModuleContext(context, "Cannot read the received message.");
			break;
		case OTRL_MSGEVENT_RCVDMSG_MALFORMED:
			mod->PutModuleContext(context, "The message received contains malformed data.");
			break;
		case OTRL_MSGEVENT_LOG_HEARTBEAT_RCVD:
			mod->PutModuleContext(context, "Received a heartbeat.");
			break;
		case OTRL_MSGEVENT_LOG_HEARTBEAT_SENT:
			mod->PutModuleContext(context, "Sent a heartbeat.");
			break;
		case OTRL_MSGEVENT_RCVDMSG_GENERAL_ERR:
			mod->PutModuleContext(context, CString("Received a general OTR error: ") + message);
			break;
		case OTRL_MSGEVENT_RCVDMSG_UNENCRYPTED:
			//TODO: send the message to the client
			mod->PutModuleContext(context, CString("Received an unencrypted message: ") +
					message);
			break;
		case OTRL_MSGEVENT_RCVDMSG_UNRECOGNIZED:
			mod->PutModuleContext(context, "Cannot recognize the type of OTR message "
					"received.");
			break;
		case OTRL_MSGEVENT_RCVDMSG_FOR_OTHER_INSTANCE:
			mod->PutModuleContext(context, "Received and discarded a message intended for "
					"another instance.");
			break;
		default:
			mod->PutModuleContext(context, "Unknown message event.");
			break;
		}
	}

	static void otrCreateInsTag(void *opdata, const char *accountname, const char *protocol) {
		COtrMod *mod = static_cast<COtrMod*>(opdata);
		assert(mod);
		assert(!mod->m_sInsTagPath.empty());

		OtrlUserState us = mod->m_pUserState;
		assert(us);

		otrl_instag_generate(us, mod->m_sInsTagPath.c_str(), accountname, protocol);
	}

	static OtrlMessageAppOps InitOps() {
		OtrlMessageAppOps ops;

		ops.policy = otrPolicy;
		ops.create_privkey = otrCreatePrivkey;
		ops.is_logged_in = otrIsLoggedIn;
		ops.inject_message = otrInjectMessage;
		ops.update_context_list =  otrUpdateContextList;
		ops.new_fingerprint = otrNewFingerprint;
		ops.write_fingerprints =  otrWriteFingerprints;
		ops.gone_secure = otrGoneSecure;
		ops.gone_insecure = otrGoneInsecure;
		ops.still_secure = otrStillSecure;
		ops.max_message_size = otrMaxMessageSize;
		ops.account_name = otrAccountName;
		ops.account_name_free = otrFreeStringNop;
		ops.received_symkey = otrReceiveSymkey;
		ops.otr_error_message = otrErrorMessage;
		ops.otr_error_message_free =  otrFreeStringNop;
		ops.resent_msg_prefix = NULL; // uses [resent] by default
		ops.resent_msg_prefix_free =  NULL;
		ops.handle_smp_event = otrHandleSMPEvent;
		ops.handle_msg_event = otrHandleMsgEvent;
		ops.create_instag = otrCreateInsTag;
		ops.convert_msg = NULL; // no conversion
		ops.convert_free = NULL;
		ops.timer_control = NULL; // we'll handle the timer ourselves

		return ops;
	}

	// end of callbacks
};

OtrlMessageAppOps COtrMod::m_xOtrOps = COtrMod::InitOps();

template<> void TModInfo<COtrMod>(CModInfo& Info) {
	Info.SetWikiPage("otr");
	Info.SetHasArgs(false);
	//Info.SetArgsHelpText("No args.");
}

//TODO: make this a network module, maybe?
USERMODULEDEFS(COtrMod, "Off-the-Record (OTR) encryption for private messages")

void COtrTimer::RunJob()
{
	static_cast<COtrMod*>(m_pModule)->TimerFires();
}
