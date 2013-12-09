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

/*
 * TODO:
 *
 * every user has different instance of the module
 * does this also work for different networks of one user? - must be but better try it
 * ... but the keys/fps/instags are shared among networks, no?
 *
 * protocol id - "prpl-irc" or "IRC" ?
 *
 * check if user is admin using CModule::GetUser && CUser::IsAdmin and print a
 * fat warning if he is not
 *
 * call otrl_message_poll periodically
 *
 * module callbacks may be invoked even if no client is attached - we probably
 * should save the module messages and replay them later
 *
 * formatting (80? 100?), consistent naming, brace style
 *
 * logging - can we detect if it's turned on? can we turn it off? what is
 * logged on the bouncer, plain/ciphertext?
 */

using std::vector;
using std::cout;

/* forward, needed by the module */
OtrlMessageAppOps InitOps();

#define PROTOCOL_ID "irc"

// helpers

const char* strdup_new(const char *str) {
	size_t len = strlen(str);
	char *dup = new char[len + 1];
	strncpy(dup, str, len)[len] = '\0';

	return dup;
}

// end helpers

class COtrMod : public CModule {
public: /* XXX */
	OtrlUserState m_pUserState = NULL;
	OtrlMessageAppOps m_xOtrOps; //FIXME: we can init this just once
	CString *pPrivkeyPath = NULL; //FIXME: can I use a = constructor?
	CString *pFPPath = NULL; //FIXME: m_
	CString *pInsTagPath = NULL;

	void dbg(CString s)
	{
		cout << s << "\n";
	}

public:
	MODCONSTRUCTOR(COtrMod) {}

	virtual bool OnLoad(const CString& sArgs, CString& sMessage) {

		// Initialize libotr if needed
		static bool otrInitialized = false;
		if (!otrInitialized) {
			OTRL_INIT;
			otrInitialized = true;
		}

		// Initialize userstate
		m_pUserState = otrl_userstate_create();

		pPrivkeyPath = new CString(GetSavePath() + "/otr.key");
		pFPPath = new CString(GetSavePath() + "/otr.fp");
		pInsTagPath = new CString(GetSavePath() + "/otr.instag");
		gcry_error_t err;

		//FIXME: OUTPUT
		// Load private key
		err = otrl_privkey_read(m_pUserState, pPrivkeyPath->c_str());
		if (err == GPG_ERR_NO_ERROR)
			dbg(CString("Private keys loaded from ") + *pPrivkeyPath + ".");
		else if (err == gcry_error_from_errno(ENOENT))
			dbg("No private key found, you need to generate one.");
		else
			dbg(CString("Failed to load private key: ") + gcry_strerror(err) + ".");

		// Load fingerprints
		err = otrl_privkey_read_fingerprints(m_pUserState, pFPPath->c_str(), NULL, NULL);
		if (err == GPG_ERR_NO_ERROR)
			dbg(CString("Fingerprints loaded from ") + *pFPPath + ".");
		else if (err == gcry_error_from_errno(ENOENT))
			dbg("No fingerprint file found.");
		else
			dbg(CString("Failed to load fingerprints: ") + gcry_strerror(err) + ".");

		//  Load instance tags
		err = otrl_instag_read(m_pUserState, pInsTagPath->c_str());
		if (err == GPG_ERR_NO_ERROR)
			dbg("Instance tags loaded from " + *pInsTagPath + ".");
		else if (err == gcry_error_from_errno(ENOENT))
			dbg("No instance tag file found.");
		else
			dbg(CString("Failed to load instance tags: ") + gcry_strerror(err) + ".");

		m_xOtrOps = InitOps();

		return true;
	}

	virtual ~COtrMod() {
		if (m_pUserState)
			otrl_userstate_free(m_pUserState);
		delete pPrivkeyPath;
		delete pFPPath;
		delete pInsTagPath;
	}

	virtual EModRet OnUserMsg(CString& sTarget, CString& sMessage) {
		PutModule("OnUserMsg " + sTarget + ": " + sMessage);

		// Do not pass the message to libotr if sTarget is a channel
		CIRCNetwork *network = GetNetwork();
		assert(network);

		bool bTargetIsChan;;
		if (sTarget.empty()) {
			bTargetIsChan = true;
		} else if (network->GetChanPrefixes().empty()) {
			// RFC 2811
			bTargetIsChan = (CString("&#!+").find(sTarget[0]) != CString::npos);
		} else {
			bTargetIsChan = (network->GetChanPrefixes().find(sTarget[0]) != CString::npos);
		}

		if (bTargetIsChan) {
			PutModule("Target is channel, not encrypting");
			return CONTINUE;
		}

		gcry_error_t err;
		char *newmessage = NULL;

		/* XXX: Due to a bug in libotr-4.0.0, we cannot pass
		 * OTRL_FRAGMENT_SEND_ALL (fixed in d748757). For now, we send
		 * the message ourselves, without fragmentation.
		 */
		err = otrl_message_sending(m_pUserState, &m_xOtrOps, this, "FIXME", PROTOCOL_ID, sTarget.c_str(), OTRL_INSTAG_BEST /*FIXME*/, sMessage.c_str(), NULL, &newmessage, OTRL_FRAGMENT_SEND_SKIP, NULL, NULL, NULL);

		if (err) {
			PutModule(CString("otrl_message_sending failed: ") + gcry_strerror(err));
			return HALT;
		}

		assert(newmessage);
		// FIXME: aren't we leaking the memory of original sMessage?
		sMessage = CString(newmessage);
		PutModule("Sending '" + sMessage + "'");
		otrl_message_free(newmessage);

		return CONTINUE;
	}

	virtual EModRet OnPrivMsg(CNick& Nick, CString& sMessage) {
                /* incoming private messages */
		//PutModule("[" + Nick.GetNick() +  ", " + Nick.GetHost() + "] privmsg [" + sMessage + "]");

		int res;
		char *newmessage = NULL;
		res = otrl_message_receiving(m_pUserState, &m_xOtrOps, this, "FIXME"/*should not really matter?*/, PROTOCOL_ID, Nick.GetNick().c_str() /* @server? */, sMessage.c_str(), &newmessage, NULL, NULL, NULL, NULL);

		if (res == 1) {
			PutModule("Received internal OTR message");
			return HALT;
		} else if (res != 0) {
			PutModule(CString("otrl_message_receiving: unknown return code ") + CString(res));
			return HALT;
		} else if (newmessage == NULL) {
			PutModule("Received non-encrypted privmsg");
			return CONTINUE;
		} else {
			// FIXME: aren't we leaking the memory of original sMessage?
			PutModule("Received encrypted privmsg");
			sMessage = CString(newmessage);
			otrl_message_free(newmessage);
			return CONTINUE;
		}
	}

	/* OnPrivAction/CTCP? */

	virtual void OnModCommand(const CString& sCommand) {
		if (sCommand.Equals("TIMERS")) {
			ListTimers();
		}
		else
		{
			PutModule(GetModDataDir());
			PutModule(GetSavePath());
			PutModule(GetModPath());
		}
	}

	virtual EModRet OnStatusCommand(CString& sCommand) {
		if (sCommand.Equals("SAMPLE")) {
			PutModule("Hi, I'm your friendly sample module.");
			return HALT;
		}

		return CONTINUE;
	}
};

template<> void TModInfo<COtrMod>(CModInfo& Info) {
	Info.SetWikiPage("otr");
	Info.SetHasArgs(true); //FIXME
	Info.SetArgsHelpText("FIXME");
}

USERMODULEDEFS(COtrMod, "FIXME")

// libotr callbacks

OtrlPolicy otrPolicy(void *opdata, ConnContext *context) {
	return OTRL_POLICY_DEFAULT;
}

void otrCreatePrivkey(void *opdata, const char *accountname, const char *protocol) {
	/* TODO: key generation needs to happen in background thread */
	COtrMod *mod = static_cast<COtrMod*>(opdata);
	assert(mod);
	assert(0 == strcmp(protocol, PROTOCOL_ID));
	assert(mod->m_pUserState);
	assert(mod->pPrivkeyPath);

	mod->PutModule("otrCreatePrivkey: this will take a shitload of time, freezing ZNC.");
	gcry_error_t err;
	err = otrl_privkey_generate(mod->m_pUserState, mod->pPrivkeyPath->c_str(), accountname, protocol);

	if (err) {
		mod->PutModule(CString("otrCreatePrivkey: error: ") + gcry_strerror(err) + ".");
	} else
		mod->PutModule("otrCreatePrivkey: done.");
}

int otrIsLoggedIn(void *opdata, const char *accountname, const char *protocol, const char *recipient) {
	// 1 = online, 0 = offline, -1 = not sure
	return -1;
}

void otrInjectMessage(void *opdata, const char *accountname, const char *protocol, const char *recipient, const char *message) {
	COtrMod *mod = static_cast<COtrMod*>(opdata);
	assert(mod);
	assert(0 == strcmp(protocol, PROTOCOL_ID));

	mod->PutModule("otrInjectMessage:");
	mod->PutModule(accountname);
	mod->PutModule(recipient);
	mod->PutModule(message);

	//TODO: is there a better way to send the message?
	mod->PutIRC(CString("PRIVMSG ") + recipient + " :" + message);
}

void otrUpdateContextList(void *opdata) {
	/* do nothing? */
	COtrMod *mod = static_cast<COtrMod*>(opdata);
	assert(mod);
	mod->PutModule("Not implemented: otrUpdateContextList");
}

void otrNewFingerprint(void *opdata, OtrlUserState us, const char *accountname, const char *protocol, const char *username, unsigned char fingerprint[20]) {
	/* TODO */
	COtrMod *mod = static_cast<COtrMod*>(opdata);
	assert(mod);
	mod->PutModule("Not implemented: otrNewFingerprint");
}

void otrWriteFingerprints(void *opdata)
{
	/* TODO: write fingerprints to disk */
	COtrMod *mod = static_cast<COtrMod*>(opdata);
	assert(mod);
	mod->PutModule("Not implemented: otrWriteFingerprints");
}

void otrGoneSecure(void *opdata, ConnContext *context) {
	/* TODO */
	COtrMod *mod = static_cast<COtrMod*>(opdata);
	assert(mod);
	mod->PutModule("Not implemented: otrGoneSecure");
}

void otrGoneInsecure(void *opdata, ConnContext *context) {
	/* TODO */
	COtrMod *mod = static_cast<COtrMod*>(opdata);
	assert(mod);
	mod->PutModule("Not implemented: otrGoneInsecure");
}

void otrStillSecure(void *opdata, ConnContext *context, int is_reply) {
	/* TODO */
	COtrMod *mod = static_cast<COtrMod*>(opdata);
	assert(mod);
	mod->PutModule("Not implemented: otrStillSecure");
}

int otrMaxMessageSize(void *opdata, ConnContext *context) {
	return 400; /* TODO */
}

const char* otrAccountName(void *opdata, const char *account, const char *protocol) {
	/* TODO */
	return strdup_new(account);
}

void otrFreeString(void *opdata, const char *str) {
	delete[] str;
}

void otrReceiveSymkey(void *opdata, ConnContext *context, unsigned int use, const unsigned char *usedata, size_t usedatalen, const unsigned char *symkey) {
	/* We don't have any use for a symmetric key. */
	return;
}

const char* otrErrorMessage(void *opdata, ConnContext *context, OtrlErrorCode err_code) {
	/* TODO: improve the explanations */
	switch (err_code){
	case OTRL_ERRCODE_ENCRYPTION_ERROR:
		return strdup_new("Error encrypting message.");
	case OTRL_ERRCODE_MSG_NOT_IN_PRIVATE:
		return strdup_new("Sent an encrypted message to somebody who is not in OTR session.");
	case OTRL_ERRCODE_MSG_UNREADABLE:
		return strdup_new("Sent an unreadable encrypted message.");
	case OTRL_ERRCODE_MSG_MALFORMED:
		return strdup_new("Malformed message sent.");
	default:
		return strdup_new("Unknown error.");
	}
}

void otrHandleSMPEvent(void *opdata, OtrlSMPEvent smp_event, ConnContext *context, unsigned short progress_percent, char *question) {
	/* TODO: replace assert with something sensible. */
	COtrMod *mod = static_cast<COtrMod*>(opdata);
	assert(mod);
	mod->PutModule("Not implemented: otrHandleSMPEvent");
}

void otrHandleMsgEvent(void *opdata, OtrlMessageEvent msg_event, ConnContext *context, const char *message, gcry_error_t err) {
	COtrMod *mod = static_cast<COtrMod*>(opdata);
	assert(mod);

	switch (msg_event) {
	case OTRL_MSGEVENT_ENCRYPTION_REQUIRED:
		mod->PutModule("Our policy requires encryption but we are trying to send an unencrypted message out.");
		break;
	case OTRL_MSGEVENT_ENCRYPTION_ERROR:
		mod->PutModule("An error occured while encrypting a message and the message was not sent.");
		break;
	case OTRL_MSGEVENT_CONNECTION_ENDED:
		mod->PutModule("Message has not been sent because our buddy has ended the private conversation. We should either close the connection, or refresh it.");
		break;
	case OTRL_MSGEVENT_SETUP_ERROR:
		mod->PutModule("A private conversation could not be set up."); //TODO: A gcry_error_t will be passed.
		break;
	case OTRL_MSGEVENT_MSG_REFLECTED:
		mod->PutModule("Received our own OTR messages.");
		break;
	case OTRL_MSGEVENT_MSG_RESENT:
		mod->PutModule("The previous message was resent.");
		break;
	case OTRL_MSGEVENT_RCVDMSG_NOT_IN_PRIVATE:
		mod->PutModule("Received an encrypted message but cannot read it because no private connection is established yet.");
		break;
	case OTRL_MSGEVENT_RCVDMSG_UNREADABLE:
		mod->PutModule("Cannot read the received message.");
		break;
	case OTRL_MSGEVENT_RCVDMSG_MALFORMED:
		mod->PutModule("The message received contains malformed data.");
		break;
	case OTRL_MSGEVENT_LOG_HEARTBEAT_RCVD:
		mod->PutModule("Received a heartbeat.");
		break;
	case OTRL_MSGEVENT_LOG_HEARTBEAT_SENT:
		mod->PutModule("Sent a heartbeat.");
		break;
	case OTRL_MSGEVENT_RCVDMSG_GENERAL_ERR:
		mod->PutModule("Received a general OTR error."); //TODO: The argument 'message' will also be passed and it will contain the OTR error message.
		break;
	case OTRL_MSGEVENT_RCVDMSG_UNENCRYPTED:
		mod->PutModule("Received an unencrypted message."); //TODO: The argument 'smessage' will also be passed and it will contain the plaintext message.
		break;
	case OTRL_MSGEVENT_RCVDMSG_UNRECOGNIZED:
		mod->PutModule("Cannot recognize the type of OTR message received.");
		break;
	case OTRL_MSGEVENT_RCVDMSG_FOR_OTHER_INSTANCE:
		mod->PutModule("Received and discarded a message intended for another instance.");
		break;
	default:
		mod->PutModule("Unknown message event.");
		break;
	}
}

void otrCreateInsTag(void *opdata, const char *accountname, const char *protocol) {
	COtrMod *mod = static_cast<COtrMod*>(opdata);
	assert(mod);

	OtrlUserState us = mod->m_pUserState;
	assert(us);

	otrl_instag_generate(us, mod->pInsTagPath->c_str(), accountname, protocol);
}

// end of callbacks

OtrlMessageAppOps InitOps() {
	return (OtrlMessageAppOps){
		/* policy */		otrPolicy,
		/* create_privkey */	otrCreatePrivkey,
		/* is_logged_in */	otrIsLoggedIn,
		/* inject_message */	otrInjectMessage,
		/* update_context_list */ otrUpdateContextList,
		/* new_fingerprint */	otrNewFingerprint,
		/* write_fingerprints */ otrWriteFingerprints,
		/* gone_secure */	otrGoneSecure,
		/* gone_insecure */	otrGoneInsecure,
		/* still_secure */	otrStillSecure,
		/* max_message_size */	otrMaxMessageSize,
		/* account_name */	otrAccountName,
		/* account_name_free */	otrFreeString,
		/* received_symkey */	otrReceiveSymkey,
		/* otr_error_message */	otrErrorMessage,
		/* otr_error_message_free */ otrFreeString,
		/* resent_msg_prefix */	NULL, /* uses [resent] by default */
		/* resent_msg_prefix_free */ NULL,
		/* handle_smp_event */	otrHandleSMPEvent,
		/* handle_msg_event */	otrHandleMsgEvent,
		/* create_instag */	otrCreateInsTag,
		/* convert_msg */	NULL, /* no conversion */
		/* convert_free */	NULL,
		/* timer_control */	NULL /* we'll handle the timer ourselves */
	};
}

