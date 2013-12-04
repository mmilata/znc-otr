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

extern "C" {
#include <libotr/proto.h>
}

#include <znc/Client.h>
#include <znc/Chan.h>
#include <znc/Modules.h>

using std::vector;

#if 0
class CSampleTimer : public CTimer {
public:

	CSampleTimer(CModule* pModule, unsigned int uInterval, unsigned int uCycles, const CString& sLabel, const CString& sDescription) : CTimer(pModule, uInterval, uCycles, sLabel, sDescription) {}
	virtual ~CSampleTimer() {}

private:
protected:
	virtual void RunJob() {
		m_pModule->PutModule("TEST!!!!");
	}
};
#endif

class COtrMod : public CModule {
public:
	MODCONSTRUCTOR(COtrMod) {}

	virtual bool OnLoad(const CString& sArgs, CString& sMessage) {
		PutModule("HI!");
		//AddTimer(new CSampleTimer(this, 300, 0, "Sample", "Sample timer for sample things."));
		//AddTimer(new CSampleTimer(this, 5, 20, "Another", "Another sample timer."));
		//AddTimer(new CSampleTimer(this, 25000, 5, "Third", "A third sample timer."));

                OTRL_INIT; /* FIXME */

		return true;
	}

	virtual ~COtrMod() {
		PutModule("I'm being unloaded!");
	}

	virtual bool OnBoot() {
		// This is called when the app starts up (only modules that are loaded in the config will get this event)
		return true;
	}

	virtual void OnIRCConnected() {
		PutModule("You got connected BoyOh.");
	}

	virtual void OnIRCDisconnected() {
		PutModule("You got disconnected BoyOh.");
	}

	virtual EModRet OnIRCRegistration(CString& sPass, CString& sNick, CString& sIdent, CString& sRealName) {
		sRealName += " - ZNC";
		return CONTINUE;
	}

	virtual EModRet OnBroadcast(CString& sMessage) {
		PutModule("------ [" + sMessage + "]");
		sMessage = "======== [" + sMessage + "] ========";
		return CONTINUE;
	}

	virtual void OnRawMode(const CNick& OpNick, CChan& Channel, const CString& sModes, const CString& sArgs) {
		PutModule("* " + OpNick.GetNick() + " sets mode: " + sModes + " " + sArgs + " (" + Channel.GetName() + ")");
	}

	virtual EModRet OnRaw(CString& sLine) {
		// PutModule("OnRaw() [" + sLine + "]");
		return CONTINUE;
	}

	virtual EModRet OnUserRaw(CString& sLine) {
		// PutModule("UserRaw() [" + sLine + "]");
		return CONTINUE;
	}

	virtual EModRet OnTimerAutoJoin(CChan& Channel) {
		PutModule("Attempting to join " + Channel.GetName());
		return CONTINUE;
	}

	virtual void OnNick(const CNick& OldNick, const CString& sNewNick, const vector<CChan*>& vChans) {
		PutModule("* " + OldNick.GetNick() + " is now known as " + sNewNick);
	}

	virtual EModRet OnUserNotice(CString& sTarget, CString& sMessage) {
		PutModule("[" + sTarget + "] usernotice [" + sMessage + "]");
		sMessage = "\037" + sMessage + "\037";

		return CONTINUE;
	}

	virtual EModRet OnPrivNotice(CNick& Nick, CString& sMessage) {
		PutModule("[" + Nick.GetNick() + "] privnotice [" + sMessage + "]");
		sMessage = "\002" + sMessage + "\002";

		return CONTINUE;
	}

	virtual EModRet OnUserMsg(CString& sTarget, CString& sMessage) {
		PutModule("[" + sTarget + "] usermsg [" + sMessage + "]");
		sMessage = "Sample: \0034" + sMessage + "\003";

		return CONTINUE;
	}

	virtual EModRet OnPrivMsg(CNick& Nick, CString& sMessage) {
		PutModule("[" + Nick.GetNick() + "] privmsg [" + sMessage + "]");
		sMessage = "\002" + sMessage + "\002";

		return CONTINUE;
	}

	virtual EModRet OnChanMsg(CNick& Nick, CChan& Channel, CString& sMessage) {
		if (sMessage == "!ping") {
			PutIRC("PRIVMSG " + Channel.GetName() + " :PONG?");
		}

		sMessage = "x " + sMessage + " x";

		PutModule(sMessage);

		return CONTINUE;
	}

	virtual void OnModCommand(const CString& sCommand) {
		if (sCommand.Equals("TIMERS")) {
			ListTimers();
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
