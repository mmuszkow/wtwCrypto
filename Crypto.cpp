#include "stdinc.h"

#include "PluginController.h"
#include "Crypto.h"
#include "WtwMsg.h"
#include "CRC32.h"

namespace wtwCrypto {
	
	void Crypto::send(const wtwMessageDef& msg) {

		WTWFUNCTIONS* wtw = PluginController::getInstance().getWTWFUNCTIONS();

		if(dh.getSessionKey()) { // encrypting message if received session key
			// send encypted
			WtwMsg enc(msg);
			enc.encryptMe(aes);

			wchar_t fnSendMsg[512] = {};
			swprintf_s(fnSendMsg, 512, L"%s/%d/%s", enc.get().contactData.netClass, enc.get().contactData.netId, WTW_PF_MESSAGE_SEND);

			WTW_PTR ret = wtw->fnCall(fnSendMsg, enc.get(), 0);
			if(ret == S_OK)
				wtw->fnCall(WTW_CHATWND_SHOW_MESSAGE, reinterpret_cast<WTW_PARAM>(&msg), NULL);
			else
				__LOG_F(wtw, WTW_LOG_LEVEL_ERROR, MIDL, L"Sending encrypted message failed, err=%d", ret);
		}
	}

	WTW_PTR Crypto::recv(const wtwMessageDef& msg) {
		WTWFUNCTIONS* wtw = PluginController::getInstance().getWTWFUNCTIONS();

		if(dh.getSessionKey()) {
			WtwMsg dec(msg);
			dec.decryptMe(aes);
			wtw->fnCall(WTW_CHATWND_SHOW_MESSAGE, dec.get(), NULL);
			return S_FALSE;
		} else {
			__LOG_F(wtw, WTW_LOG_LEVEL_ERROR, MIDL, L"Message received, without knowing session key");
			wtw->fnCall(WTW_CHATWND_SHOW_MESSAGE, reinterpret_cast<WTW_PARAM>(&msg), NULL);
			return S_OK; // this message will be shown as not encrypted
		}
	}
};
