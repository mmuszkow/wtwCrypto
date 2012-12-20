#include "stdinc.h"

#include "PluginController.h"
#include "Crypto.h"
#include "WtwMsg.h"
#include "CRC32.h"

namespace wtwCrypto {
	Crypto::Crypto(const wchar_t* aesKeyHex) {
		BYTE key[AES::AESKEYSIZEBYTES];
		if(hex2key(aesKeyHex, key, AES::AESKEYSIZEBYTES)) {
			aes.setEncryptionKey(key);
			aes.setDecryptionKey(key);
		} else {
			__LOG_F(PluginController::getInstance().getWTWFUNCTIONS(), 
				WTW_LOG_LEVEL_ERROR, MIDL, L"Wrong AES key format");
		}
	}
	
	WTW_PTR Crypto::send(const wtwMessageDef& msg) {
		WTWFUNCTIONS* wtw = PluginController::getInstance().getWTWFUNCTIONS();

		if(aes.hasKey()) {
			WtwMsg enc(msg);
			enc.encryptMe(aes);

			wchar_t fnSendMsg[512] = {};
			swprintf_s(fnSendMsg, 512, L"%s/%d/%s", 
				enc.get().contactData.netClass, enc.get().contactData.netId, WTW_PF_MESSAGE_SEND);

			WTW_PTR ret = wtw->fnCall(fnSendMsg, enc.get(), 0);
			if(ret != S_OK) 
				return BMP_OK; // forward

			wtw->fnCall(WTW_CHATWND_SHOW_MESSAGE, reinterpret_cast<WTW_PARAM>(&msg), NULL);
			return BMP_NO_PROCESS; // we have eaten it
		}

		return BMP_OK; // send as not encrypted
	}

	WTW_PTR Crypto::recv(const wtwMessageDef& msg) {
		WTWFUNCTIONS* wtw = PluginController::getInstance().getWTWFUNCTIONS();

		if(aes.hasKey()) {
			WtwMsg dec(msg);
			dec.decryptMe(aes);
			wtw->fnCall(WTW_CHATWND_SHOW_MESSAGE, dec.get(), NULL);
			return S_FALSE;
		} else {
			wtw->fnCall(WTW_CHATWND_SHOW_MESSAGE, reinterpret_cast<WTW_PARAM>(&msg), NULL);
			return S_OK; // this message will be shown as not encrypted
		}
	}
};
