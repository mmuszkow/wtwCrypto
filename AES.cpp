#pragma once

#include "stdinc.h"
#include "AES.h"
#include "PluginController.h"

namespace wtwCrypto {

	AES::~AES() {
		WTWFUNCTIONS* wtw = PluginController::getInstance().getWTWFUNCTIONS();

		if(wtwEncKey) wtw->fnCall(WTW_CRYPTO_AES_FREE_KEY, reinterpret_cast<WTW_PARAM>(wtwEncKey), 0);
		if(wtwDecKey) wtw->fnCall(WTW_CRYPTO_AES_FREE_KEY, reinterpret_cast<WTW_PARAM>(wtwDecKey), 0);
	}

	void AES::setEncryptionKey(const BYTE* key) {
		WTWFUNCTIONS* wtw = PluginController::getInstance().getWTWFUNCTIONS();

		if(wtwEncKey) wtw->fnCall(WTW_CRYPTO_AES_FREE_KEY, reinterpret_cast<WTW_PARAM>(wtwEncKey), 0);
		
		wtwAESKeyInfo info;
		info.keySize = AESKEYSIZEBITS;
		info.key = key;
		info.flags = WTW_CRYPTO_AES_KEY_FLAG_ENCRYPTION;	
		wtwEncKey = reinterpret_cast<void*>(
			wtw->fnCall(WTW_CRYPTO_AES_EXPAND_KEY, info, 0));

		if(!wtwEncKey) __LOG_F(wtw, WTW_LOG_LEVEL_ERROR, MIDL, L"Expanding encryption AES key failed");
	}

	void AES::setDecryptionKey(const BYTE* key) {
		WTWFUNCTIONS* wtw = PluginController::getInstance().getWTWFUNCTIONS();

		if(wtwDecKey) wtw->fnCall(WTW_CRYPTO_AES_FREE_KEY, reinterpret_cast<WTW_PARAM>(wtwDecKey), 0);

		wtwAESKeyInfo info;
		info.keySize = AESKEYSIZEBITS;
		info.key = key;
		info.flags = WTW_CRYPTO_AES_KEY_FLAG_DECRYPTION;		
		wtwDecKey = reinterpret_cast<void*>(
			wtw->fnCall(WTW_CRYPTO_AES_EXPAND_KEY, info, 0));

		if(!wtwDecKey) __LOG_F(wtw, WTW_LOG_LEVEL_ERROR, MIDL, L"Expanding decryption AES key failed");
	}

	bool AES::encrypt(ByteBuffer& buff) const {
		WTWFUNCTIONS* wtw = PluginController::getInstance().getWTWFUNCTIONS();
		if(!wtwEncKey) {
			__LOG_F(wtw, WTW_LOG_LEVEL_ERROR, MIDL, L"Encryption impossible, no key set");
			return false;
		}

		wtwCryptoData data;
		data.nData = buff.size();
		data.pData = buff.getData();
		data.expandedKey = wtwEncKey;
		data.flags = WTW_CRYPTO_AES_FLAG_MODE_ECB;

		WTW_PTR res = wtw->fnCall(WTW_CRYPTO_AES_ENCRYPT, data, 0);
		if(res == S_OK) {
			return true;
		} else {
			__LOG_F(wtw, WTW_LOG_LEVEL_ERROR, MIDL, L"Encryption failed, err=0x%X", res);
			return false;
		}
	}

	bool AES::decrypt(ByteBuffer& buff) const {
		WTWFUNCTIONS* wtw = PluginController::getInstance().getWTWFUNCTIONS();
		if(!wtwDecKey) {
			__LOG_F(wtw, WTW_LOG_LEVEL_ERROR, MIDL, L"Decryption impossible, no key set");
			return false;
		}
	
		wtwCryptoData data;
		data.nData = buff.size();
		data.pData = buff.getData();
		data.expandedKey = wtwDecKey;
		data.flags = WTW_CRYPTO_AES_FLAG_MODE_ECB;

		WTW_PTR res = wtw->fnCall(WTW_CRYPTO_AES_DECRYPT, data, 0);
		if(res == S_OK) {
			return true;
		} else {
			__LOG_F(wtw, WTW_LOG_LEVEL_ERROR, MIDL, L"Decryption failed, err=0x%X", res);
			return false;
		}
	}
};