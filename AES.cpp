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
		wtwEncKey = NULL;

		wtwAESKeyInfoEx info;
		info.keySize = KEYSIZEBITS;
		info.key = key;
		info.flags = WTW_CRYPTO_AES_KEY_FLAG_ENCRYPTION;	
		WTW_PTR ret = wtw->fnCall(WTW_CRYPTO_AES_EXPAND_KEY_EX, info, NULL);

		if (ret == S_OK) {
			memcpy(encKey, key, KEYSIZEBYTES);
			wtwEncKey = info.expandedKeyPtr;
		} else {
			__LOG_F(wtw, WTW_LOG_LEVEL_ERROR, MDL, L"Expanding encryption AES key failed: %p", ret);
			wtwEncKey = NULL;
		}
	}

	void AES::setDecryptionKey(const BYTE* key) {
		WTWFUNCTIONS* wtw = PluginController::getInstance().getWTWFUNCTIONS();

		if(wtwDecKey) wtw->fnCall(WTW_CRYPTO_AES_FREE_KEY, reinterpret_cast<WTW_PARAM>(wtwDecKey), 0);
		wtwDecKey = NULL;

		wtwAESKeyInfoEx info;
		info.keySize = KEYSIZEBITS;
		info.key = key;
		info.flags = WTW_CRYPTO_AES_KEY_FLAG_DECRYPTION;		
		WTW_PTR ret = wtw->fnCall(WTW_CRYPTO_AES_EXPAND_KEY_EX, info, NULL);

		if (ret == S_OK) {
			memcpy(decKey, key, KEYSIZEBYTES);
			wtwDecKey = info.expandedKeyPtr;
		} else {
			__LOG_F(wtw, WTW_LOG_LEVEL_ERROR, MDL, L"Expanding decryption AES key failed: %p", ret);
			wtwDecKey = NULL;
		}
	}

	bool AES::encrypt(AesBuffer& buff) const {
		WTWFUNCTIONS* wtw = PluginController::getInstance().getWTWFUNCTIONS();
		if(!wtwEncKey) {
			__LOG_F(wtw, WTW_LOG_LEVEL_ERROR, MDL, L"Encryption impossible, no key set");
			return false;
		}

		// to keep IV constant
		BYTE iv[AesBuffer::IVSIZEBYTES];
		memcpy(iv, buff.getIV(), AesBuffer::IVSIZEBYTES);

		wtwCryptoData data;
		data.nData = buff.size();
		data.pData = buff.getData();
		data.expandedKey = wtwEncKey;
		data.flags = WTW_CRYPTO_AES_FLAG_MODE_CBC;
		data.ivec = iv;

		WTW_PTR res = wtw->fnCall(WTW_CRYPTO_AES_ENCRYPT, data, 0);
		if(res == S_OK) {
			return true;
		} else {
			__LOG_F(wtw, WTW_LOG_LEVEL_ERROR, MDL, L"Encryption failed, err=0x%X", res);
			return false;
		}
	}

	bool AES::decrypt(AesBuffer& buff) const {
		WTWFUNCTIONS* wtw = PluginController::getInstance().getWTWFUNCTIONS();
		if(!wtwDecKey) {
			__LOG_F(wtw, WTW_LOG_LEVEL_ERROR, MDL, L"Decryption impossible, no key set");
			return false;
		}

		// to keep IV constant
		BYTE iv[AesBuffer::IVSIZEBYTES];
		memcpy(iv, buff.getIV(), AesBuffer::IVSIZEBYTES);

		wtwCryptoData data;
		data.nData = buff.size();
		data.pData = buff.getData();
		data.expandedKey = wtwDecKey;
		data.flags = WTW_CRYPTO_AES_FLAG_MODE_CBC;
		data.ivec = iv;

		WTW_PTR res = wtw->fnCall(WTW_CRYPTO_AES_DECRYPT, data, 0);
		if(res == S_OK) {
			return true;
		} else {
			__LOG_F(wtw, WTW_LOG_LEVEL_ERROR, MDL, L"Decryption failed, err=0x%X", res);
			return false;
		}
	}
};
