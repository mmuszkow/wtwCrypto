#include "stdinc.h"

#include "AES.h"
#include "PluginController.h"

namespace wtwCrypto {



	AES::AES() {
		hProv = hKey = NULL;
		if(CryptAcquireContext(&hProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) == TRUE) {
			recreateKey();
		} else
			__LOG_F(PluginController::getInstance().getWTWFUNCTIONS(), WTW_LOG_LEVEL_ERROR, 
				MIDL, L"Acquiring AES context problem: %s", errorToString(GetLastError()));
	}

	AES::~AES() {
		if(hKey) CryptDestroyKey(hKey);
		if(hProv) CryptReleaseContext(hProv, 0);
	}

	void AES::recreateKey() {
		if(hKey) {
			CryptDestroyKey(hKey);
			hKey = NULL;
		}

		if(hProv) {
			BYTE iv[16];
			if(	CryptGenRandom(hProv, 32, key.cbKey ) == TRUE && 
				CryptGenRandom(hProv, 16, iv) == TRUE) {
					// Import AES key
					if(CryptImportKey(hProv, (CONST BYTE*)&key, sizeof(AesKey), NULL, 0, &hKey ) == TRUE) {
						// Set CBC Mode
						DWORD dwMode = CRYPT_MODE_CBC;
						if(CryptSetKeyParam(hKey, KP_IV, iv, 0) == TRUE) {
							if(CryptSetKeyParam(hKey, KP_MODE, (BYTE*)&dwMode, 0) == FALSE) // CryptSetKeyParam failed
								__LOG_F(PluginController::getInstance().getWTWFUNCTIONS(), WTW_LOG_LEVEL_ERROR, 
									MIDL, L"Setting CBC mode failed: %s", errorToString(GetLastError()));
						} else 
							__LOG_F(PluginController::getInstance().getWTWFUNCTIONS(), WTW_LOG_LEVEL_ERROR, 
									MIDL, L"Setting IV failed: %s", errorToString(GetLastError()));
					} else // CryptImportKey failed 
						__LOG_F(PluginController::getInstance().getWTWFUNCTIONS(), WTW_LOG_LEVEL_ERROR, 
							MIDL, L"Importing key failed: %s", errorToString(GetLastError()));
			} else // CryptGenRandom failed
				__LOG_F(PluginController::getInstance().getWTWFUNCTIONS(), WTW_LOG_LEVEL_ERROR, 
					MIDL, L"Generating random key failed: %s", errorToString(GetLastError()));
		}
	}

	wchar_t* AES::encrypt(const wchar_t* msg) const {
		if(!msg) return NULL;
		
		DWORD inSize = wcslen(msg) << 1;
		if(inSize == 0) return NULL;

		if(!hProv || !hKey) return _wcsdup(msg);
		
		while(inSize % 16 != 0) inSize++;
		DWORD outSize = inSize;
		
		wchar_t* outBuff = (wchar_t*)malloc(inSize);
		memset(outBuff, 0, inSize);
		wcscpy(outBuff, msg);
	
		if(CryptEncrypt(hKey, NULL, TRUE, 0, (BYTE*)outBuff, &outSize, inSize) == TRUE) {
			return outBuff;
		} else {
			__LOG_F(PluginController::getInstance().getWTWFUNCTIONS(), WTW_LOG_LEVEL_ERROR, 
				MIDL, L"Encrypting/decrypting failed: %s", errorToString(GetLastError()));
			free(outBuff);
			return _wcsdup(msg);
		}
	}

	wchar_t* AES::decrypt(const wchar_t* msg) const {
		if(!msg) return NULL;
		
		DWORD inSize = wcslen(msg) << 1;
		if(inSize == 0) return NULL;

		if(!hProv || !hKey) return _wcsdup(msg);
		
		while(inSize % 16 != 0) inSize++;
		DWORD outSize = inSize;
		
		wchar_t* outBuff = (wchar_t*)malloc(inSize);
		memset(outBuff, 0, inSize);
		wcscpy(outBuff, msg);
	
		if(CryptDecrypt(hKey, NULL, TRUE, 0, (BYTE*)outBuff, &outSize) == TRUE) {
			return outBuff;
		} else {
			__LOG_F(PluginController::getInstance().getWTWFUNCTIONS(), WTW_LOG_LEVEL_ERROR, 
				MIDL, L"Encrypting/decrypting failed: %s", errorToString(GetLastError()));
			free(outBuff);
			return _wcsdup(msg);
		}
	}
};