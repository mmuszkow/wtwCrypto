#include "stdinc.h"

#include "DH.h"
#include "PluginController.h"

// Roland: rozne czasy kompletacji dla roznych baz

namespace wtwCrypto {

	void DH::resetKeys() {
		if(hPrivateKey) CryptDestroyKey(hPrivateKey);
		sessionKeyValid = false;
		keysGenerated = false;
	}

	DH::DH() {
		hProv = hPrivateKey = NULL;
		sessionKeyValid = false;
		keysGenerated = false;

		WTWFUNCTIONS* wtw = PluginController::getInstance().getWTWFUNCTIONS();

		BOOL res = CryptAcquireContext(&hProv, NULL, MS_ENH_DSS_DH_PROV, PROV_DSS_DH, CRYPT_VERIFYCONTEXT);
		if(res == FALSE) {
			__LOG_F(wtw, WTW_LOG_LEVEL_ERROR, MIDL, L"Could not acquire context for DH, err=%s", CryptoLastErr());
			return;
		}

		P.cbData = DHKEYSIZEBYTES;
		P.pbData = (BYTE*)g_rgbPrime;

		G.cbData = DHKEYSIZEBYTES;
		G.pbData = (BYTE*)g_rgbGenerator;
		
		HCRYPTKEY hPrivateKey;
		res = CryptGenKey(hProv, CALG_DH_EPHEM, DHKEYSIZEBITS << 16 | CRYPT_EXPORTABLE | CRYPT_PREGEN, &hPrivateKey);
		if(res == FALSE) {
			__LOG_F(wtw, WTW_LOG_LEVEL_ERROR, MIDL, L"Could not create private key for DH, err=%s", CryptoLastErr());
			resetKeys();
			return;
		}

		// Set prime (P)
		res = CryptSetKeyParam(hPrivateKey, KP_P, reinterpret_cast<BYTE*>(&P), 0);
		if(res == FALSE) {
			__LOG_F(wtw, WTW_LOG_LEVEL_ERROR, MIDL, L"Could not set prime for DH, err=%s", CryptoLastErr());
			resetKeys();
			return;
		}

		// Set generator (G)
		res = CryptSetKeyParam(hPrivateKey, KP_G, reinterpret_cast<BYTE*>(&G), 0);
		if(res == FALSE) {
			__LOG_F(wtw, WTW_LOG_LEVEL_ERROR, MIDL, L"Could not set generator for DH, err=%s", CryptoLastErr());
			resetKeys();
			return;
		}

		// Random secret (X)
		res = CryptSetKeyParam(hPrivateKey, KP_X, NULL, 0);
		if(res == FALSE) {
			__LOG_F(wtw, WTW_LOG_LEVEL_ERROR, MIDL, L"Could not generate random number for DH, err=%s", CryptoLastErr());
			resetKeys();
			return;
		}

		// Public key value, (G^X) mod P is calculated.

		// Get the size for the key BLOB.
		DWORD dwPublicSize;
		res = CryptExportKey(hPrivateKey, NULL, PUBLICKEYBLOB, 0, NULL,	&dwPublicSize);
		if(res == FALSE) {
			__LOG_F(wtw, WTW_LOG_LEVEL_ERROR, MIDL, L"Could determine public key size for DH, err=%s", CryptoLastErr());
			resetKeys();
			return;
		}

		if(dwPublicSize != sizeof(PublicKeyDH)) {
			__LOG_F(wtw, WTW_LOG_LEVEL_ERROR, MIDL, L"Wrong size of DH public key");
			resetKeys();
			return;
		}

		// Get the key BLOB.
		res = CryptExportKey(hPrivateKey, 0, PUBLICKEYBLOB,	0, reinterpret_cast<BYTE*>(&publicKey), &dwPublicSize);
		if(res == FALSE) {
			__LOG_F(wtw, WTW_LOG_LEVEL_ERROR, MIDL, L"Could not export public key for DH, err=%s", CryptoLastErr());		
			resetKeys();
			return;
		}

		// Get the size for the key BLOB.
		DWORD dwPrivateSize;
		res = CryptExportKey(hPrivateKey, NULL, PRIVATEKEYBLOB, 0, NULL, &dwPrivateSize);
		if(res == FALSE) {
			__LOG_F(wtw, WTW_LOG_LEVEL_ERROR, MIDL, L"Could determine private key size for DH, err=%s", CryptoLastErr());
			resetKeys();
			return;
		}

		if(dwPrivateSize != sizeof(PrivateKeyDH)) {
			__LOG_F(wtw, WTW_LOG_LEVEL_ERROR, MIDL, L"Wrong size of DH private key");
			resetKeys();
			return;
		}

		// Get the key BLOB.
		res = CryptExportKey(hPrivateKey, 0, PRIVATEKEYBLOB, 0, reinterpret_cast<BYTE*>(&privateKey), &dwPrivateSize);
		if(res == FALSE) {
			__LOG_F(wtw, WTW_LOG_LEVEL_ERROR, MIDL, L"Could not export private key for DH, err=%s", CryptoLastErr());		
			resetKeys();
			return;
		}

		keysGenerated = true;
	}

	void DH::importKey(const BYTE* importedKeyBlob) {
		//BOOL			res;
		//HCRYPTKEY		hSessionKey = NULL;
		WTWFUNCTIONS*	wtw = PluginController::getInstance().getWTWFUNCTIONS();

		sessionKeyValid = false;

		/*
		// just for chickity check
		res = CryptImportKey(hProv, importedKeyBlob, sizeof(PublicKeyDH), hPrivateKey, 0, &hSessionKey);
		if(res == FALSE) {
			__LOG_F(wtw, WTW_LOG_LEVEL_ERROR, MIDL, L"Could not import key for DH, err=%s", CryptoLastErr());
			return;
		}

		CryptDestroyKey(hSessionKey);
		*/

		if(sizeof(NN_DIGIT) != 4) {
			__LOG_F(wtw, WTW_LOG_LEVEL_ERROR, MIDL, L"Unsuspected situation, contact developer");
			return;
		}

		static const unsigned int NN_LEN = DHKEYSIZEBYTES>>2;
		NN_DIGIT	a[NN_LEN], b[NN_LEN], c[NN_LEN];
		memcpy(a, publicKey.y, DHKEYSIZEBYTES);
		memcpy(b, privateKey.secret, DHKEYSIZEBYTES);
		memcpy(c, privateKey.prime, DHKEYSIZEBYTES);
		NN_ModExp((NN_DIGIT*)sessionKey, a, b, NN_LEN, c, NN_LEN); // res = a^b mod c

		sessionKeyValid = true;
	}
};
