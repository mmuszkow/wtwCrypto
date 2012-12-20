#pragma once

#include "stdinc.h"

#include "wtwMessageHelper.h"

namespace wtwCrypto {

	// Diffie-Hellman
	class DH {
	public:
		static const int KEYSIZEBITS = 1024;
		static const int KEYSIZEBYTES = KEYSIZEBITS>>3;
	private:

		static const BYTE PRIME[KEYSIZEBYTES];
		static const BYTE GENERATOR[KEYSIZEBYTES];

		BYTE	publicKey[KEYSIZEBYTES];
		BYTE	sessionKey[KEYSIZEBYTES];
		BYTE	secretKey[KEYSIZEBYTES];

		bool	publicKeyGenerated;
		bool	sessionKeyValid;

	public:
		DH() {
			recreateKeys();
		}

		void recreateKeys();

		inline const BYTE* getPublicKey() const {
			if(publicKeyGenerated) return publicKey;
			return NULL;
		}

		inline const BYTE* getSessionKey() const {
			if(sessionKeyValid) return sessionKey;
			return NULL;
		}

		static BOOL ModExpo(
			const BYTE *pbBase, 
			const BYTE *pbExpo, DWORD cbExpo, 
			const BYTE *pbMod, DWORD cbMod, 
			BYTE *pbResult);	

		inline void importKey(const BYTE* otherPublic) {

			if(ModExpo(otherPublic, secretKey, KEYSIZEBYTES, PRIME, KEYSIZEBYTES, sessionKey) != TRUE)
				return;

			sessionKeyValid = true;
		}
	};
};
