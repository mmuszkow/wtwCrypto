#pragma once

#include "stdinc.h"
#include "ByteBuffer.h"
#include "DH.h"

namespace wtwCrypto {
	// 256-bit AES using wtwCrypto.h
	class AES {
	public:
		static const int AESKEYSIZEBITS = 256;
		static const int AESKEYSIZEBYTES = AESKEYSIZEBITS >> 3;
	private:
		void*	wtwEncKey;
		void*	wtwDecKey;
		BYTE	encKey[AESKEYSIZEBYTES];
		BYTE	decKey[AESKEYSIZEBYTES];
	public:
		AES() {
			wtwEncKey = wtwDecKey = NULL;
		}
		AES(const AES& other) {
			wtwEncKey = wtwDecKey = NULL;
			setEncryptionKey(other.encKey);
			setDecryptionKey(other.decKey);
		}
		AES(const wchar_t* aesKeyHex) {
			BYTE key[DH::KEYSIZEBYTES];
			wtwEncKey = wtwDecKey = NULL;
			if(DH::hex2key(aesKeyHex, key)) {
				setEncryptionKey(key);
				setDecryptionKey(key);
			}
		}
		AES& operator=(const AES& other) {
			if(this == &other) return *this;
			setEncryptionKey(other.encKey);
			setDecryptionKey(other.decKey);
			return *this;
		}
		~AES();

		inline bool hasKey() const {
			return (wtwEncKey && wtwDecKey);
		}

		void setEncryptionKey(const BYTE* key);
		void setDecryptionKey(const BYTE* key);

		// buff in both cases must be padded to 16 bytes
		bool encrypt(ByteBuffer& buff) const;
		bool decrypt(ByteBuffer& buff) const;
	};
};