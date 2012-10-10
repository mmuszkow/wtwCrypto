#pragma once

#include "stdinc.h"
#include "ByteBuffer.h"

namespace wtwCrypto {
	// 256-bit AES using wtwCrypto.h
	class AES {
		static const int AESKEYSIZEBITS = 256;

		void*	wtwEncKey;
		void*	wtwDecKey;
	public:
		AES() {
			wtwEncKey = wtwDecKey = NULL;
		}
		~AES();

		void setEncryptionKey(const BYTE* key);
		void setDecryptionKey(const BYTE* key);

		// buff in both cases must be padded to 16 bytes
		bool encrypt(ByteBuffer& buff) const;
		bool decrypt(ByteBuffer& buff) const;
	};
};