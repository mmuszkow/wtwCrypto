#pragma once

#include "stdinc.h"
#include "AES.h"

namespace wtwCrypto {
	class WtwMsg {
		wtwMessageDef	wtwMsg;

		void alloc(const wtwMessageDef& msg);
		void dealloc();
	public:
		WtwMsg() {}

		WtwMsg(const WtwMsg& msg) {
			alloc(msg.wtwMsg);
		}

		WtwMsg(const wtwMessageDef& msg) {
			alloc(msg);
		}

		~WtwMsg() {
			dealloc();
		}

		WtwMsg& operator=(const WtwMsg& msg) {
			if(this == &msg) return *this;
			dealloc();
			alloc(msg.wtwMsg);
			return *this;
		}

		inline wtwMessageDef& get() {
			return wtwMsg;
		}

		// encrypts message text and subject
		void encryptMe(const AES& aesCtx);
		// decrypts message text and subject
		void decryptMe(const AES& aesCtx);
	};
};
