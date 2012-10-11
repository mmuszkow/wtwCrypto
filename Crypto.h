#pragma once

#include "stdinc.h"

#include "AES.h"
#include "DH.h"
#include "WtwMsg.h"

namespace wtwCrypto {

	class Crypto {
		AES				aes;
		DH				dh;
		wtwContactDef	cnt;
	public:
		Crypto() {
		}

		Crypto(const wtwContactDef& cnt) {
			this->cnt.id = _wcsdup(cnt.id);
			this->cnt.netId = cnt.netId;
			this->cnt.netClass = _wcsdup(cnt.netClass);
		}

		Crypto(const Crypto& c2) {
			if(c2.cnt.id)
				this->cnt.id = _wcsdup(c2.cnt.id);
			this->cnt.netId = c2.cnt.netId;
			if(c2.cnt.netClass)
				this->cnt.netClass = _wcsdup(c2.cnt.netClass);
		}

		~Crypto() {
			if(cnt.id) free((void*)cnt.id);
			if(cnt.netClass) free((void*)cnt.netClass);
		}

		Crypto& operator=(const Crypto& c2) {
			if(cnt.id) free((void*)cnt.id);
			if(cnt.netClass) free((void*)cnt.netClass);

			if(c2.cnt.id)
				this->cnt.id = _wcsdup(c2.cnt.id);
			this->cnt.netId = c2.cnt.netId;
			if(c2.cnt.netClass)
				this->cnt.netClass = _wcsdup(c2.cnt.netClass);

			return *this;
		}

		void send(const wtwMessageDef& msg);
		WTW_PTR recv(const wtwMessageDef& msg);

		inline bool hasKey() const {
			return dh.getSessionKey() != NULL;
		}

		inline const wtwContactDef& getCnt() const {
			return cnt;
		}
	};
};
