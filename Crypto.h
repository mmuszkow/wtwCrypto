#pragma once

#include "stdinc.h"

#include "AES.h"
#include "DH.h"
#include "WtwMsg.h"

namespace wtwCrypto {

	class Crypto {
		AES		aes;
		DH		dh;

		std::vector<WtwMsg>	toBeSent;
		bool	publicKeySent;

		int		sentCount;
		static const int CHANGE_KEY_COUNT = 100;

		void sendPublicKey(WTWFUNCTIONS* wtw, const wtwMessageDef& msg);
		void onRecvSessionKey(WTWFUNCTIONS* wtw, const wtwMessageDef& msg);

		enum MsgType { PLAIN, CRYPTED, DH };
		static MsgType determineMsgType(const wtwMessageDef& msg);

		wtwContactDef	cnt;
	public:
		Crypto() {
			publicKeySent = false;
			sentCount = 0;
		}

		Crypto(const wtwContactDef& cnt) {
			publicKeySent = false;
			sentCount = 0;
			this->cnt.id = _wcsdup(cnt.id);
			this->cnt.netId = cnt.netId;
			this->cnt.netClass = _wcsdup(cnt.netClass);
		}

		Crypto(const Crypto& c2) {
			publicKeySent = c2.publicKeySent;
			sentCount = c2.sentCount;
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

			publicKeySent = c2.publicKeySent;
			sentCount = c2.sentCount;
			if(c2.cnt.id)
				this->cnt.id = _wcsdup(c2.cnt.id);
			this->cnt.netId = c2.cnt.netId;
			if(c2.cnt.netClass)
				this->cnt.netClass = _wcsdup(c2.cnt.netClass);

			return *this;
		}

		void send(const wtwMessageDef& msg);
		void recv(const wtwMessageDef& msg);

		inline bool hasKey() const {
			return dh.getSessionKey() != NULL;
		}

		void onTimeout(WTWFUNCTIONS* wtw);
		static bool isDHKey(const wtwMessageDef& msg);

		inline const wtwContactDef& getCnt() const {
			return cnt;
		}
	};
};
