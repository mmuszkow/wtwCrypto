#include "stdinc.h"

#include "PluginController.h"
#include "Crypto.h"
#include "WtwMsg.h"
#include "CRC32.h"

namespace wtwCrypto {
	// msg is regular message that was meant to be send
	void Crypto::sendPublicKey(WTWFUNCTIONS* wtw, const wtwMessageDef& msg) {
		if(!msg.contactData.id || !msg.contactData.netClass)
			return;

		wtwMessageDef keyMsg;
		keyMsg.msgTime = msg.msgTime;
		keyMsg.contactData.id = msg.contactData.id;
		keyMsg.contactData.netClass = msg.contactData.netClass;
		keyMsg.contactData.netId = msg.contactData.netId;
		keyMsg.msgFlags = WTW_MESSAGE_FLAG_CHAT_MSG | WTW_MESSAGE_FLAG_OUTGOING;
		
		wchar_t* keyHex = hex2str(dh.getPublicKey(), DH::KEYSIZEBYTES);

		if(keyHex) {
			size_t len = wcslen(keyHex) + WtwMsg::PACKET_HEADER_LEN + 1;
			wchar_t* packet = static_cast<wchar_t*>(malloc(len<<1));
			swprintf_s(packet, len, L"DH1-%s", keyHex); // DH1-key
			delete [] keyHex;

			keyMsg.msgMessage = packet;

			wchar_t fnSendMsg[512] = {0};
			WTW_PTR ret;
			swprintf_s(fnSendMsg, 512, L"%s/%d/%s", keyMsg.contactData.netClass, keyMsg.contactData.netId, WTW_PF_MESSAGE_SEND);
			if((ret = wtw->fnCall(fnSendMsg, keyMsg, 0)) != S_OK) {
				if(packet) free(packet);
				__LOG_F(wtw, WTW_LOG_LEVEL_ERROR, MIDL, L"Sending public key to %s failed, err=0x%X", fnSendMsg, ret);
				return;
			}

			wchar_t cntId[512];
			swprintf_s(cntId, 512, L"wtwCrypto/%s/%d/%s", keyMsg.contactData.netClass, keyMsg.contactData.netId, keyMsg.contactData.id);

			wtwTimerDef timerDef;
			timerDef.id = cntId;
			timerDef.sleepTime = 5000; // 5 sek
			timerDef.callback = PluginController::onKeyTimeout;
			timerDef.cbData = NULL;
			timerDef.flags = WTW_TIMER_FLAG_ONE_TICK;
			wtw->fnCall(WTW_TIMER_CREATE, timerDef, NULL);

			if(packet) free(packet);

			publicKeySent = true;
		} else
			__LOG_F(wtw, WTW_LOG_LEVEL_ERROR, MIDL, L"No public key to send");
	}
	
	void Crypto::send(const wtwMessageDef& msg) {

		WTWFUNCTIONS* wtw = PluginController::getInstance().getWTWFUNCTIONS();

		if(publicKeySent && sentCount > CHANGE_KEY_COUNT) {
			dh.recreateKeys();
			publicKeySent = false; // will change key
			sentCount = 0;
		}

		if(!publicKeySent && dh.getPublicKey()) { // sending DH public key
			
			sendPublicKey(wtw, msg);

			// push msg COPY to awaiting queue
			toBeSent.push_back(WtwMsg(msg));

		} else if(dh.getSessionKey()) { // encrypting message if received session key
			// send encypted
			WtwMsg enc(msg);
			enc.encryptMe(aes);

			wchar_t fnSendMsg[512] = {};
			swprintf_s(fnSendMsg, 512, L"%s/%d/%s", enc.get().contactData.netClass, enc.get().contactData.netId, WTW_PF_MESSAGE_SEND);

			WTW_PTR ret = wtw->fnCall(fnSendMsg, enc.get(), 0);
			if(ret == S_OK)
				wtw->fnCall(WTW_CHATWND_SHOW_MESSAGE, reinterpret_cast<WTW_PARAM>(&msg), NULL);
			else
				__LOG_F(wtw, WTW_LOG_LEVEL_ERROR, MIDL, L"Sending encrypted message failed, err=%d", ret);

			sentCount++;
		}
	}

	Crypto::MsgType Crypto::determineMsgType(const wtwMessageDef& msg) {
		if(!msg.msgMessage || wcslen(msg.msgMessage) < 3)
			return PLAIN;

		if(msg.msgMessage[0] == 'B' && msg.msgMessage[1] == '6' && msg.msgMessage[2] == '4')
			return CRYPTED;

		if(msg.msgMessage[0] == 'D' && msg.msgMessage[1] == 'H' && msg.msgMessage[2] == '1')
			return DH;

		return PLAIN;
	}

	void Crypto::recv(const wtwMessageDef& msg) {

		WTWFUNCTIONS* wtw = PluginController::getInstance().getWTWFUNCTIONS();

		MsgType type = determineMsgType(msg);

		switch(type) {
			case CRYPTED:
				// if we got decryption key
				if(dh.getSessionKey()) {
					WtwMsg dec(msg);
					dec.decryptMe(aes);
					wtw->fnCall(WTW_CHATWND_SHOW_MESSAGE, dec.get(), NULL);
				} else {
					__LOG_F(wtw, WTW_LOG_LEVEL_ERROR, MIDL, L"Message received, without knowing session key");
					wtw->fnCall(WTW_CHATWND_SHOW_MESSAGE, reinterpret_cast<WTW_PARAM>(&msg), NULL);
				}
				break;
			case PLAIN: {
				const wtwContactDef& cnt = msg.contactData;
				wtw->fnCall(WTW_CHATWND_SHOW_MESSAGE, reinterpret_cast<WTW_PARAM>(&msg), NULL);				
				wtwOutputChatInfo(wtw, cnt.id, cnt.netClass, cnt.netId, text::NON_CIPHERED);
				break;
			}
			case DH: {
				sentCount = 0; // because somebody else changed the key
				onRecvSessionKey(wtw, msg);

				// send awaiting if they are any
				if(!toBeSent.empty()) {
					wchar_t	fnSendMsg[512] = {0};

					for(unsigned int i=0; i<toBeSent.size(); i++) {
						WtwMsg& copy = toBeSent[i];
						copy.encryptMe(aes);

						swprintf_s(fnSendMsg, 512, L"%s/%d/%s", copy.get().contactData.netClass, copy.get().contactData.netId, WTW_PF_MESSAGE_SEND);
						WTW_PTR ret = wtw->fnCall(fnSendMsg, copy.get(), 0);
						if(ret == S_OK) {
							copy.decryptMe(aes);
							wtw->fnCall(WTW_CHATWND_SHOW_MESSAGE, copy.get(), NULL);
						}
						else
							__LOG_F(wtw, WTW_LOG_LEVEL_ERROR, MIDL, L"Sending encrypted message failed, err=%d", ret);
					}
					toBeSent.clear();
				}
				break;
			 }
		}
	}

	void Crypto::onRecvSessionKey(WTWFUNCTIONS* wtw, const wtwMessageDef& msg) {
		if(!msg.msgMessage) {
			__LOG_F(wtw, WTW_LOG_LEVEL_ERROR, MIDL, L"Malformed packet received, key expected but empty message received");
			return;
		}

		if(dh.getSessionKey()) // if we have sess key that means it's a key change and we have to resent our pub key
			publicKeySent = false;

		size_t len = wcslen(msg.msgMessage);
		if(len > WtwMsg::PACKET_HEADER_LEN) {
			const wchar_t* key = &msg.msgMessage[WtwMsg::PACKET_HEADER_LEN];

			size_t keySize;
			BYTE* publicKey = hex2byte(key, &keySize);
			if(keySize == DH::KEYSIZEBYTES) {
				dh.importKey(publicKey);
				if(dh.getSessionKey()) {
					aes.setEncryptionKey(dh.getSessionKey());
					aes.setDecryptionKey(dh.getSessionKey());
				} else
					__LOG_F(wtw, WTW_LOG_LEVEL_ERROR, MIDL, L"DH importing key failed, could not set key for AES");
			}
			else
				__LOG_F(wtw, WTW_LOG_LEVEL_ERROR, MIDL, L"Malformed packet received, wrong key size (%d)", keySize);
			if(publicKey) delete [] publicKey;
		} else {
			__LOG_F(wtw, WTW_LOG_LEVEL_ERROR, MIDL, L"Malformed packet received, packet too small");
		}

		if(!publicKeySent && dh.getPublicKey()) // sending DH public key
			sendPublicKey(wtw, msg);
	}

	void Crypto::onTimeout(WTWFUNCTIONS* wtw) {
		// send awaiting uncrypted if they are any
		if(!toBeSent.empty()) {
			wchar_t	fnSendMsg[512] = {0};
			for(unsigned int i=0; i<toBeSent.size(); i++) {
				wtwMessageDef& copy = toBeSent[i].get();
				swprintf_s(fnSendMsg, 512, L"%s/%d/%s", copy.contactData.netClass, copy.contactData.netId, WTW_PF_MESSAGE_SEND);
				
				WTW_PTR ret = wtw->fnCall(fnSendMsg, copy, 0);
				if(ret == S_OK)
					wtw->fnCall(WTW_CHATWND_SHOW_MESSAGE, copy, NULL);
				else
					__LOG_F(wtw, WTW_LOG_LEVEL_ERROR, MIDL, L"Sending message failed, err=%d", ret);
			}
			
			wtwContactDef& cnt = toBeSent[0].get().contactData;
			wtwOutputChatInfo(wtw, cnt.id, cnt.netClass, cnt.netId, text::NEG_FAIL);

			toBeSent.clear();
		}
	}

	bool Crypto::isDHKey(const wtwMessageDef& msg) {
		MsgType type = determineMsgType(msg);
		return (type == DH);
	}
};
