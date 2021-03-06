#include "stdinc.h"

#include "WtwMsg.h"
#include "PluginController.h"
#include "ByteBuffer.h"

namespace wtwCrypto {
	void WtwMsg::alloc(const wtwMessageDef& msg) {
		if(msg.contactData.id)
			wtwMsg.contactData.id = _wcsdup(msg.contactData.id);
		wtwMsg.contactData.netId = msg.contactData.netId;
		if(msg.contactData.netClass)
			wtwMsg.contactData.netClass = _wcsdup(msg.contactData.netClass);

		wtwMsg.msgFlags = msg.msgFlags;
		wtwMsg.msgTime = msg.msgTime;
		if(msg.msgMessage)
			wtwMsg.msgMessage = _wcsdup(msg.msgMessage);
	}

	void WtwMsg::dealloc() {
		if(wtwMsg.msgMessage) {
			free((void*)wtwMsg.msgMessage);
			wtwMsg.msgMessage = NULL;
		}

		if(wtwMsg.contactData.id) {
			free((void*)wtwMsg.contactData.id);
			wtwMsg.contactData.id = NULL;
		}

		if(wtwMsg.contactData.netClass) {
			free((void*)wtwMsg.contactData.netClass);
			wtwMsg.contactData.netClass = NULL;
		}
	}

	void WtwMsg::encryptMe(const AES& aesCtx) {
		WTWFUNCTIONS* wtw = PluginController::getInstance().getWTWFUNCTIONS();

		if(wtwMsg.msgMessage) {
			AesBuffer buff(false, wtwMsg.msgMessage);
			buff.padTo16bytes();
			if(aesCtx.encrypt(buff)) {
				free((void*)wtwMsg.msgMessage);
				wtwMsg.msgMessage = _wcsdup(buff.toBase64().c_str());
			}
		}
	}

	// decrypts message
	void WtwMsg::decryptMe(const AES& aesCtx) {
		WTWFUNCTIONS* wtw = PluginController::getInstance().getWTWFUNCTIONS();

		if(wtwMsg.msgMessage && wtwMsg.msgMessage[0] != 0) {
			// decrypt what's inside base64
			AesBuffer buff(true, wtwMsg.msgMessage);
			if(buff.size() % 16 == 0) {
				if(aesCtx.decrypt(buff)) {
					free((void*)wtwMsg.msgMessage);
					wtwMsg.msgMessage = buff.dupAsString();
				}
			} else 
				__LOG_F(wtw, WTW_LOG_LEVEL_ERROR, MDL, L"Msg text: malformed packet received, size is not padded to 16 bytes");
		}
	}
};
