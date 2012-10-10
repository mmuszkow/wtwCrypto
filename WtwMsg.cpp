#include "stdinc.h"

#include "WtwMsg.h"
#include "PluginController.h"
#include "ByteBuffer.h"
#include "CRC32.h"

namespace wtwCrypto {
	void WtwMsg::alloc(const wtwMessageDef& msg) {
		if(msg.contactData.id)
			wtwMsg.contactData.id = _wcsdup(msg.contactData.id);
		wtwMsg.contactData.netId = msg.contactData.netId;
		if(msg.contactData.netClass)
			wtwMsg.contactData.netClass = _wcsdup(msg.contactData.netClass);

		wtwMsg.msgFlags = msg.msgFlags;
		wtwMsg.msgTime = msg.msgTime;
		if(msg.msgSubject)
			wtwMsg.msgSubject = _wcsdup(msg.msgSubject);
		if(msg.msgMessage)
			wtwMsg.msgMessage = _wcsdup(msg.msgMessage);
	}

	void WtwMsg::dealloc() {
		if(wtwMsg.msgSubject) {
			free((void*)wtwMsg.msgSubject);
			wtwMsg.msgSubject = NULL;
		}

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

		if(wtwMsg.msgSubject) {
			ByteBuffer buff(false, wtwMsg.msgSubject);
			buff.padTo16bytes();
			
			if(aesCtx.encrypt(buff)) {
				std::wstring b64 = buff.toBase64();				
				size_t len = b64.size() + PACKET_HEADER_LEN + 1;
				wchar_t* packet = static_cast<wchar_t*>(malloc(len<<1));
				swprintf_s(packet, len, L"B64-%s", b64.c_str()); // B64-base64

				free((void*)wtwMsg.msgSubject);
				wtwMsg.msgSubject = packet;
			}
		}

		if(wtwMsg.msgMessage) {
			ByteBuffer buff(false, wtwMsg.msgMessage);
			buff.padTo16bytes();
			if(aesCtx.encrypt(buff)) {
				std::wstring b64 = buff.toBase64();
				size_t len = b64.size() + PACKET_HEADER_LEN + 1;
				wchar_t* packet = static_cast<wchar_t*>(malloc(len<<1));
				swprintf_s(packet, len, L"B64-%s", b64.c_str()); // B64-FFFFFFFF-base64

				free((void*)wtwMsg.msgMessage);
				wtwMsg.msgMessage = packet;
			}
		}
	}

	// decrypts message
	void WtwMsg::decryptMe(const AES& aesCtx) {
		WTWFUNCTIONS* wtw = PluginController::getInstance().getWTWFUNCTIONS();

		if(wtwMsg.msgSubject && wtwMsg.msgSubject[0] != 0) {
			size_t len = wcslen(wtwMsg.msgSubject);
			// check proper length
			if(len > PACKET_HEADER_LEN) {
				// decrypt what's inside base64
				ByteBuffer buff(true, &wtwMsg.msgSubject[PACKET_HEADER_LEN]);
				if(buff.size() % 16 == 0) {
					if(aesCtx.decrypt(buff)) {
							free((void*)wtwMsg.msgSubject);
							wtwMsg.msgSubject = buff.dupAsString();
						}
					} else 
						__LOG_F(wtw, WTW_LOG_LEVEL_ERROR, MIDL, L"Msg subject: malformed packet received, size is not padded to 16 bytes");
			} else
				__LOG_F(wtw, WTW_LOG_LEVEL_ERROR, MIDL, L"Msg subject: malformed packet received, wrong packet len");
		}

		if(wtwMsg.msgMessage && wtwMsg.msgMessage[0] != 0) {
			size_t len = wcslen(wtwMsg.msgMessage);
			// check proper length
			if(len > PACKET_HEADER_LEN) {
				// decrypt what's inside base64
				ByteBuffer buff(true, &wtwMsg.msgMessage[PACKET_HEADER_LEN]);
				if(buff.size() % 16 == 0) {
					if(aesCtx.decrypt(buff)) {
						free((void*)wtwMsg.msgMessage);
						wtwMsg.msgMessage = buff.dupAsString();
					}
				} else 
					__LOG_F(wtw, WTW_LOG_LEVEL_ERROR, MIDL, L"Msg text: malformed packet received, size is not padded to 16 bytes");
			} else
				__LOG_F(wtw, WTW_LOG_LEVEL_ERROR, MIDL, L"Msg text: malformed packet received, packet too small");
		}
	}
};
