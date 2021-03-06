#include "stdinc.h"
#include "PluginController.h"
#include "Crypto.h"

namespace wtwCrypto {

	int PluginController::onLoad(WTWFUNCTIONS *fn) {
		wtw = fn;
#ifdef _DEBUG
		_CrtSetDbgFlag ( _CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF );
#endif
		srand(static_cast<unsigned int>(GetTickCount()));

		protoEventHook = wtw->evHook(WTW_ON_PROTOCOL_EVENT, onProtocolEvent, this);
		msgProcHook = wtw->evHook(WTW_EVENT_CHATWND_BEFORE_MSG_PROC, onMessage, this);
		menuRebuildHook = wtw->evHook(WTW_EVENT_MENU_REBUILD, onMenuRebuild, this);
		wndCreateHook = wtw->evHook(WTW_EVENT_ON_CHATWND_CREATE, onWndCreated, this);

		wtwMenuItemDef menuDef;
		menuDef.menuID = WTW_MENU_ID_CONTACT;
		menuDef.callback = onMenuClick;
		menuDef.itemId = menu::CRYPT;
		menuDef.menuCaption = text::CRYPT;
		menuDef.iconId = WTW_GRAPH_ID_ENCRYPTION;
		wtw->fnCall(WTW_MENU_ITEM_ADD, menuDef, NULL);

		menuDef.itemId = menu::DONT_CRYPT;
		menuDef.menuCaption = text::DONT_CRYPT;
		menuDef.iconId = NULL;
		wtw->fnCall(WTW_MENU_ITEM_ADD, menuDef, NULL);

		sett = new wtwUtils::Settings(wtw, hInst);

		return 0;
	}

	int PluginController::onUnload() {
		ciphered.clear();

		wtwMenuItemDef menuDef;
		menuDef.menuID = WTW_MENU_ID_CONTACT;
		menuDef.itemId = menu::CRYPT;
		wtw->fnCall(WTW_MENU_ITEM_DELETE, menuDef, NULL);

		menuDef.itemId = menu::DONT_CRYPT;
		wtw->fnCall(WTW_MENU_ITEM_DELETE, menuDef, NULL);

		wtw->fnCall(WTW_CCB_FUNCT_CLEAR, reinterpret_cast<WTW_PARAM>(hInst), 0);

		if (protoEventHook)
			wtw->evUnhook(protoEventHook);

		if(msgProcHook)
			wtw->evUnhook(msgProcHook);

		if(menuRebuildHook)
			wtw->evUnhook(menuRebuildHook);

		if(wndCreateHook)
			wtw->evUnhook(wndCreateHook);

		if(sett)
			delete sett;

		return 0;
	}

	WTW_PTR PluginController::onProtocolEvent(WTW_PARAM wParam, WTW_PARAM lParam, void *cbData) {
		wtwProtocolEvent *ev = reinterpret_cast<wtwProtocolEvent*>(wParam);
		if(ev->event == WTW_PEV_MESSAGE_RECV && ev->type == WTW_PEV_TYPE_BEFORE) {
			wtwMessageDef *msg = (wtwMessageDef*)lParam;
			if(!msg) 
				return S_OK;

			if(!(msg->msgFlags & WTW_MESSAGE_FLAG_INCOMING)) // only incoming
				return S_OK;

			if(!(msg->msgFlags & WTW_MESSAGE_FLAG_CHAT_MSG)) // only messages
				return S_OK;

			wtwContactDef& cnt = msg->contactData;
			if(!cnt.id || !cnt.netClass)
				return S_OK;
									
			wchar_t	id[512] = {0}; // contact unique id
			swprintf_s(id, 512, L"%s/%d/%s", cnt.netClass, cnt.netId, cnt.id);				

			PluginController& pc = PluginController::getInstance();
			std::map<std::wstring, Crypto>& ciphered = pc.getCiphered();
			WTWFUNCTIONS* wtw = pc.getWTWFUNCTIONS();

			if(ciphered.find(id) == ciphered.end())
				return S_OK; // this message is not to be encrypted
			
			return ciphered[id].recv(*msg);
		}
		return 0;
	}

	WTW_PTR PluginController::onMessage(WTW_PARAM wParam, WTW_PARAM lParam, void *ptr) {
		wtwBmpStruct *pBmp = reinterpret_cast<wtwBmpStruct*>(wParam);

		if (!pBmp || !pBmp->message.msgMessage) 
			return BMP_OK;

		if(!(pBmp->message.msgFlags & WTW_MESSAGE_FLAG_OUTGOING)) // only outgoing
			return BMP_OK;

		if(!(pBmp->message.msgFlags & WTW_MESSAGE_FLAG_CHAT_MSG)) // only messages
			return BMP_OK;

		if(pBmp->message.msgFlags & WTW_MESSAGE_FLAG_PICTURE) // no pictures
			return BMP_OK;

		if(pBmp->message.msgFlags & WTW_MESSAGE_FLAG_CONFERENCE) // no conferences
			return BMP_OK;

		if(!pBmp->message.contactData.netClass || !pBmp->message.contactData.id)
			return BMP_OK;

		PluginController& pc = PluginController::getInstance();
		wchar_t	id[512] = {0}; // contact unique id
		swprintf_s(id, 512, L"%s/%d/%s", 
			pBmp->message.contactData.netClass, 
			pBmp->message.contactData.netId, 
			pBmp->message.contactData.id);
		
		std::map<std::wstring, Crypto>& ciphered = pc.getCiphered();
		if(ciphered.find(id) == ciphered.end()) 
			return S_OK; // this message is not to be encrypted

		return ciphered[id].send(pBmp->message);
	}

	WTW_PTR PluginController::onMenuRebuild(WTW_PARAM wParam, WTW_PARAM lParam, void* ptr) {
		wtwMenuCallbackEvent* ev = reinterpret_cast<wtwMenuCallbackEvent*>(wParam);
		if(!ev || !ev->pInfo)
			return E_INVALIDARG;

		if(ev->pInfo->iContacts != 1)
			return 0;

		wtwContactDef& cnt = ev->pInfo->pContacts[0];
		if(!cnt.netClass || !cnt.id)
			return E_INVALIDARG;

		PluginController& pc = PluginController::getInstance();
		wtwPresenceDef pr;
		wchar_t fn[512] = {0};

		// get status
		swprintf_s(fn, 512, L"%s/%d/%s", cnt.netClass, cnt.netId, WTW_PF_STATUS_GET);
		pc.getWTWFUNCTIONS()->fnCall(fn, pr, NULL);

		if(pr.curStatus != WTW_PRESENCE_OFFLINE) { // add ony if connected to that network
			// check if cnt is crypted or not
			swprintf_s(fn, 512, L"%s/%d/%s", cnt.netClass, cnt.netId, cnt.id);

			if(pc.ciphered.find(fn) == pc.ciphered.end())
				ev->slInt.add(ev->itemsToShow, menu::CRYPT);
			else 
				ev->slInt.add(ev->itemsToShow, menu::DONT_CRYPT);
		}

		return 0;
	}

	WTW_PTR PluginController::onMenuClick(WTW_PARAM wParam, WTW_PARAM lParam, void* ptr) {		
		wtwMenuItemDef* menuItem = reinterpret_cast<wtwMenuItemDef*>(wParam);
		wtwMenuPopupInfo* menuPopupInfo = reinterpret_cast<wtwMenuPopupInfo*>(lParam);
		
		if(!menuItem || !menuPopupInfo || !menuPopupInfo->pContacts)
			return E_INVALIDARG;

		if(menuPopupInfo->iContacts != 1)
			return 0;

		wtwContactDef& cnt = menuPopupInfo->pContacts[0];
		if(!cnt.netClass || !cnt.id)
			return E_INVALIDARG;

		PluginController& pc = PluginController::getInstance();
		if(!pc.getSettings())
			return E_ABORT;

		wchar_t cntId[512] = {0};
		swprintf_s(cntId, 512, L"%s/%d/%s", cnt.netClass, cnt.netId, cnt.id);

		// turning on encryption
		if(pc.ciphered.find(cntId) == pc.ciphered.end()) { 
			HINSTANCE hInst = PluginController::getInstance().getDllHINSTANCE();
			INT_PTR dlgRes = DialogBox(hInst, MAKEINTRESOURCE(IDD_KEYDLG), 0, keyDlgProc);
			if(dlgRes != NULL && dlgRes != -1) {
				wchar_t* key = reinterpret_cast<wchar_t*>(dlgRes);
				wchar_t settKey[512] = {0};
				swprintf_s(settKey, 511, L"wtwCryptoAesKey/%s/%d/%s",
					cnt.netClass, cnt.netId, cnt.id);
				pc.ciphered[cntId] = Crypto(key);
				pc.getSettings()->setStr(settKey, key);
				pc.getSettings()->write();
				free(key); // _wcsdup
				pc.setSecuredButton(cnt, true, NULL);
			}
		}
		// turning off encryption
		else {
			wchar_t settKey[512];
			pc.ciphered.erase(cntId);
			pc.setSecuredButton(cnt, false, NULL);
			swprintf_s(settKey, 511, L"wtwCryptoAesKey/%s/%d/%s",
				cnt.netClass, cnt.netId, cnt.id);
			pc.getSettings()->setStr(settKey, L"");
			pc.getSettings()->write();
		}

		return 0;
	}

	void PluginController::setSecuredButton(const wtwContactDef& cnt, bool secured, void* pWnd) {
		wtwCommandEntry	entry;		
		if(pWnd)
			entry.pWnd = pWnd;
		else
			entry.pContactData = const_cast<wtwContactDef*>(&cnt);
		entry.itemId = menu::CRYPTED;
		entry.hInstance = PluginController::getInstance().getDllHINSTANCE();

		WTWFUNCTIONS* wtw = PluginController::getInstance().getWTWFUNCTIONS();
		if(secured) {
			entry.itemFlags = CCB_FLAG_CHANGECAPTION|CCB_FLAG_CHANGEICON|CCB_FLAG_CHANGETIP;
			entry.itemType = CCB_TYPE_STANDARD;
			entry.graphId = WTW_GRAPH_ID_ENCRYPTION;
			entry.toolTip = text::CRYPTED;
			wtw->fnCall(WTW_CCB_FUNCT_ADD, entry, 0);
		} else {
			if(wtw->fnCall(WTW_CCB_FUNCT_DEL, entry, 0) != S_OK)
				__LOG_F(wtw, WTW_LOG_LEVEL_ERROR, MDL, L"Could not remove button");
		}
	}

	WTW_PTR PluginController::onWndCreated(WTW_PARAM wParam, WTW_PARAM lParam, void *cbData) {
		wtwContactDef* cnt = reinterpret_cast<wtwContactDef*>(wParam);
		wtwChatWindowInfo* info = reinterpret_cast<wtwChatWindowInfo*>(lParam);

		if(!info || !cnt || !cnt->id || !cnt->netClass || !info->pWnd)
			return E_INVALIDARG;

		if(info->iContacts != 1)
			return 0;

		PluginController& pc = PluginController::getInstance();
		if(!pc.getSettings())
			return E_ABORT;

		wchar_t	cntId[512] = {0}; // contact unique id
		swprintf_s(cntId, 512, L"%s/%d/%s", cnt->netClass, cnt->netId, cnt->id);
		if(pc.ciphered.find(cntId) != pc.ciphered.end()) 
			setSecuredButton(*cnt, true, info->pWnd);
		else {
			wchar_t settKey[512];
			swprintf_s(settKey, 511, L"wtwCryptoAesKey/%s/%d/%s",
				cnt->netClass, cnt->netId, cnt->id);
			pc.getSettings()->read();
			std::wstring aesKey = pc.getSettings()->getWStr(settKey);
			if(aesKey.size() > 0) {
				pc.ciphered[cntId] = Crypto(aesKey.c_str());
				pc.setSecuredButton(*cnt, true, info->pWnd);
			}
		}

		return 0;
	}
};
