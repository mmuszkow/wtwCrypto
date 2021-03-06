#pragma once

#include "stdinc.h"
#include "Crypto.h"
#include "../common/Settings.h"

namespace wtwCrypto {
	namespace menu {
		static const wchar_t CRYPTED[] = L"wtwCrypto/crypted";
		static const wchar_t CRYPT[] = L"wtwCrypto/crypt";
		static const wchar_t DONT_CRYPT[] = L"wtwCrypto/dontCrypt";
	};
	namespace text {
		static const wchar_t CRYPTED[] = L"Rozmowa szyfrowana";
		static const wchar_t CRYPT[] = L"Szyfruj";
		static const wchar_t DONT_CRYPT[] = L"Nie szyfruj";
	};

INT_PTR CALLBACK keyDlgProc(HWND hDlg, UINT Msg, WPARAM wParam, LPARAM lParam);

class SettingsPage; // forward decl

/** Singleton */
class PluginController {
	// basic
	WTWFUNCTIONS*	wtw;
	HINSTANCE		hInst;

	std::map<std::wstring, Crypto>	ciphered;

	HANDLE			protoEventHook;
	HANDLE			msgProcHook;
	HANDLE			menuRebuildHook;
	HANDLE			wndCreateHook;

	wtwUtils::Settings*	sett;

	PluginController() : wtw(NULL), hInst(NULL), 
		protoEventHook(NULL), menuRebuildHook(NULL), 
		msgProcHook(NULL), wndCreateHook(NULL), 
		sett(NULL) {}
	PluginController(const PluginController&);

	static WTW_PTR onProtocolEvent(WTW_PARAM wParam, WTW_PARAM lParam, void *cbData);
	static WTW_PTR onWndCreated(WTW_PARAM wParam, WTW_PARAM lParam, void *cbData);
	static WTW_PTR onMessage(WTW_PARAM wParam, WTW_PARAM lParam, void *ptr);
	static WTW_PTR onMenuRebuild(WTW_PARAM wParam, WTW_PARAM lParam, void* ptr);
	static WTW_PTR onMenuClick(WTW_PARAM wParam, WTW_PARAM lParam, void* ptr);

	static void setSecuredButton(const wtwContactDef& cnt, bool secured, void* pWnd);
public:

	static PluginController& getInstance() {
		static PluginController instance;
		return instance;
	}

	int onLoad(WTWFUNCTIONS *fn);

	int onUnload();

	inline const WTWPLUGINFO* getPlugInfo()	{
		static WTWPLUGINFO _plugInfo = {
			sizeof(WTWPLUGINFO),						// struct size
			L"wtwCrypto",								// plugin name
			L"Szyfrowanie wiadomości (AES, Diffie-Hellman)", // plugin description
			L"© 2012-2014 Maciej Muszkowski",			// copyright
			L"Maciej Muszkowski",						// author
			L"maciek.muszkowski@gmail.com",				// authors contact
			L"http://www.alset.pl/Maciek/",				// authors webpage
			L"",										// url to xml with autoupdate data
			PLUGIN_API_VERSION,							// api version
			MAKE_QWORD(0, 4, 0, 0),						// plugin version
			WTW_CLASS_UTILITY,							// plugin class
			NULL,										// function called after "O wtyczce..." pressed
			L"{153c977e-2ab7-480b-9ee4-ae9f58d39695}",	// guid
			NULL,										// dependencies (list of guids)
			0,											// options
			0, 0, 0										// reserved
		};
		return &_plugInfo;
	}

	inline void setDllHINSTANCE(const HINSTANCE h) {
		hInst = h;
	}

	inline HINSTANCE getDllHINSTANCE() const {
		return hInst;
	}

	inline WTWFUNCTIONS* getWTWFUNCTIONS() const {
		return wtw;
	}

	inline std::map<std::wstring, Crypto>& getCiphered() {
		return ciphered;
	}

	inline wtwUtils::Settings* getSettings() {
		return sett;
	}
};

}; // namespace wtwCrypto
