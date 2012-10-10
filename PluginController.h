#pragma once

#include "stdinc.h"
#include "Crypto.h"

namespace wtwCrypto {
	namespace menu {
		static const wchar_t CRYPT_ME[] = L"wtwCrypto/cryptMe";
		static const wchar_t DONT_CRYPT_ME[] = L"wtwCrypto/dontCryptMe";
		static const wchar_t CRYPTED[] = L"wtwCrypto/crypted";
	};
	namespace text {
		static const wchar_t CRYPT_ME[] = L"Szyfruj";
		static const wchar_t CRYPTED[] = L"Rozmowa szyfrowana";
		static const wchar_t DONT_CRYPT_ME[] = L"Nie szyfruj";
		static const wchar_t NON_CIPHERED[] = L"Ta wiadomoœæ zosta³a otrzymana jako niezaszyfrowana";
		static const wchar_t NEG_FAIL[] = L"Negocjacja klucza nieudana";
	};

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

	PluginController() : wtw(NULL), hInst(NULL), 
		protoEventHook(NULL), menuRebuildHook(NULL), 
		msgProcHook(NULL), wndCreateHook(NULL) {}
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
			L"Szyfrowanie wiadomoœci (AES, Diffie-Hellman)", // plugin description
			L"© 2012 Maciej Muszkowski",				// copyright
			L"Maciej Muszkowski",						// author
			L"maciek.muszkowski@gmail.com",				// authors contact
			L"http://www.alset.pl/Maciek/",				// authors webpage
			L"",										// url to xml with autoupdate data
			PLUGIN_API_VERSION,							// api version
			MAKE_QWORD(0, 1, 0, 0),						// plugin version
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

	static WTW_PTR onKeyTimeout(WTW_PARAM wParam, WTW_PARAM lParam, void *ptr);
};

}; // namespace wtwCrypto
