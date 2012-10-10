#pragma once

#include "stdinc.h"

namespace wtwCrypto {

	namespace config {
		static const wchar_t CRYPTED_LIST[] = L"wtwCrypto/cryptedList";
	};

	class SettingsController {

		void*			_config;
		WTWFUNCTIONS*	wtw;
		HINSTANCE		hInst;

		static std::vector<std::wstring> split(const std::wstring& list);

		SettingsController() : _config(NULL), wtw(NULL) {}
		SettingsController(const SettingsController&);
	public:
		static SettingsController& getInstance() {
			static SettingsController instance;
			return instance;
		}

		void init(WTWFUNCTIONS *wtw, HINSTANCE hInst);
		std::wstring getWStr(const wchar_t* name);
		std::vector<std::wstring> getArray(const wchar_t* name);
		std::string getStr(const wchar_t* name);
		int getInt(wchar_t const* name, int defVal = -1);
		void setStr(const wchar_t* name, const wchar_t* val);
		void setInt(wchar_t const*name, int const val);
		void deinit();
	};
}; // namespace wtwRSS
