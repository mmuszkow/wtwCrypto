#pragma once

#include "../API/plInterface.h"
#include "stringUtils.h"

namespace wtwUtils {

	class Settings {
		void*			_config;
		WTWFUNCTIONS*	wtw;
		HINSTANCE		hInst;

	public:
		/** For normal plugins that have 1 config file */
		Settings(WTWFUNCTIONS *wtw, HINSTANCE hInst) {
			this->wtw = wtw;
			this->hInst = hInst;

			wchar_t buff[MAX_PATH + 1];
			wtwMyConfigFile configName;
			configName.bufferSize = MAX_PATH;
			configName.pBuffer = buff;
			wtw->fnCall(WTW_SETTINGS_GET_MY_CONFIG_FILE, 
				configName, reinterpret_cast<WTW_PARAM>(hInst));

			if(wtw->fnCall(WTW_SETTINGS_INIT_EX, 
				reinterpret_cast<WTW_PARAM>(configName.pBuffer), 
				reinterpret_cast<WTW_PARAM>(&_config)) != S_OK)
				_config = NULL;
			else
				read();
		}

		/** For protocols */
		Settings(WTWFUNCTIONS *wtw, HINSTANCE hInst, const wchar_t* name) {
			this->wtw = wtw;
			this->hInst = hInst;

			wchar_t	buff[MAX_PATH+1];
			wtwDirectoryInfo dir;
			dir.dirType = WTW_DIRECTORY_PROFILE;
			dir.flags = WTW_DIRECTORY_FLAG_FULLPATH;
			dir.bi.bufferSize = MAX_PATH;
			dir.bi.pBuffer = buff;

			if(wtw->fnCall(WTW_GET_DIRECTORY_LOCATION, dir, 0) != S_OK) {
				_config = NULL;
				return;
			}

			wchar_t	configName[MAX_PATH+128];
			if(name && wcscmp(name, L"") != 0)
				swprintf_s(configName, MAX_PATH+127, L"%s\\protoMail_%s.config", buff, name);
			else
				swprintf_s(configName, MAX_PATH+127, L"%s\\protoMail.config", buff);

			if(wtw->fnCall(WTW_SETTINGS_INIT_EX, 
				reinterpret_cast<WTW_PARAM>(configName), 
				reinterpret_cast<WTW_PARAM>(&_config)) != S_OK)
				_config = NULL;
			else
				read();
		}

		~Settings() {
			if (_config) {
				wtw->fnCall(WTW_SETTINGS_DESTROY, 
					reinterpret_cast<WTW_PARAM>(_config), 
					reinterpret_cast<WTW_PARAM>(hInst));
				_config = NULL;
			}
		}

		std::wstring getWStr(const wchar_t *name) {
			if (_config) {
				wchar_t* tmp = NULL;
				wtwGetStr(wtw, _config, name, L"", &tmp);
				std::wstring ret(tmp);
				delete [] tmp;
				return ret;
			}
			return L"";
		}

		std::string getStr(const wchar_t *name) {
			if (_config) {
				wchar_t* tmp = NULL;
				wtwGetStr(wtw, _config, name, L"", &tmp);
				std::string res = strUtils::convertEnc(tmp);
				delete [] tmp;
				return res;
			}
			return "";
		}

		std::vector<std::wstring> getArray(const wchar_t *name) {
			if (_config) {
				wchar_t* tmp = NULL;
				wtwGetStr(wtw, _config, name, L"", &tmp);
				std::wstring ret(tmp);
				delete [] tmp;

				return strUtils::explode(ret);
			}
			return std::vector<std::wstring>();
		}

		inline void Settings::setStr(wchar_t const* name, wchar_t const* val) {
			if(_config) wtwSetStr(wtw,_config,name,val);
		}

		inline void Settings::setInt(wchar_t const* name, int const val) {
			if(_config) wtwSetInt(wtw,_config,name,val);			
		}

		inline int Settings::getInt(wchar_t const* name, int defVal) {
			if(_config) return wtwGetInt(wtw, _config, name, defVal);
			return defVal;
		}

		inline void Settings::read() {
			if(_config)	wtw->fnCall(WTW_SETTINGS_READ, reinterpret_cast<WTW_PARAM>(_config), 0);
		}

		inline void Settings::write() {
			if(_config) wtw->fnCall(WTW_SETTINGS_WRITE, reinterpret_cast<WTW_PARAM>(_config), 0);
		}
	};
};
