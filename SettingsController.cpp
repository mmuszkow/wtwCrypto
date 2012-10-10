#include "stdinc.h"
#include "SettingsController.h"
#include "PluginController.h"

namespace wtwCrypto {

	std::vector<std::wstring> SettingsController::split(const std::wstring& list) {
		std::vector<std::wstring> ret;
		if(list.size()>0) {
			size_t pos = 0;
			size_t found;
			while ((found = list.find(L"\r\n", pos)) != std::wstring::npos) {
				ret.push_back(list.substr(pos, found - pos));
				pos = found + 2;
			}
			ret.push_back(list.substr(pos));
		}
		return ret;
	}

	void SettingsController::init(WTWFUNCTIONS *wtw, HINSTANCE hInst) {
		
		if(_config)	return;

		this->wtw = wtw;
		this->hInst = hInst;

		wtwMyConfigFile configName;
		initStruct(configName);
		configName.bufferSize = MAX_PATH + 1;
		configName.pBuffer = new wchar_t[MAX_PATH + 1];

		wtw->fnCall(WTW_SETTINGS_GET_MY_CONFIG_FILE, 
			reinterpret_cast<WTW_PARAM>(&configName), 
			reinterpret_cast<WTW_PARAM>(hInst));
		if(wtw->fnCall(WTW_SETTINGS_INIT_EX, 
			reinterpret_cast<WTW_PARAM>(configName.pBuffer), 
			reinterpret_cast<WTW_PARAM>(&_config)) != S_OK)
			_config = NULL;
		delete [] configName.pBuffer;
	}

	void SettingsController::deinit() {
		if (_config) {
			wtw->fnCall(WTW_SETTINGS_DESTROY, reinterpret_cast<WTW_PARAM>(_config), reinterpret_cast<WTW_PARAM>(hInst));
			_config = NULL;
		}
	}

	std::wstring SettingsController::getWStr(const wchar_t *name) {
		if (_config) {
			wtw->fnCall(WTW_SETTINGS_READ, reinterpret_cast<WTW_PARAM>(_config), 0);
			wchar_t* tmp = NULL;
			wtwGetStr(wtw, _config, name, L"", &tmp);
			std::wstring ret(tmp);
			delete [] tmp;
			return ret;
		}
		return L"";
	}

	std::vector<std::wstring> SettingsController::getArray(const wchar_t *name) {
		if (_config) {
			wtw->fnCall(WTW_SETTINGS_READ, reinterpret_cast<WTW_PARAM>(_config), 0);
			wchar_t* tmp = NULL;
			wtwGetStr(wtw, _config, name, L"", &tmp);
			std::wstring ret(tmp);
			delete [] tmp;

			return split(ret);
		}
		return std::vector<std::wstring>();
	}

	void SettingsController::setStr(wchar_t const* name, wchar_t const* val) {
		if (_config) {
			wtwSetStr(wtw,_config,name,val);
			wtw->fnCall(WTW_SETTINGS_WRITE, reinterpret_cast<WTW_PARAM>(_config), 0);
		}
	}

	void SettingsController::setInt(wchar_t const* name, int const val) {
		if (_config) {
			wtwSetInt(wtw,_config,name,val);
			wtw->fnCall(WTW_SETTINGS_WRITE, reinterpret_cast<WTW_PARAM>(_config), 0);
		}
	}

	int SettingsController::getInt(wchar_t const* name, int defVal) {
		if (_config) {
			wtw->fnCall(WTW_SETTINGS_READ, reinterpret_cast<WTW_PARAM>(_config), 0);
			return wtwGetInt(wtw, _config, name, defVal);
		}
		return defVal;
	}

}
