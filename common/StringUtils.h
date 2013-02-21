#pragma once

#include <windows.h>
#include <string>
#include <vector>

namespace strUtils {
	/** GetWindowTextLengthA + GetWindowTextA = std::string (local encoding!) */
	static std::string getWindowTextStr(HWND hWnd) {
		int len = GetWindowTextLengthA(hWnd);
		if(len == 0) return "";
		char* buff = new char[len+2];
		GetWindowTextA(hWnd, buff, len+1);
		std::string res = buff;
		delete [] buff;
		return res;
	}

	/** GetWindowTextLengthW + GetWindowTextW = std::wstring */
	static std::wstring getWindowTextWideStr(HWND hWnd) {
		int len = GetWindowTextLengthW(hWnd);
		if(len == 0) return L"";
		wchar_t* buff = new wchar_t[len+2];
		GetWindowTextW(hWnd, buff, len+1);
		std::wstring res = buff;
		delete [] buff;
		return res;
	}

	/** GetWindowTextLengthA + GetDlgItemTextA = std::string */
	static std::string getDlgItemTextStr(HWND hWnd, int id) {
		int len = GetWindowTextLengthA(GetDlgItem(hWnd, id));
		if(len == 0) return "";
		char* buff = new char[len+2];
		GetDlgItemTextA(hWnd, id, buff, len+1);
		std::string res = buff;
		delete [] buff;
		return res;
	}

	/** GetWindowTextLengthW + GetDlgItemTextW = std::wstring */
	static std::wstring getDlgItemTextWideStr(HWND hWnd, int id) {
		int len = GetWindowTextLengthW(GetDlgItem(hWnd, id));
		if(len == 0) return L"";
		wchar_t* buff = new wchar_t[len+2];
		GetDlgItemTextW(hWnd, id, buff, len+1);
		std::wstring res = buff;
		delete [] buff;
		return res;
	}


	static inline bool startsWith(const std::string& str, const std::string& prefix) {
		return (str.compare(0, prefix.size(), prefix) == 0);
	}

	static bool endsWith(std::string const &fullString, std::string const &ending) {
		if (fullString.length() >= ending.length()) {
			return (0 == fullString.compare (fullString.length() - ending.length(), ending.length(), ending));
		} else
			return false;
	}

	/** Splits string into lines by \r\n */
	static std::vector<std::string> explode(const std::string& str) {
		std::vector<std::string> ret;
		if(str.size()>0) {
			size_t pos = 0;
			size_t found;
			while ((found = str.find("\r\n", pos)) != std::string::npos) {
				ret.push_back(str.substr(pos, found - pos));
				pos = found + 2;
			}
			ret.push_back(str.substr(pos));
		}
		return ret;
	}

	/** Splits string into lines by \r\n */
	static std::vector<std::wstring> explode(const std::wstring& str) {
		std::vector<std::wstring> ret;
		if(str.size()>0) {
			size_t pos = 0;
			size_t found;
			while ((found = str.find(L"\r\n", pos)) != std::wstring::npos) {
				ret.push_back(str.substr(pos, found - pos));
				pos = found + 2;
			}
			ret.push_back(str.substr(pos));
		}
		return ret;
	}

	static std::string toLower(const std::string& str) {
		std::string res(str);
		unsigned int i, len = res.size();
		for(i=0; i<len; i++)
			res[i] = tolower(res[i]);
		return res;
	}

	static std::wstring toLower(const std::wstring& str) {
		std::wstring res(str);
		unsigned int i, len = res.size();
		for(i=0; i<len; i++)
			res[i] = towlower(res[i]);
		return res;
	}

	static std::string extractFilename(const std::string& str) {
		size_t pos = str.find_last_of('\\');

		// if didn't find \ try /
		if(pos == std::string::npos) str.find_last_of('/');

		// single filename
		if(pos == std::string::npos) return str;

		return str.substr(pos + 1);
	}

	struct hostPort {
		std::string	host;
		int			port;
	};

	/** Extracts host and port from string "host:port" */
	static hostPort extractHostPort(const std::string& str, int defaultPort) {
		hostPort	hp;
		size_t		pos;

		// No port info, set to default
		if((pos = str.find_last_of(':')) == std::string::npos) {
			hp.host = str;
			hp.port = defaultPort;
			return hp;
		}

		// Avoid seg fault if user puts "host:"
		if(pos+1 >= str.size()) {
			hp.host = str.substr(0, pos);
			hp.port = defaultPort;
			return hp;
		}

		// Finally cut the host part and convert the port part of the string
		hp.host = str.substr(0, pos);
		hp.port = atoi(&str.c_str()[pos+1]);
		return hp;
	}

	struct hostPortHttp {
		std::wstring	host;
		std::wstring	object;
		int				port;
		bool			ssl;
	};

	/** Extracts host and port from std::wstring "uri://host:port" */
	static hostPortHttp extractHostPortFromUrl(const std::wstring& url) {
		hostPortHttp	hp;
		size_t			pos;
		std::wstring	str(url);

		hp.ssl = false;
		hp.port = 80;

		// skip http:// or https://
		if((pos = str.find(L"://")) != std::wstring::npos) {
			if(toLower(str.substr(0, pos)) == L"https") {
				hp.ssl = true;
				hp.port = 443;
			}
			str = str.substr(pos + 3);
		}

		// remove anything after host name
		if((pos = str.find_first_of('/')) != std::wstring::npos) {
			hp.object = str.substr(pos);
			str = str.substr(0, str.size() - hp.object.size());
		} else
			hp.object = L"/";
		
		// No port info, set to default
		if((pos = str.find_last_of(L':')) == std::wstring::npos) {
			hp.host = str;
			return hp;
		}

		// Avoid seg fault if user puts "host:"
		if(pos+1 >= str.size()) {
			hp.host = str.substr(0, pos);
			return hp;
		}

		// Finally cut the host part and convert the port part of the string
		hp.host = str.substr(0, pos);
		hp.port = _wtoi(&str.c_str()[pos+1]);
		return hp;
	}

	/** Converts std::string with defined encoding to UTF-16 std::wstring */
	static std::wstring convertEnc(const std::string& str, UINT encoding = CP_UTF8) {
		int len = MultiByteToWideChar(encoding, 0, str.c_str(), -1, NULL, 0);
		if(len == 0) return L"";

		wchar_t* buff = new wchar_t[len+1];
		MultiByteToWideChar(encoding, 0, str.c_str(), -1, buff, len);
		buff[len] = 0;
		std::wstring res(buff);
		delete [] buff;
		return res;
	}

	/** Converts UTF-16 std::wstring to std::string with choosen encoding */
	static std::string convertEnc(const std::wstring& str, UINT encoding = CP_UTF8) {
		int len = WideCharToMultiByte(encoding, 0, str.c_str(), -1, NULL, 0, 0, 0);
		if(len == 0) return "";

		char* buff = new char[len+1];
		WideCharToMultiByte(encoding, 0, str.c_str(), -1, buff, len, 0, 0);
		buff[len] = 0;
		std::string res(buff);
		delete [] buff;
		return res;
	}

	/** Converts std::string with defined encoding to std::string with different encoding */
	static std::string convertEnc(const std::string& str, UINT inEncoding, UINT outEncoding) {
		if(str.size() == 0) return "";
		return convertEnc(convertEnc(str, inEncoding), outEncoding);
	}

	/** C-formatted string */
	template <class T>
	class FString {
		FString() {}
	public:
	};

	template <>
	class FString<char> {
		char*	data;
		size_t	len;

		FString() {}
	public:
		FString(const char* fmt, ...) {
			va_list ap;
		
			va_start(ap, fmt);
			len = _vscprintf(fmt, ap) + 1;
			data = new char[len+1];
			vsprintf_s(data, len, fmt, ap);
			va_end(ap);

			len = strlen(data);
		}

		void assign(const FString& str) {
			len = str.len;
			if(len == 0 || !str.data) return;
			if(data) delete [] data;
			data = new char[len+1];
			strcpy_s(data, len, str.data);
			data[len] = 0;
		}

		FString(const FString& str) {
			data = NULL;
			assign(str);
		}

		inline FString& operator=(const FString &s2) { 
			assign(s2);
			return *this; 
		}

		inline const char* c_str() const {
			return data;
		}

		~FString() {
			if(data) delete [] data;
		}
	};

	template <>
	class FString<wchar_t> {
		wchar_t*	data;
		size_t		len;

		FString() {}
	public:
		FString(const wchar_t* fmt, ...) {
			va_list ap;
		
			va_start(ap, fmt);
			len = _vscwprintf(fmt, ap) + 1;
			data = new wchar_t[len+1];

			vswprintf_s(data, len, fmt, ap);
			va_end(ap);

			len = wcslen(data);
		}

		void assign(const FString& str) {
			len = str.len;
			if(len == 0 || !str.data) return;
			if(data) delete [] data;
			data = new wchar_t[len+1];
			wcscpy_s(data, len, str.data);
			data[len] = 0;
		}

		FString(const FString& str) {
			data = NULL;
			assign(str);
		}

		inline FString& operator=(const FString &s2) { 
			assign(s2);
			return *this; 
		}

		inline const wchar_t* c_str() const {
			return data;
		}

		~FString() {
			if(data) delete [] data;
		}
	};
};