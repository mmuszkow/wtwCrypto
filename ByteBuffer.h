#pragma once

#include "stdinc.h"
#include <wincrypt.h>
#pragma comment(lib, "Crypt32.lib")

namespace wtwCrypto {
    class AesBuffer {
	public:
		static const int IVSIZEBYTES = 16;
	private:
		BYTE	 iv[IVSIZEBYTES];
        BYTE*    data;
        DWORD    len;
    public:
		AesBuffer() : data(NULL), len(0) { 
			int z = 4;
			int a = 3;
		}

        // parameters must be in this order
		AesBuffer(bool base64, const std::wstring& str) : data(NULL), len(0) {
            if(str.size() > 0) {
				// decode AES buffer
                if(base64) {
                    if(CryptStringToBinary(str.c_str(), str.size(), CRYPT_STRING_BASE64, NULL, &len, NULL, NULL) == FALSE) {
						len = 0;
                        return;
                    }

					if (len <= IVSIZEBYTES) {
						len = 0;
						data = NULL;
						return;
					}

					data = new BYTE[len];
                    if(CryptStringToBinary(str.c_str(), str.size(), CRYPT_STRING_BASE64, data, &len, NULL, NULL) == FALSE) {
                        len = 0;
                        delete [] data;
                        data = NULL;
                        return;
                    }

					// extract IV, TODO: is this safe?
					len -= IVSIZEBYTES;
					memcpy(iv, data, IVSIZEBYTES);
					memcpy(data, data + IVSIZEBYTES, len);
                } else {
					// create AES buffer from utf-16 string
                    len = (str.size()<<1) + 2;
                    data = new BYTE[len + 16];
                    memcpy(data, str.c_str(), len);

					//RtlGenRandom(iv, IVSIZEBYTES); // TODO
					memset(iv, 0, IVSIZEBYTES);
                }
            }
        }

		AesBuffer(const AesBuffer& b2) {
            data = NULL;
            this->len = 0;
            assign(b2.data, b2.len, b2.iv);
        }

		AesBuffer(const BYTE* arr, DWORD len, const BYTE* iv) {
            data = NULL;
            this->len = 0;
            assign(arr, len, iv);
        }

		~AesBuffer() {
            if(data) delete [] data;
        }

		AesBuffer& operator=(const AesBuffer& b2) {
            if(this == &b2) return *this;
            if(data) delete [] data;
            assign(b2.data, b2.len, b2.iv);
            return *this;
        }

        inline DWORD size() const {
            return len;
        }

        inline BYTE* getData() {
            return data;
        }

		inline BYTE* getIV() {
			return iv;
		}

        void assign(const BYTE* arr, DWORD len, const BYTE* iv) {
            BYTE* prevData = data;
			if (len && arr && iv) {
				if (this->iv != iv)
					memcpy(this->iv, iv, IVSIZEBYTES);

                DWORD prevLen = this->len;
                data = new BYTE[len];
                this->len = len;
                memset(data, 0, len);
                if(prevLen > 0)
                    memcpy(data, arr, prevLen);
            } else {
                data = NULL;
                this->len = 0;
            }
            if(prevData) delete [] prevData; // in the end to allow realloc
        }

        wchar_t* dupAsString() const {
            return _wcsdup(reinterpret_cast<wchar_t*>(data));
        }

        void padTo16bytes() {
            if(len % 16 == 0)
                return;

            DWORD newLen = len;
            while(newLen % 16 != 0) 
                newLen++;

            assign(data, newLen, iv);
        }

        std::wstring toBase64() const {
			// combine IV and data
			BYTE* all = new BYTE[IVSIZEBYTES + len];
			memcpy(all, iv, IVSIZEBYTES);
			memcpy(all + IVSIZEBYTES, data, len);			

            DWORD strLen;
			if (CryptBinaryToString(all, IVSIZEBYTES + len, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &strLen) == FALSE) {
				delete [] all;
				return L"";
			}
            
            wchar_t* str = new wchar_t[strLen];
			if (CryptBinaryToString(data, IVSIZEBYTES + len, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, str, &strLen) == FALSE) {
                delete [] str;
				delete [] all;
                return L"";
            }			

            std::wstring ret(str);
            delete [] str;
			delete [] all;
            return ret;
        }
    };
};
