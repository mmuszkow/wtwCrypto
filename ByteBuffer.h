#pragma once

#include "stdinc.h"
#include <wincrypt.h>
#pragma comment(lib, "Crypt32.lib")

namespace wtwCrypto {
    class ByteBuffer {
        BYTE*    data;
        DWORD    len;
    public:
        ByteBuffer() {
            data = NULL;
            len = 0;
        }

        // parameters must be in this order
        ByteBuffer(bool base64, const std::wstring& str) {
            if(str.size() > 0) {
                if(base64) {
                    if(CryptStringToBinary(str.c_str(), str.size(), CRYPT_STRING_BASE64, NULL, &len, NULL, NULL) == FALSE) {
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
                } else {
                    len = (str.size()<<1) + 2;
                    data = new BYTE[len];
                    memcpy(data, str.c_str(), len);
                }
            } else {
                len = 0;
                data = NULL;
            }
        }

        ByteBuffer(const ByteBuffer& b2) {
            data = NULL;
            this->len = 0;
            assign(b2.data, b2.len);
        }

        ByteBuffer(const BYTE* arr, DWORD len) {
            data = NULL;
            this->len = 0;
            assign(arr, len);
        }

        ~ByteBuffer() {
            if(data) delete [] data;
        }

        ByteBuffer& operator=(const ByteBuffer& b2) {
            if(this == &b2) return *this;
            if(data) delete [] data;
            assign(b2.data, b2.len);
            return *this;
        }

        inline DWORD size() const {
            return len;
        }

        inline BYTE* getData() {
            return data;
        }

        void assign(const BYTE* arr, DWORD len) {
            BYTE* prevData = data;
            if(len && arr) {
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

            assign(data, newLen);
        }

        std::wstring toBase64() const {
            DWORD strLen;
            if(CryptBinaryToString(data, len, CRYPT_STRING_BASE64|CRYPT_STRING_NOCRLF, NULL, &strLen) == FALSE)
                return L"";
            
            wchar_t* str = new wchar_t[strLen];
            if(CryptBinaryToString(data, len, CRYPT_STRING_BASE64|CRYPT_STRING_NOCRLF, str, &strLen) == FALSE) {
                delete [] str;
                return L"";
            }

            std::wstring ret(str);
            delete [] str;
            return ret;
        }
    };
};
