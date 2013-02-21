#pragma once

#include "stdinc.h"

#include "AES.h"
#include "DH.h"
#include "WtwMsg.h"

namespace wtwCrypto {

    class Crypto {
        AES                aes;
    public:
        Crypto() {}
        Crypto(const Crypto& other) {
            aes = other.aes;
        }
        Crypto(const wchar_t* aesKeyHex);
        Crypto& operator=(const Crypto& other) {
            if(this == &other) return *this;
            aes = other.aes;
            return *this;
        }
        WTW_PTR send(const wtwMessageDef& msg);
        WTW_PTR recv(const wtwMessageDef& msg);
    };
};
