#pragma once

#include "stdinc.h"

#include <openssl/bn.h>

typedef BIGNUM* (*pBN_bin2bn)(const unsigned char *s, int len, BIGNUM *ret);
typedef int	(*pBN_bn2bin)(const BIGNUM *a, unsigned char *to);
typedef BIGNUM* (*pBN_new)(void);
typedef BN_CTX* (*pBN_CTX_new)(void);
typedef int	(*pBN_mod_exp)(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx);
typedef void (*pBN_free)(BIGNUM *a);
typedef void (*pBN_CTX_free)(BN_CTX *c);

namespace wtwCrypto {
	class OpenSSL_ModExp {
		HMODULE			hLib;
	public:
		pBN_bin2bn		BN_bin2bn;
		pBN_bn2bin		BN_bn2bin;
		pBN_new			BN_new;
		pBN_CTX_new		BN_CTX_new;
		pBN_mod_exp		BN_mod_exp;
		pBN_free		BN_free;
		pBN_CTX_free	BN_CTX_free;

	private:
		OpenSSL_ModExp() {
			hLib = LoadLibraryW(L"libeay32.dll");
			if(hLib) {
				BN_bin2bn = reinterpret_cast<pBN_bin2bn>(GetProcAddress(hLib, "BN_bin2bn"));
				BN_bn2bin = reinterpret_cast<pBN_bn2bin>(GetProcAddress(hLib, "BN_bn2bin"));
				BN_new = reinterpret_cast<pBN_new>(GetProcAddress(hLib, "BN_new"));
				BN_CTX_new = reinterpret_cast<pBN_CTX_new>(GetProcAddress(hLib, "BN_CTX_new"));
				BN_mod_exp = reinterpret_cast<pBN_mod_exp>(GetProcAddress(hLib, "BN_mod_exp"));
				BN_free = reinterpret_cast<pBN_free>(GetProcAddress(hLib, "BN_free"));
				BN_CTX_free = reinterpret_cast<pBN_CTX_free>(GetProcAddress(hLib, "BN_CTX_free"));

				if(	!BN_bin2bn || !BN_bn2bin || !BN_new || !BN_CTX_new 
					|| !BN_mod_exp || !BN_free || !BN_CTX_free) {
					FreeLibrary(hLib);
					hLib = NULL;
				}
			}
		}
	public:
		~OpenSSL_ModExp() {
			if(hLib)
				FreeLibrary(hLib);
		}

		inline static OpenSSL_ModExp& func() {
			static OpenSSL_ModExp instance;
			return instance;
		}

		inline bool loaded() const {
			return (hLib != NULL);
		}
	};
};
