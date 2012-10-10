#pragma once
/*
#include "stdinc.h"

namespace wtwCrypto {
	static DWORD crc32(WTWFUNCTIONS* wtw, const BYTE* arr, size_t len) {
		DWORD		hash;
		wtwHashData	hashData;

		if(!arr || len == 0)
			return 0;

		hashData.pDataToHash = arr;
		hashData.nDataToHash = len;
		hashData.hashType = WTW_CRYPTO_HASH_TYPE_CRC32;
		hashData.hash = &hash;
		hashData.hashLen = 4;
		hashData.flags = WTW_CRYPTO_HASH_FLAG_OUT_BINARY;

		WTW_PTR res = wtw->fnCall(WTW_CRYPTO_HASH_SIMPLE, hashData, 0);
		if(FAILED(res)) {
			__LOG_F(wtw, WTW_LOG_LEVEL_ERROR, MIDL, L"CRC32 computation failed, err=%d", res);
			return 0;
		}

		return hash;
	}

	static DWORD crc32(WTWFUNCTIONS* wtw, const wchar_t* str) {
		if(!str) 
			return 0;

		return crc32(wtw, reinterpret_cast<const BYTE*>(str), (wcslen(str)<<1) + 2);
	}
};
*/
