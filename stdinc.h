#ifndef _MSC_VER
//#error This code can be only compiled using Visual Studio
#endif

#pragma once

#include <WinSock2.h>
#include <plInterface.h>

#ifdef _DEBUG
# define CRTDBG_MAP_ALLOC
# include <stdlib.h>
# include <crtdbg.h> 
#endif

#include <string>
#include <vector>
#include <map>

#include <ctime>
#include <windows.h>

#include "resource.h"

static const wchar_t MDL[] = L"CRPT";
static INT_PTR bkBrush = reinterpret_cast<INT_PTR>(GetStockObject(WHITE_BRUSH));

static std::wstring key2hex(const BYTE* key, const int keySize) {
	wchar_t bhex[4];	
	
	if(!key) 
		return L"";

	wchar_t* hex = new wchar_t[(keySize<<1) + 1];
	for(int i=0; i<keySize; i++) {
		swprintf_s(bhex, 3, L"%.2X", key[i]);
		hex[i<<1] = bhex[0];
		hex[(i<<1)+1] = bhex[1];
	}
	hex[keySize<<1] = 0;

	std::wstring res(hex);
	delete [] hex;
	return res;
}

static bool hex2key(const std::wstring& hex, BYTE* key, unsigned int keySize) {
	wchar_t bhex[2];
	const wchar_t* hexS = hex.c_str();

	if(hex.size() < (keySize<<1))
		return false;

	for(unsigned int i=0; i<(keySize<<1); i+=2) {
		bhex[0] = hexS[i];
		bhex[1] = hexS[i+1];
		if(!iswxdigit(bhex[0]) || !iswxdigit(bhex[1])) {
			return false;
		}

		bhex[0] = towupper(bhex[0]);
		bhex[1] = towupper(bhex[1]);
		iswdigit(bhex[0]) ?	bhex[0] -= 0x30 : bhex[0] -= 0x37;
		iswdigit(bhex[1]) ?	bhex[1] -= 0x30 : bhex[1] -= 0x37;
		key[i>>1] = ((bhex[0]<<4)&0xF0)|(bhex[1] & 0xF);
	}

	return true;
}
