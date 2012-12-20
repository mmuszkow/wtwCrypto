#include "stdinc.h"

std::wstring key2hex(const BYTE* key, const int len) {
	wchar_t bhex[4];	
	
	if(!key) 
		return L"ERROR";

	wchar_t* hex = new wchar_t[(len<<1) + 1];
	for(int i=0; i<len; i++) {
		swprintf_s(bhex, 3, L"%.2X", key[i]);
		hex[i<<1] = bhex[0];
		hex[(i<<1)+1] = bhex[1];
	}
	hex[len<<1] = 0;

	std::wstring res(hex);
	delete [] hex;
	return res;
}

bool hex2key(const std::wstring& hex, BYTE* key, int keyLen) {
	wchar_t bhex[2];
	const wchar_t* hexS = hex.c_str();

	if(hex.size() != (keyLen<<1))
		return false;

	for(int i=0; i<(keyLen<<1); i+=2) {
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
