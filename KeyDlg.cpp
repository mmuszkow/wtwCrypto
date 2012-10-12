#include "stdinc.h"
#include "DH.h"
#include "../common/StringUtils.h"

namespace wtwCrypto {
	INT_PTR CALLBACK keyDlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam)
	{
		switch(msg) {
			case WM_INITDIALOG: return TRUE;
			case WM_COMMAND: 
				switch (LOWORD(wParam)) {
					case IDC_GENKEY: 
						{
							DH* dh;
							if(GetProp(hDlg, L"wtwCrypto/dh") != NULL) {
								dh = reinterpret_cast<DH*>(GetProp(hDlg, L"wtwCrypto/dh"));
								dh->recreateKeys();
							}
							else {
								dh = new DH();
								SetProp(hDlg, L"wtwCrypto/dh", dh);
							}

							std::wstring pubKey = DH::key2hex(dh->getPublicKey());
							SetDlgItemText(hDlg, IDC_MYPUBKEY, pubKey.c_str());
							if(pubKey != L"ERROR") {
								EnableWindow(GetDlgItem(hDlg, IDC_IMPORTKEY), TRUE);
								EnableWindow(GetDlgItem(hDlg, IDC_HISPUBKEY), TRUE);
							}
							return TRUE;
						}
					case IDC_IMPORTKEY:
						{
							DH* dh;
							if(GetProp(hDlg, L"wtwCrypto/dh") != NULL) {
								dh = reinterpret_cast<DH*>(GetProp(hDlg, L"wtwCrypto/dh"));
								std::wstring hisKey = strUtils::getDlgItemTextWideStr(hDlg, IDC_HISPUBKEY);
								BYTE dhKey[DH::KEYSIZEBYTES];

								if(!DH::hex2key(hisKey, dhKey)) {
									MessageBox(hDlg, L"Zły format klucza (za krótki/długi lub niedozwolone znaki)", L"Import klucza", MB_OK|MB_ICONERROR);
									return TRUE;
								}
								dh->importKey(dhKey);

								std::wstring aesKey = DH::key2hex(dh->getSessionKey());
								EndDialog(hDlg, reinterpret_cast<INT_PTR>(_wcsdup(aesKey.c_str()))); 
								delete reinterpret_cast<DH*>(GetProp(hDlg, L"wtwCrypto/dh"));
								SetProp(hDlg, L"wtwCrypto/dh", NULL);

								return TRUE;
							}
							return TRUE;
						}
					case IDCANCEL:
						{
							if(GetProp(hDlg, L"wtwCrypto/dh") != NULL) {
								delete reinterpret_cast<DH*>(GetProp(hDlg, L"wtwCrypto/dh"));
								SetProp(hDlg, L"wtwCrypto/dh", NULL);
							}
							EndDialog(hDlg, NULL); 
							return TRUE;
						}
					default: return FALSE;
				} 
			default: return FALSE;
		}
	}
}
