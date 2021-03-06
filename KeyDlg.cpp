#include "stdinc.h"
#include "DH.h"
#include "AES.h"
#include "../common/StringUtils.h"

#define SystemFunction036 NTAPI SystemFunction036
#include <NTSecAPI.h> // for RtlGenRandom
#undef SystemFunction036

namespace wtwCrypto {
    INT_PTR CALLBACK keyDlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam) {
        switch(msg) {
            case WM_INITDIALOG: return TRUE;
            case WM_COMMAND: 
                switch (LOWORD(wParam)) {
                    case IDC_DH_GEN: {
                            DH* dh;
                            if(GetProp(hDlg, L"wtwCrypto/dh") != NULL) {
                                dh = reinterpret_cast<DH*>(GetProp(hDlg, L"wtwCrypto/dh"));
                                dh->recreateKeys();
                            }
                            else {
                                dh = new DH();
                                SetProp(hDlg, L"wtwCrypto/dh", dh);
                            }

                            std::wstring pubKey = key2hex(dh->getPublicKey(), DH::KEYSIZEBYTES);
                            SetDlgItemText(hDlg, IDC_MYPUBKEY, pubKey.c_str());
                            if(pubKey != L"ERROR") {
                                EnableWindow(GetDlgItem(hDlg, IDC_DH_IMPORT), TRUE);
                                EnableWindow(GetDlgItem(hDlg, IDC_HISPUBKEY), TRUE);
                            }
                            return TRUE;
                        }
                    case IDC_DH_IMPORT: {
                            DH* dh;
                            if(GetProp(hDlg, L"wtwCrypto/dh") != NULL) {
                                dh = reinterpret_cast<DH*>(GetProp(hDlg, L"wtwCrypto/dh"));
                                std::wstring hisKey = strUtils::getDlgItemTextWideStr(hDlg, IDC_HISPUBKEY);
                                BYTE dhKey[DH::KEYSIZEBYTES];

                                if(!hex2key(hisKey, dhKey, DH::KEYSIZEBYTES)) {
                                    MessageBox(hDlg, L"Zły format klucza (za krótki/długi lub niedozwolone znaki)", L"Import klucza", MB_OK|MB_ICONERROR);
                                    return TRUE;
                                }
                                dh->importKey(dhKey);

                                std::wstring aesKey = key2hex(dh->getSessionKey(), AES::KEYSIZEBYTES);
                                EndDialog(hDlg, reinterpret_cast<INT_PTR>(_wcsdup(aesKey.c_str()))); 
                                delete reinterpret_cast<DH*>(GetProp(hDlg, L"wtwCrypto/dh"));
                                SetProp(hDlg, L"wtwCrypto/dh", NULL);

                                return TRUE;
                            }
                            return TRUE;
                        }
                    case IDC_AES_GEN: {
                            BYTE aesKey[AES::KEYSIZEBYTES];
                            if(RtlGenRandom(aesKey, AES::KEYSIZEBYTES) != TRUE)
                                return TRUE;
                            SetDlgItemText(hDlg, IDC_AES_KEY, key2hex(aesKey, AES::KEYSIZEBYTES).c_str());
                            return TRUE;
                        }
                    case IDC_AES_IMPORT: {
                            std::wstring aesKey = strUtils::getDlgItemTextWideStr(hDlg, IDC_AES_KEY);
                            size_t len = aesKey.size();
                            if(len != (AES::KEYSIZEBYTES<<1)) {
                                MessageBox(hDlg, L"Zły format klucza (za krótki/długi)", L"Import klucza", MB_OK|MB_ICONERROR);
                                return TRUE;
                            }
                            const wchar_t* aesKeyS = aesKey.c_str();
                            for(size_t i=0; i<len; i++)
                                if(!iswxdigit(aesKeyS[i])) {
                                    MessageBox(hDlg, L"Zły format klucza (niedozwolone znaki)", L"Import klucza", MB_OK|MB_ICONERROR);
                                    return TRUE;
                                }

                            if(GetProp(hDlg, L"wtwCrypto/dh") != NULL) {
                                delete reinterpret_cast<DH*>(GetProp(hDlg, L"wtwCrypto/dh"));
                                SetProp(hDlg, L"wtwCrypto/dh", NULL);
                            }
                            EndDialog(hDlg, reinterpret_cast<INT_PTR>(_wcsdup(aesKeyS)));
                            return TRUE;
                        }
                    case IDCANCEL: {
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
