#ifndef _MSC_VER
//#error This code can be only compiled using Visual Studio
#endif

#pragma once

#ifdef _DEBUG
# define CRTDBG_MAP_ALLOC
# include <stdlib.h>
# include <crtdbg.h> 
#endif

#include <string>
#include <vector>
#include <map>
#include <set>

#include <ctime>
#include <windows.h>

#include "resource.h"

#include "plInterface.h"

static const wchar_t MIDL[] = L"CRPT";
static INT_PTR bkBrush = reinterpret_cast<INT_PTR>(GetStockObject(WHITE_BRUSH));

static BYTE char2hex(const wchar_t c) {
    switch(c) {
        case '0': return 0;
        case '1': return 1;
        case '2': return 2;
        case '3': return 3;
        case '4': return 4;
        case '5': return 5;
        case '6': return 6;
        case '7': return 7;
        case '8': return 8;
        case '9': return 9;
        case 'a':
        case 'A': return 10;
        case 'b':
        case 'B': return 11;
        case 'c':
        case 'C': return 12;
        case 'd':
        case 'D': return 13;
        case 'e':
        case 'E': return 14;
        case 'f':
        case 'F': return 15;
        default: return 0;
    }
}

// hex str must have at least 8 chars!
static DWORD str2hex(const wchar_t* str) {
    if(!str || wcslen(str) < 8)
        return 0;

    DWORD ret = 0;
    for(int i=0; i<8; i++) {
        ret <<= 4;
        ret |= char2hex(str[i]);
    }

    return ret;
}

// memory will be alloced for str, free with delete []
static wchar_t* hex2str(const BYTE* arr, size_t len) {
    if(!arr || !len) return NULL;

    wchar_t* res = new wchar_t[(len<<1)+2];
    wchar_t tmp[3];
    for(size_t i=0; i<len; i++) {
        swprintf_s(tmp, 3, L"%.2X", arr[i]);
        res[i<<1] = tmp[0];
        res[(i<<1)+1] = tmp[1];
    }
    res[len<<1] = 0;

    return res;
}

// memory will be alloced for arr, free with delete []
static BYTE* hex2byte(const wchar_t* str, size_t* len) {
    if(!str) {
        *len = 0;
        return NULL;
    }

    size_t strln = wcslen(str);
    if(strln == 0 || strln & 1) { // must be even
        *len = 0;
        return NULL;
    }

    *len = strln>>1;
    BYTE* arr = static_cast<BYTE*>(malloc(*len));
    if(!arr) {
        *len = 0;
        return NULL;
    }

    size_t j = 0;
    for(size_t i=0; i<strln; i+=2) {
        arr[j] = char2hex(str[i])<<4;
        arr[j++] |= char2hex(str[i+1]);
    }
    return arr;
}

static void hexdup(const BYTE* arr, int len) {
    std::wstring str;
    wchar_t tmp[4];
    for(int i=0; i<len; i++) {
        swprintf_s(tmp, 4, L"%.2X", arr[i]);
        str += tmp;
    }
    str += L"\r\n";
    OutputDebugStringW(str.c_str());
}

/*
#include <wincrypt.h>

static const wchar_t* CryptoLastErr() {
    switch(GetLastError())
    {
    default:
        return L"<Unknown>";
    case ERROR_INVALID_HANDLE:
        return L"ERROR_INVALID_HANDLE: One of the parameters specifies an invalid handle."; 
    case ERROR_INVALID_PARAMETER:
        return L"ERROR_INVALID_PARAMETER: One of the parameters contains an invalid value. This is most often an invalid pointer."; 
    case NTE_BAD_ALGID:
        return L"NTE_BAD_ALGID: The hKey session key specifies an algorithm that this CSP does not support."; 
    case NTE_BAD_DATA:
        return L"NTE_BAD_DATA: The data to be encrypted is invalid. For example, when a block cipher is used and the Final flag is FALSE, the value specified by pdwDataLen must be a multiple of the block size."; 
    case NTE_BAD_FLAGS:
        return L"NTE_BAD_FLAGS: The dwFlags parameter is nonzero."; 
    case NTE_BAD_HASH:
        return L"NTE_BAD_HASH: The hHash parameter contains an invalid handle."; 
    case NTE_BAD_HASH_STATE:
        return L"NTE_BAD_HASH_STATE: An attempt was made to add data to a hash object that is already marked \"finished.\""; 
    case NTE_BAD_KEY:
        return L"NTE_BAD_KEY: The hKey parameter does not contain a valid handle to a key. A session key is being exported, and the hExpKey parameter does not specify a public key"; 
    case NTE_NO_KEY:
        return L"NTE_NO_KEY: The hKey parameter does not contain a valid handle to a key. A session key is being exported, and the hExpKey parameter does not specify a public key"; 
    case NTE_BAD_LEN:
        return L"NTE_BAD_LEN: The size of the output buffer is too small to hold the generated ciphertext."; 
    case NTE_BAD_UID:
        return L"NTE_BAD_UID: The CSP context that was specified when the key was created cannot be found."; 
    case NTE_DOUBLE_ENCRYPT:
        return L"NTE_DOUBLE_ENCRYPT: The application attempted to encrypt the same data twice."; 
    case NTE_FAIL:
        return L"NTE_FAIL: The function failed in some unexpected way."; 
    case NTE_NO_MEMORY:
        return L"NTE_NO_MEMORY: The CSP ran out of memory during the operation"; 
    case ERROR_BUSY:
        return L"ERROR_BUSY: Some CSPs set this error if a private key is imported into a container while another thread or process is using this key."; 
    case NTE_BAD_TYPE:
        return L"NTE_BAD_TYPE: The key BLOB type is not supported by this CSP and is possibly invalid."; 
    case NTE_BAD_VER:
        return L"NTE_BAD_VER: The key BLOB's version number does not match the CSP version. This usually indicates that the CSP needs to be upgraded. "; 
    case ERROR_NOT_ENOUGH_MEMORY:
        return L"ERROR_NOT_ENOUGH_MEMORY: The operating system ran out of memory during the operation. ";
    case NTE_BAD_KEYSET:
        return L"NTE_BAD_KEYSET: The key container could not be opened. A common cause of this error is that the key container does not exist. To create a key container, call CryptAcquireContext using the CRYPT_NEWKEYSET flag. This error code can also indicate that access to an existing key container is denied. Access rights to the container can be granted by the key set creator using CryptSetProvParam. ";
    case NTE_BAD_KEYSET_PARAM:
        return L"NTE_BAD_KEYSET_PARAM: The pszContainer or pszProvider parameter is set to an invalid value. ";
    case NTE_BAD_PROV_TYPE:
        return L"NTE_BAD_PROV_TYPE: The value of the dwProvType parameter is out of range. All provider types must be from 1 to 999, inclusive. ";
    case NTE_BAD_SIGNATURE:
        return L"NTE_BAD_SIGNATURE: The provider DLL signature could not be verified. Either the DLL or the digital signature has been tampered with. ";
    case NTE_EXISTS:
        return L"NTE_EXISTS: The dwFlags parameter is CRYPT_NEWKEYSET, but the key container already exists. ";
    case NTE_KEYSET_ENTRY_BAD:
        return L"NTE_KEYSET_ENTRY_BAD: The pszContainer key container was found but is corrupt. ";
    case NTE_KEYSET_NOT_DEF:
        return L"NTE_KEYSET_NOT_DEF: The key container specified by pszContainer does not exist or the requested provider does not exist. ";
    case NTE_PROV_DLL_NOT_FOUND:
        return L"NTE_PROV_DLL_NOT_FOUND: The provider DLL file does not exist or is not on the current path. ";
    case NTE_PROV_TYPE_ENTRY_BAD:
        return L"NTE_PROV_TYPE_ENTRY_BAD: The provider type specified by dwProvType is corrupt. This error can relate to either the user default CSP list or the computer default CSP list. ";
    case NTE_PROV_TYPE_NO_MATCH:
        return L"NTE_PROV_TYPE_NO_MATCH: The provider type specified by dwProvType does not match the provider type found. Note that this error can only occur when pszProvider specifies an actual CSP name. ";
    case NTE_PROV_TYPE_NOT_DEF:
        return L"NTE_PROV_TYPE_NOT_DEF: No entry exists for the provider type specified by dwProvType.";
    case NTE_PROVIDER_DLL_FAIL:
        return L"NTE_PROVIDER_DLL_FAIL: The provider DLL file could not be loaded or failed to initialize.";
    case NTE_SIGNATURE_FILE_BAD:
        return L"NTE_SIGNATURE_FILE_BAD: An error occurred while loading the DLL file image, prior to verifying its signature.";
    case NTE_SILENT_CONTEXT:
        return L"NTE_SILENT_CONTEXT: The provider could not perform the action because the context was acquired as silent.";
    case NTE_BAD_KEY_STATE: 
        return L"NTE_BAD_KEY_STATE:: You do not have permission to export the key. That is, when the hKey key was created, the CRYPT_EXPORTABLE flag was not specified."; 
    case NTE_BAD_PUBLIC_KEY:
        return L"NTE_BAD_PUBLIC_KEY: The key BLOB type specified by dwBlobType is PUBLICKEYBLOB, but hExpKey does not contain a public key handle.";
    }
}
*/

std::wstring key2hex(const BYTE* key, const int len);
bool hex2key(const std::wstring& hex, BYTE* key, const int keyLen);
