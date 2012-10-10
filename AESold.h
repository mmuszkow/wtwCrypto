#pragma once

#include "stdinc.h"

namespace wtwCrypto {


	class MsgInfo {
	public:
		char	sig[4]; // "MUH"
		DWORD	flags;

		MsgInfo() {
			strcpy_s(sig, 4, "MUH");
			flags = 0;
		}
	};

	struct AesKey {
        BLOBHEADER Header;
        DWORD	dwKeyLength;
        BYTE	cbKey[32];

        AesKey() {
            Header.bType = PLAINTEXTKEYBLOB;
            Header.bVersion = CUR_BLOB_VERSION;			
            Header.reserved = 0;
			Header.aiKeyAlg = CALG_AES_256;
            dwKeyLength = 32;
        }
    };

	class AES {
		AesKey		key;
		HCRYPTPROV	hProv;
		HCRYPTKEY	hKey;

		static const wchar_t* errorToString(DWORD err) {
			switch(err)
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
	public:
		AES();
		~AES();

		void recreateKey();

		wchar_t* encrypt(const wchar_t* msg) const;
		wchar_t* decrypt(const wchar_t* msg) const;
	};
};
