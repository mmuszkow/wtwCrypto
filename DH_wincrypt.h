#pragma once

#include "stdinc.h"

typedef unsigned int NN_DIGIT;
extern "C" void NN_ModExp (NN_DIGIT *a, NN_DIGIT *b, NN_DIGIT *c, unsigned int cDigits, NN_DIGIT *d, unsigned int dDigits);

namespace wtwCrypto {

	/*class BigInt {
		BYTE*	digits;
		size_t	len;
	public:
		BigInt() {
			digits = NULL;
			len = 0;
		}

		BigInt(const BigInt& int2) {
			len = int2.len;
			digits = new BYTE[len];
			memcpy(digits, int2.digits, len);
		}

		BigInt& operator=(const BigInt& int2) {
			if(this == &int2) return *this;

			if(digits) delete [] digits;

			len = int2.len;
			digits = new BYTE[len];
			memcpy(digits, int2.digits, len);
			return *this;
		}

		BigInt(size_t len) {
			digits = new BYTE[len];
			this->len = len;
		}

		~BigInt() {
			delete [] digits;
		}

		BigInt& operator*=(const BigInt& num2) {


			return *this;
		}

		BigInt& operator%=(const BigInt& modulus) {
			return *this;
		}

		static BigInt powerMod(const BigInt& base, const BigInt& exponent, const BigInt& modulus) {
			BigInt res(modulus.len);
			BigInt num(base);
			memset(res.digits, 0, res.len);
			res.digits[0] = 1; // set res to 1

			size_t i, j;
			int bit;
			for(i=0; i<exponent.len; i++) { // exponent bytes loop
				for(j=0; i<8; j++) { // exponent bits loop
					bit = (exponent.digits[i]>>j) & 1;
					if(bit & 1)	{ // if odd
						res *= num;
						res %= modulus;
					}
					num *= num;
					num %= modulus;
				}
			}
			return res;
		}
	};*/

	// Prime in little-endian format.
	static const BYTE g_rgbPrime[] = {
		0x91, 0x02, 0xc8, 0x31, 0xee, 0x36, 0x07, 0xec, 
		0xc2, 0x24, 0x37, 0xf8, 0xfb, 0x3d, 0x69, 0x49, 
		0xac, 0x7a, 0xab, 0x32, 0xac, 0xad, 0xe9, 0xc2, 
		0xaf, 0x0e, 0x21, 0xb7, 0xc5, 0x2f, 0x76, 0xd0, 
		0xe5, 0x82, 0x78, 0x0d, 0x4f, 0x32, 0xb8, 0xcb,
		0xf7, 0x0c, 0x8d, 0xfb, 0x3a, 0xd8, 0xc0, 0xea, 
		0xcb, 0x69, 0x68, 0xb0, 0x9b, 0x75, 0x25, 0x3d,
		0xaa, 0x76, 0x22, 0x49, 0x94, 0xa4, 0xf2, 0x8d 
	};

	// Generator in little-endian format.
	static BYTE g_rgbGenerator[] = {
		0x02, 0x88, 0xd7, 0xe6, 0x53, 0xaf, 0x72, 0xc5,
		0x8c, 0x08, 0x4b, 0x46, 0x6f, 0x9f, 0x2e, 0xc4,
		0x9c, 0x5c, 0x92, 0x21, 0x95, 0xb7, 0xe5, 0x58, 
		0xbf, 0xba, 0x24, 0xfa, 0xe5, 0x9d, 0xcb, 0x71, 
		0x2e, 0x2c, 0xce, 0x99, 0xf3, 0x10, 0xff, 0x3b,
		0xcb, 0xef, 0x6c, 0x95, 0x22, 0x55, 0x9d, 0x29,
		0x00, 0xb5, 0x4c, 0x5b, 0xa5, 0x63, 0x31, 0x41,
		0x13, 0x0a, 0xea, 0x39, 0x78, 0x02, 0x6d, 0x62
	};

	// Diffie-Hellman
	class DH {

		// The key size, in bits (Can be 384 bits to 512 bits in 8 bit increments)
		static const int DHKEYSIZEBITS = 512;
		// The key size, in bytes
		static const int DHKEYSIZEBYTES = DHKEYSIZEBITS >> 3;

	public:
#pragma pack(push, 1)
		// struct for holding DH keys
		struct PublicKeyDH {
			PUBLICKEYSTRUC  publickeystruc;
			DHPUBKEY        dhpubkey;
			BYTE            y[DHKEYSIZEBYTES]; // Where y = (G^X) mod P
		};

		struct PrivateKeyDH {
			PUBLICKEYSTRUC  publickeystruc;
			DHPUBKEY        dhpubkey;
			BYTE            prime[DHKEYSIZEBYTES];
			BYTE            generator[DHKEYSIZEBYTES];
			BYTE            secret[DHKEYSIZEBYTES];
		};
#pragma pack(pop)

	private:
		HCRYPTPROV		hProv;
		HCRYPTKEY		hPrivateKey;
		DATA_BLOB		P, G; // prime, generator

		PublicKeyDH		publicKey;
		PrivateKeyDH	privateKey;
		bool			keysGenerated;

		BYTE			sessionKey[DHKEYSIZEBYTES];
		bool			sessionKeyValid;

		void resetKeys();
	public:
		inline const BYTE* getPublicKey() {
			if(keysGenerated)	return reinterpret_cast<const BYTE*>(&publicKey);
			return NULL;
		}

		inline const BYTE* getSessionKey() {
			if(sessionKeyValid)	return reinterpret_cast<const BYTE*>(&sessionKey);
			return NULL;
		}

		DH();
		~DH() {
			if(hProv) CryptReleaseContext(hProv, 0);
		}

		void importKey(const BYTE* importedKeyBlob);
	};
};
