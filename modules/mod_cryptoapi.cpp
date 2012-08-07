/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by-nc-sa/3.0/fr/
*/
#include "mod_cryptoapi.h"
HMODULE mod_cryptoapi::hRsaEng = NULL;

bool mod_cryptoapi::loadRsaEnh()
{
	if(!hRsaEng)
		hRsaEng = LoadLibrary(L"rsaenh");
	return (hRsaEng != NULL);
}

bool mod_cryptoapi::unloadRsaEnh()
{
	if(hRsaEng)
		FreeLibrary(hRsaEng);
	return true;
}

bool mod_cryptoapi::getVectorProviders(vector<wstring> * monVectorProviders)
{
	DWORD index = 0;
	DWORD provType;
	DWORD tailleRequise;

	while(CryptEnumProviders(index, NULL, 0, &provType, NULL, &tailleRequise))
	{
		wchar_t * monProvider = new wchar_t[tailleRequise];
		if(CryptEnumProviders(index, NULL, 0, &provType, monProvider, &tailleRequise))
		{
			monVectorProviders->push_back(monProvider);
		}
		delete[] monProvider;
		index++;
	}
	return (GetLastError() == ERROR_NO_MORE_ITEMS);
}

bool mod_cryptoapi::getVectorContainers(vector<wstring> * monVectorContainers, bool isMachine)
{
	bool reussite = false;

	HCRYPTPROV hCryptProv = NULL;
	if(CryptAcquireContext(&hCryptProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT | (isMachine ? CRYPT_MACHINE_KEYSET : NULL)))
	{
		DWORD tailleRequise = 0;
		char * containerName = NULL;
		DWORD CRYPT_first_next = CRYPT_FIRST;
		bool success = false;

		success = (CryptGetProvParam(hCryptProv, PP_ENUMCONTAINERS, NULL, &tailleRequise, CRYPT_first_next) != 0);
		while(success)
		{
			containerName = new char[tailleRequise];
			if(success = (CryptGetProvParam(hCryptProv, PP_ENUMCONTAINERS, reinterpret_cast<BYTE *>(containerName), &tailleRequise, CRYPT_first_next) != 0))
			{
				wstringstream resultat;
				resultat << containerName;
				monVectorContainers->push_back(resultat.str());
			}
			delete[] containerName;
			CRYPT_first_next = CRYPT_NEXT;
		}
		reussite = (GetLastError() == ERROR_NO_MORE_ITEMS);
		CryptReleaseContext(hCryptProv, 0);
	}

	return reussite;
}

bool mod_cryptoapi::getPrivateKey(HCRYPTKEY maCle, PBYTE * monExport, DWORD * tailleExport, DWORD dwBlobType)
{
	bool reussite = false;

	if(CryptExportKey(maCle, NULL, dwBlobType, NULL, NULL, tailleExport))
	{
		*monExport = new BYTE[*tailleExport];
		if(!(reussite = (CryptExportKey(maCle, NULL, dwBlobType, NULL, *monExport, tailleExport) != 0)))
			delete[] monExport;

	}
	return reussite;
}