/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by-nc-sa/3.0/fr/
*/
#pragma once
#include "globdefs.h"
#include <wincrypt.h>
#include <sstream>

class mod_crypto
{
public:
	typedef struct _KIWI_KEY_PROV_INFO {
		std::wstring            pwszContainerName;
		std::wstring            pwszProvName;
		DWORD                   dwProvType;
		DWORD                   dwFlags;
		DWORD                   cProvParam;
		DWORD                   dwKeySpec;
	} KIWI_KEY_PROV_INFO, *PKIWI_KEY_PROV_INFO;


private:
	static BOOL WINAPI enumSysCallback(const void *pvSystemStore, DWORD dwFlags, PCERT_SYSTEM_STORE_INFO pStoreInfo, void *pvReserved, void *pvArg);
public:
	/*
	CERT_SYSTEM_STORE_CURRENT_USER
    CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY
	
	CERT_SYSTEM_STORE_LOCAL_MACHINE
    CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY
    CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE

	CERT_SYSTEM_STORE_CURRENT_SERVICE
    
	CERT_SYSTEM_STORE_USERS
    CERT_SYSTEM_STORE_SERVICES
    */

	static bool getSystemStoreFromString(wstring strSystemStore, DWORD * systemStore);

	static bool getVectorSystemStores(vector<wstring> * maSystemStoresvector, DWORD systemStore = CERT_SYSTEM_STORE_CURRENT_USER);
	static bool getCertNameFromCertCTX(PCCERT_CONTEXT certCTX, wstring * certName);
	static bool getKiwiKeyProvInfo(PCCERT_CONTEXT certCTX, KIWI_KEY_PROV_INFO * keyProvInfo);
	
	static bool	PrivateKeyBlobToPVK(BYTE * monExport, DWORD tailleExport, wstring pvkFile);
	static bool CertCTXtoPFX(PCCERT_CONTEXT certCTX, wstring pfxFile, wstring password);
	static bool CertCTXtoDER(PCCERT_CONTEXT certCTX, wstring DERFile);
};
