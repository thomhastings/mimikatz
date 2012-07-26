#include "mod_crypto.h"

bool mod_crypto::getSystemStoreFromString(wstring strSystemStore, DWORD * systemStore)
{
	vector<pair<wstring, DWORD>> mesEmplacements;
	mesEmplacements.push_back(make_pair(L"CERT_SYSTEM_STORE_CURRENT_USER", CERT_SYSTEM_STORE_CURRENT_USER));
	mesEmplacements.push_back(make_pair(L"CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY", CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY));
	
	mesEmplacements.push_back(make_pair(L"CERT_SYSTEM_STORE_LOCAL_MACHINE", CERT_SYSTEM_STORE_LOCAL_MACHINE));
	mesEmplacements.push_back(make_pair(L"CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY", CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY));
	mesEmplacements.push_back(make_pair(L"CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE", CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE));
	
	mesEmplacements.push_back(make_pair(L"CERT_SYSTEM_STORE_CURRENT_SERVICE", CERT_SYSTEM_STORE_CURRENT_SERVICE));

	mesEmplacements.push_back(make_pair(L"CERT_SYSTEM_STORE_USERS", CERT_SYSTEM_STORE_USERS));
	mesEmplacements.push_back(make_pair(L"CERT_SYSTEM_STORE_SERVICES", CERT_SYSTEM_STORE_SERVICES));

	for(vector<pair<wstring, DWORD>>::iterator monEmplacement = mesEmplacements.begin(); monEmplacement != mesEmplacements.end(); monEmplacement++)
	{
		if(monEmplacement->first.compare(strSystemStore) == 0)
		{
			*systemStore = monEmplacement->second;
			return true;
		}
	}

	return false;
}


BOOL WINAPI mod_crypto::enumSysCallback(const void *pvSystemStore, DWORD dwFlags, PCERT_SYSTEM_STORE_INFO pStoreInfo, void *pvReserved, void *pvArg)
{
	reinterpret_cast<vector<wstring> *>(pvArg)->push_back(reinterpret_cast<const wchar_t *>(pvSystemStore));
	return TRUE;
}

bool mod_crypto::getVectorSystemStores(vector<wstring> * maSystemStoresvector, DWORD systemStore)
{
	return (CertEnumSystemStore(systemStore, NULL, maSystemStoresvector, enumSysCallback) != 0);
}

bool mod_crypto::getCertNameFromCertCTX(PCCERT_CONTEXT certCTX, wstring * certName)
{
	bool reussite = false;
	wchar_t * monBuffer = NULL;
	DWORD tailleRequise = CertGetNameString(certCTX, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, NULL, 0);
	if(tailleRequise > 1)
	{
		monBuffer = new wchar_t[tailleRequise];
		reussite = CertGetNameString(certCTX, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, monBuffer, tailleRequise) > 1;
		certName->assign(monBuffer);
		delete[] monBuffer;
	}
	return reussite;
}

bool mod_crypto::getKiwiKeyProvInfo(PCCERT_CONTEXT certCTX, KIWI_KEY_PROV_INFO * keyProvInfo)
{
	bool reussite = false;
	DWORD taille = 0;
	if(CertGetCertificateContextProperty(certCTX, CERT_KEY_PROV_INFO_PROP_ID, NULL, &taille))
	{
		BYTE * monBuffer = new BYTE[taille];
		if(reussite = (CertGetCertificateContextProperty(certCTX, CERT_KEY_PROV_INFO_PROP_ID, monBuffer, &taille) != 0))
		{
			CRYPT_KEY_PROV_INFO * mesInfos = reinterpret_cast<CRYPT_KEY_PROV_INFO *>(monBuffer);
			
			if(mesInfos->pwszProvName)
				keyProvInfo->pwszProvName.assign(mesInfos->pwszProvName);
			else
				keyProvInfo->pwszProvName.assign(L"(null)");
			
			if(mesInfos->pwszContainerName)
				keyProvInfo->pwszContainerName.assign(mesInfos->pwszContainerName);
			else
				keyProvInfo->pwszContainerName.assign(L"(null)");
			
			keyProvInfo->cProvParam = mesInfos->cProvParam;
			keyProvInfo->dwFlags = mesInfos->dwFlags;
			keyProvInfo->dwKeySpec = mesInfos->dwKeySpec;
			keyProvInfo->dwProvType = mesInfos->dwProvType;
		}
		delete[] monBuffer;
	}
	return reussite;
}



bool mod_crypto::CertCTXtoPFX(PCCERT_CONTEXT certCTX, wstring pfxFile, wstring password)
{
	bool retour = false;

	HCERTSTORE hTempStore = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, NULL, CERT_STORE_CREATE_NEW_FLAG, NULL); 
	PCCERT_CONTEXT  pCertContextCopy = NULL;

	if(CertAddCertificateContextToStore(hTempStore, certCTX, CERT_STORE_ADD_NEW, &pCertContextCopy))
	{
		CRYPT_DATA_BLOB bDataBlob = {0, NULL};
		if(PFXExportCertStoreEx(hTempStore, &bDataBlob, password.c_str(), NULL, EXPORT_PRIVATE_KEYS | REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY))
		{
			bDataBlob.pbData = new BYTE[bDataBlob.cbData]; 
			if(PFXExportCertStoreEx(hTempStore, &bDataBlob, password.c_str(), NULL, EXPORT_PRIVATE_KEYS | REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY))
			{
				HANDLE hFile = CreateFile(pfxFile.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
				if(hFile && hFile != INVALID_HANDLE_VALUE)
				{
					DWORD dwBytesWritten;
					if(WriteFile(hFile, bDataBlob.pbData, bDataBlob.cbData, &dwBytesWritten, NULL) && bDataBlob.cbData == dwBytesWritten)
					{
						retour = FlushFileBuffers(hFile) != 0;
					}
					CloseHandle(hFile);
				}
			}
			delete[] bDataBlob.pbData;
		}
		CertFreeCertificateContext(pCertContextCopy);
	}
	CertCloseStore(hTempStore, CERT_CLOSE_STORE_FORCE_FLAG);

	return retour;
}

bool mod_crypto::CertCTXtoDER(PCCERT_CONTEXT certCTX, wstring DERFile)
{
	bool retour = false;

	HANDLE hFile = CreateFile(DERFile.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
	if(hFile && hFile != INVALID_HANDLE_VALUE)
	{
		DWORD dwBytesWritten;
		if(WriteFile(hFile, certCTX->pbCertEncoded, certCTX->cbCertEncoded, &dwBytesWritten, NULL) && certCTX->cbCertEncoded == dwBytesWritten)
		{
			retour = FlushFileBuffers(hFile) != 0;
		}
		CloseHandle(hFile);
	}
	return retour;
}


bool mod_crypto::PrivateKeyBlobToPVK(BYTE * monExport, DWORD tailleExport, wstring pvkFile)
{
	bool retour = false;

	BYTE monHead[] = {
		0x1e, 0xf1, 0xb5, 0xb0,				// magic
		0x00, 0x00, 0x00, 0x00,				// reserved
		AT_KEYEXCHANGE, 0x00, 0x00, 0x00,	// keytype
		0x00, 0x00, 0x00, 0x00,				// encrypted
		0x00, 0x00, 0x00, 0x00				// saltlen
	};

	HANDLE hFile = CreateFile(pvkFile.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
	if(hFile && hFile != INVALID_HANDLE_VALUE)
	{
		DWORD dwBytesWritten;
		if(WriteFile(hFile, monHead, sizeof(monHead), &dwBytesWritten, NULL) && sizeof(monHead) == dwBytesWritten)
		{
			if(WriteFile(hFile, &tailleExport, sizeof(tailleExport), &dwBytesWritten, NULL) && sizeof(tailleExport) == dwBytesWritten)
			{
				if(WriteFile(hFile, monExport, tailleExport, &dwBytesWritten, NULL) && tailleExport == dwBytesWritten)
				{
					retour = FlushFileBuffers(hFile) != 0;
				}
			}
		}
		CloseHandle(hFile);
	}

/*
	HANDLE hFile = CreateFile(pvkFile.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
	DWORD dwBytesWritten;
	WriteFile(hFile, monHead, sizeof(monHead), &dwBytesWritten, NULL);
	WriteFile(hFile, &tailleExport, sizeof(tailleExport), &dwBytesWritten, NULL);
	WriteFile(hFile, monExport, tailleExport, &dwBytesWritten, NULL);
	CloseHandle(hFile);
*/
	return retour;
}