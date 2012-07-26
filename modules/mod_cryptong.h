#pragma once
#include "globdefs.h"
#include <bcrypt.h>
#include <sstream>
/*
typedef __checkReturn SECURITY_STATUS	(WINAPI * ptrNCryptOpenStorageProvider)		(__out   NCRYPT_PROV_HANDLE *phProvider, __in_opt LPCWSTR pszProviderName, __in    DWORD   dwFlags);
typedef __checkReturn SECURITY_STATUS	(WINAPI * ptrNCryptEnumKeys)				(__in    NCRYPT_PROV_HANDLE hProvider, __in_opt LPCWSTR pszScope, __deref_out NCryptKeyName **ppKeyName, __inout PVOID * ppEnumState, __in    DWORD   dwFlags);
typedef	SECURITY_STATUS					(WINAPI * ptrNCryptOpenKey)					(__in   NCRYPT_PROV_HANDLE hProvider, __out  NCRYPT_KEY_HANDLE *phKey, __in   LPCWSTR pszKeyName, __in   DWORD dwLegacyKeySpec, __in   DWORD dwFlags);
typedef SECURITY_STATUS					(WINAPI * ptrNCryptExportKey)				(__in       NCRYPT_KEY_HANDLE hKey, __in_opt   NCRYPT_KEY_HANDLE hExportKey, __in       LPCWSTR pszBlobType, __in_opt   NCryptBufferDesc *pParameterList, __out_opt  PBYTE pbOutput, __in       DWORD cbOutput, __out      DWORD *pcbResult, __in       DWORD dwFlags);
typedef __checkReturn SECURITY_STATUS	(WINAPI * ptrNCryptGetProperty)				(__in    NCRYPT_HANDLE hObject, __in    LPCWSTR pszProperty, __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput, __in    DWORD   cbOutput, __out   DWORD * pcbResult, __in    DWORD   dwFlags);

typedef SECURITY_STATUS					(WINAPI * ptrNCryptFreeBuffer)				(__deref PVOID   pvInput);
typedef SECURITY_STATUS					(WINAPI * ptrNCryptFreeObject)				(__in    NCRYPT_HANDLE hObject);

typedef __checkReturn NTSTATUS			(WINAPI * ptrBCryptEnumRegisteredProviders)	(__inout ULONG* pcbBuffer, __deref_opt_inout_bcount_part_opt(*pcbBuffer, *pcbBuffer) PCRYPT_PROVIDERS *ppBuffer);
typedef VOID							(WINAPI * ptrBCryptFreeBuffer)				(__in PVOID   pvBuffer);
*/

class mod_cryptong /* Ref : http://msdn.microsoft.com/en-us/library/aa376210.aspx */
{
public:
	static bool getVectorProviders(vector<wstring> * monVectorProviders);
	static bool getVectorContainers(vector<wstring> * monVectorContainers, bool isMachine = false);
	static bool getHKeyFromName(wstring keyName, NCRYPT_KEY_HANDLE * keyHandle, bool isMachine = false);
	static bool getKeySize(HCRYPTPROV_OR_NCRYPT_KEY_HANDLE * provOrCle, DWORD * keySize);
	static bool isKeyExportable(HCRYPTPROV_OR_NCRYPT_KEY_HANDLE * provOrCle, bool * isExportable);
	static bool getPrivateKey(NCRYPT_KEY_HANDLE maCle, PBYTE * monExport, DWORD * tailleExport, LPCWSTR pszBlobType = LEGACY_RSAPRIVATE_BLOB);
	static bool NCryptFreeObject(NCRYPT_HANDLE hObject);

	static bool isNcrypt;
	static bool justInitCNG(LPCWSTR pszProviderName = NULL);
};
