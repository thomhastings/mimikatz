/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by-nc-sa/3.0/fr/
*/
#include "generic_patch.h"

int generic_patch(wstring title, wstring command, wstring origKey, wstring kiwiKey)
{
	bool succes = false;
	PROCESS_INFORMATION * mesInfos = new PROCESS_INFORMATION();
	if(mod_process::start(&command, mesInfos, true))
	{
		wcout <<
			L"Process Handle : " << mesInfos->hProcess << L'\t' << L"PID : " << mesInfos->dwProcessId << endl <<
			L"Thread  Handle : " << mesInfos->hThread << L'\t' << L"TID : " << mesInfos->dwThreadId << endl <<
			endl;

		PEB * monPeb = new PEB();
		if(mod_process::getPeb(monPeb, mesInfos->hProcess))
		{
			wcout << L"Image Base Address : " << monPeb->ImageBaseAddress << endl;
			PBYTE patternAddr = NULL;
			SIZE_T taillePattern = (origKey.size() + 1) * sizeof(wchar_t);

			// Ici NULL est "toléré", pas de moyen de connaitre la taille en mode USER :( (enfin pour le moment)
			if(mod_memory::searchMemory(reinterpret_cast<PBYTE>(monPeb->ImageBaseAddress), NULL, reinterpret_cast<PBYTE>(const_cast<wchar_t *>(origKey.c_str())), &patternAddr, taillePattern, true, mesInfos->hProcess))
			{
				wcout << L"Pattern Address    : " << patternAddr << endl << endl;
				DWORD OldProtect, OldProtect2;
				if(VirtualProtectEx(mesInfos->hProcess, patternAddr, taillePattern, PAGE_EXECUTE_READWRITE, &OldProtect))
				{
					if(mod_memory::writeMemory(patternAddr, kiwiKey.c_str(), taillePattern, mesInfos->hProcess))
					{
						if(VirtualProtectEx(mesInfos->hProcess, patternAddr, taillePattern, OldProtect, &OldProtect2) != 0)
						{
							wcout << L"Process Ok, Memory Ok, resuming process :)" << endl << endl;
							
							if(!(succes = (ResumeThread(mesInfos->hThread) != -1)))
								wcout << L"ResumeThread ";
						}
						else wcout << L"VirtualProtectEx ";
					}
					else wcout << L"mod_memory::writeMemory ";
				}
				else wcout << L"VirtualProtectEx ";
			}
			else wcout << L"mod_memory::searchMemory ";
		}
		else wcout << L"mod_process::getPeb "; 

		delete monPeb;

		CloseHandle(mesInfos->hThread);
		CloseHandle(mesInfos->hProcess);
	}
	else wcout << L"mod_process::start " ;

	if(!succes)
		wcout << mod_system::getWinError() << endl;

	delete mesInfos;
	return ERROR_SUCCESS;
}