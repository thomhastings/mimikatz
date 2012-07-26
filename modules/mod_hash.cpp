/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by-nc-sa/3.0/fr/
*/
#include "mod_hash.h"

PSYSTEM_FUNCTION_006 mod_hash::SystemFunction006 = reinterpret_cast<PSYSTEM_FUNCTION_006>(GetProcAddress(GetModuleHandle(L"advapi32"), "SystemFunction006"));
PSYSTEM_FUNCTION_007 mod_hash::SystemFunction007 = reinterpret_cast<PSYSTEM_FUNCTION_007>(GetProcAddress(GetModuleHandle(L"advapi32"), "SystemFunction007"));
PRTL_UPCASE_UNICODE_STRING_TO_OEM_STRING mod_hash::RtlUpcaseUnicodeStringToOemString = reinterpret_cast<PRTL_UPCASE_UNICODE_STRING_TO_OEM_STRING>(GetProcAddress(GetModuleHandle(L"ntdll"), "RtlUpcaseUnicodeStringToOemString"));
PRTL_INIT_UNICODESTRING mod_hash::RtlInitUnicodeString = reinterpret_cast<PRTL_INIT_UNICODESTRING>(GetProcAddress(GetModuleHandle(L"ntdll"), "RtlInitUnicodeString"));
PRTL_FREE_OEM_STRING mod_hash::RtlFreeOemString = reinterpret_cast<PRTL_FREE_OEM_STRING>(GetProcAddress(GetModuleHandle(L"ntdll"), "RtlFreeOemString"));

bool mod_hash::lm(wstring * chaine, wstring * hash)
{
	bool status = false;
	UNICODE_STRING maChaine;
	OEM_STRING maDestination;
	BYTE monTab[16];

	RtlInitUnicodeString(&maChaine, chaine->c_str());
	if(NT_SUCCESS(RtlUpcaseUnicodeStringToOemString(&maDestination, &maChaine, TRUE)))
	{
		if(status = NT_SUCCESS(SystemFunction006(maDestination.Buffer, monTab)))
			hash->assign(mod_text::stringOfHex(monTab, sizeof(monTab)));

		RtlFreeOemString(&maDestination);
	}
	return status;
}

bool mod_hash::ntlm(wstring * chaine, wstring * hash)
{
	bool status = false;
	UNICODE_STRING maChaine;
	BYTE monTab[16];
	
	RtlInitUnicodeString(&maChaine, chaine->c_str());
	if(status = NT_SUCCESS(SystemFunction007(&maChaine, monTab)))
		hash->assign(mod_text::stringOfHex(monTab, sizeof(monTab)));
	return status;
}