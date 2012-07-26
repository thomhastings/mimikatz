/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by-nc-sa/3.0/fr/
*/
#pragma once
#include "globdefs.h"
#include "mod_text.h"

class mod_hash
{
private:
	static PSYSTEM_FUNCTION_006 SystemFunction006;
	static PSYSTEM_FUNCTION_007 SystemFunction007;
	static PRTL_UPCASE_UNICODE_STRING_TO_OEM_STRING RtlUpcaseUnicodeStringToOemString;
	static PRTL_INIT_UNICODESTRING RtlInitUnicodeString;
	static PRTL_FREE_OEM_STRING RtlFreeOemString;

public:
	typedef enum _KIWI_HASH_TYPE
	{
		LM,
		NTLM
	} KIWI_HASH_TYPE;

	static bool lm(wstring * chaine, wstring * hash);
	static bool ntlm(wstring * chaine, wstring * hash);
};
