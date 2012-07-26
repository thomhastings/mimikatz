/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by-nc-sa/3.0/fr/
*/
#include "../generic_patch.h"

int wmain(int argc, wchar_t * argv[])
{
	return generic_patch(L"Command Prompt", L"cmd", L"DisableCMD", L"KiwiAndCMD");
}
