/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by-nc-sa/3.0/fr/
*/
#pragma once
#include "globdefs.h"
#include <sstream>
#include <iomanip>

using namespace std;

class mod_text
{
public:
	static wstring stringOfHex(const BYTE monTab[], DWORD maTaille, DWORD longueur = 0);
	static wstring stringOrHex(const BYTE monTab[], DWORD maTaille, DWORD longueur = 32);
	static void wstringHexToByte(wstring &maChaine, BYTE monTab[]);
};
