/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by-nc-sa/3.0/fr/
*/
#include "mod_text.h"

wstring mod_text::stringOfHex(BYTE monTab[], DWORD maTaille, DWORD longueur)
{
	wostringstream monStream;
	for(DWORD j = 0; j < maTaille; j++)
	{
		monStream << setw(2) << setfill(wchar_t('0')) << hex << monTab[j];
		if(longueur != 0)
		{
			monStream << L' ';
			if ((j + 1) % longueur == 0)
				monStream << endl;
		}
	}
	return monStream.str();
}

wstring mod_text::stringOrHex(BYTE monTab[], DWORD maTaille, DWORD longueur)
{
	wstring result(L"<NULL>");
	if(monTab && maTaille > 0)
	{
		if(IsTextUnicode(monTab, maTaille, NULL))
		{
			result.assign(reinterpret_cast<wchar_t *>(monTab), maTaille / sizeof(wchar_t));
		}
		else
		{
			result.assign(L"\n");
			result.append(stringOfHex(monTab, maTaille, longueur));
		}
	}
	return result;
}


void mod_text::wstringHexToByte(wstring &maChaine, BYTE monTab[])
{
	wstringstream z;
	unsigned int temp;
	for(size_t i = 0; i < maChaine.size() / 2; i++)
	{
		z.clear();
		z << maChaine.substr(i * 2, 2); z >> hex >> temp;
		monTab[i] = temp;
	}
}
