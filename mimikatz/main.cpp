/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by-nc-sa/3.0/fr/
*/
#include "globdefs.h"
#include <io.h>
#include <fcntl.h>
#include "mimikatz.h"

int wmain(int argc, wchar_t * argv[])
{
	setlocale(LC_ALL, "French_France.65001");
	_setmode(_fileno(stdin), _O_U8TEXT/*_O_WTEXT/*_O_U16TEXT*/);
	_setmode(_fileno(stdout), _O_U8TEXT/*_O_WTEXT/*_O_U16TEXT*/);
	_setmode(_fileno(stderr), _O_U8TEXT/*_O_WTEXT/*_O_U16TEXT*/);
	
	/*SetConsoleCP(CP_UTF8);
	SetConsoleOutputCP(CP_UTF8);*/
	
	//vector<wstring> * mavectore = new vector<wstring>(argv, argv + argc);
	mimikatz * myMimiKatz = new mimikatz(/*mavectore*/);
	delete myMimiKatz;
	//delete mavectore;
	return ERROR_SUCCESS;
}