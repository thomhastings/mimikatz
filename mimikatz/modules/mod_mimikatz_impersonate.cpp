#include "mod_mimikatz_impersonate.h"

vector<KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND> mod_mimikatz_impersonate::getMimiKatzCommands()
{
	vector<KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND> monVector;
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(revert,	L"revert",	L"RevertToSelf"));
	return monVector;
}
bool mod_mimikatz_impersonate::revert(vector<wstring> * arguments)
{
	wcout << L"RevertToSelf : ";
	if(RevertToSelf())
		wcout << L"ok";
	else
		wcout << L"ko ; " << mod_system::getWinError();
	wcout << endl;

	return true;
}
