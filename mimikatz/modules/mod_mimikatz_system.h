#pragma once
#include "globdefs.h"
#include "mod_system.h"
#include <iostream>

class mod_mimikatz_system
{
public:
	static vector<KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND> getMimiKatzCommands();
	static bool user(vector<wstring> * arguments);
	static bool computer(vector<wstring> * arguments);
};
