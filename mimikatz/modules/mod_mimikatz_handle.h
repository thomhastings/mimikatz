#pragma once
#include "globdefs.h"
#include "mod_system.h"
#include "mod_process.h"
#include "mod_secacl.h"
#include <iostream>

class mod_mimikatz_handle
{
public:
	static vector<KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND> getMimiKatzCommands();

	static bool list(vector<wstring> * arguments);
	static bool processStop(vector<wstring> * arguments);
	static bool tokenImpersonate(vector<wstring> * arguments);
};