#pragma once
#include "globdefs.h"
#include "mod_system.h"
#include "mod_service.h"
#include <iostream>

class mod_mimikatz_service
{
private:
public:
	static vector<KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND> getMimiKatzCommands();
		
	static bool list(vector<wstring> * arguments);
	
	static bool start(vector<wstring> * arguments);
	static bool suspend(vector<wstring> * arguments);
	static bool resume(vector<wstring> * arguments);
	static bool stop(vector<wstring> * arguments);

	static bool query(vector<wstring> * arguments);
	
	static bool add(vector<wstring> * arguments);
	static bool remove(vector<wstring> * arguments);
	static bool control(vector<wstring> * arguments);

	static bool mimikatz(vector<wstring> * arguments);
};
