#pragma once
#include "globdefs.h"
#include "mod_secacl.h"
#include <tlhelp32.h>

class mod_thread
{
public:
	static bool getList(vector<THREADENTRY32> * monVecteurThreads, DWORD * processId = NULL);
	
	static bool suspend(DWORD & threadId);
	static bool resume(DWORD & threadId);
	static bool stop(DWORD & threadId, DWORD exitCode = 0);
	static bool quit(DWORD & threadId);
};
