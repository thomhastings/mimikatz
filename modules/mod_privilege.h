#pragma once
#include "globdefs.h"

class mod_privilege
{
private:
	static bool getName(PLUID idPrivilege, wstring * privilegeName);
	static bool getValue(wstring * privilegeName, PLUID idPrivilege);

public:
	static bool get(vector<pair<wstring, DWORD>> *maPrivilegesvector, HANDLE handleProcess = INVALID_HANDLE_VALUE);
	static bool set(vector<pair<wstring, DWORD>> *maPrivilegesvector, HANDLE handleProcess = INVALID_HANDLE_VALUE);
};
