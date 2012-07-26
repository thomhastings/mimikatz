#pragma once
#include "globdefs.h"
#include <aclapi.h>
#include <sddl.h>

using namespace std;

class mod_secacl
{
public:
	static bool sidToStrSid(PSID Sid, wstring * strSid);
	static bool nullSdToHandle(PHANDLE monHandle, SE_OBJECT_TYPE monType);
	static bool sidToName(PSID Sid, wstring * strName, wstring * domainName = NULL, wstring * systemName = NULL, SID_NAME_USE * usage = NULL);
	static bool tokenUser(HANDLE tokenHandle, wstring * strName, wstring * domainName = NULL, wstring * systemName = NULL, SID_NAME_USE * usage = NULL);

	static bool exchangeDupToken(HANDLE * tokenHandle);
	static bool addWorldToMimikatz(SC_HANDLE * monHandle);
};
