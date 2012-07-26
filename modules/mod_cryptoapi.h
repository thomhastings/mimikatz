#pragma once
#include "globdefs.h"
#include <wincrypt.h>
#include <sstream>

class mod_cryptoapi /* Ref : http://msdn.microsoft.com/en-us/library/aa380255.aspx */
{
private:

protected:

public:
	static bool getVectorProviders(vector<wstring> * monVectorProviders);
	static bool getVectorContainers(vector<wstring> * monVectorContainers, bool isMachine = false);
	static bool getPrivateKey(HCRYPTKEY maCle, PBYTE * monExport, DWORD * tailleExport, DWORD dwBlobType = PRIVATEKEYBLOB);
};
