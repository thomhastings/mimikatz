/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by-nc-sa/3.0/fr/
*/
#pragma once
#include "globdefs.h"
#include <wincrypt.h>
#include <sstream>

class mod_cryptoapi /* Ref : http://msdn.microsoft.com/en-us/library/aa380255.aspx */
{
public:
	static bool getVectorProviders(vector<wstring> * monVectorProviders);
	static bool getVectorContainers(vector<wstring> * monVectorContainers, bool isMachine = false);
	static bool getPrivateKey(HCRYPTKEY maCle, PBYTE * monExport, DWORD * tailleExport, DWORD dwBlobType = PRIVATEKEYBLOB);
};
