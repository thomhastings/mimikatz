/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by-nc-sa/3.0/fr/
*/
#pragma once
#include "globdefs.h"
#include "mod_cryptoapi.h"
#include "mod_cryptong.h"
#include "mod_crypto.h"
#include "mod_process.h"
#include "mod_patch.h"
#include <iostream>

class mod_mimikatz_crypto
{
private:
	static void sanitizeFileName(wstring * fileName);
	static bool isNT6;
	static void listAndOrExportCertificates(wstring monEmplacement, wstring monStore, bool exportCert = false);
	static void listAndOrExportKeys(bool isMachine = false, bool exportKeys = false);
public:
	static vector<KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND> getMimiKatzCommands();
	
	static bool listProviders(vector<wstring> * arguments);
	static bool listStores(vector<wstring> * arguments);
	static bool listKeys(vector<wstring> * arguments);
	static bool listCertificates(vector<wstring> * arguments);

	static bool exportCertificates(vector<wstring> * arguments);
	static bool exportKeys(vector<wstring> * arguments);

	static bool patchcapi(vector<wstring> * arguments);
	static bool patchcng(vector<wstring> * arguments);
};

