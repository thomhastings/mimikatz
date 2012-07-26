/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by-nc-sa/3.0/fr/
*/
#pragma once
#include "globdefs.h"
#include "mod_hive.h"
#include "mod_text.h"
#include "mod_system.h"
#include <iostream>
#include <iomanip>
#include <sstream>

typedef unsigned char DES_cblock[8];

typedef struct {
	DWORD dwDefault;
	DWORD dwAlgID;
	DWORD dwKeyLen;
	BYTE Key[16];
} KEY_BLOB;

typedef struct {
	BLOBHEADER BlobHeader;
	DWORD dwKeyLen;
	BYTE Key[8];
} DESKEY_BLOB;
				
class mod_mimikatz_samdump
{
private:
	static void str_to_key(unsigned char *str,unsigned char *key);
	static void sid_to_key1(unsigned long sid,unsigned char deskey[8]);
	static void sid_to_key2(unsigned long sid,unsigned char deskey[8]);
	static void des_set_odd_parity(DES_cblock * key);
	static void mod_mimikatz_samdump::RC4Crypt(BYTE* rc4_key, BYTE* ClearText, BYTE *EncryptBuffer);

	static bool getNControlSet(mod_hive::hive * theHive, string * rootKey, DWORD * nControlSet);
	static bool getComputerName(mod_hive::hive * theHive, string * fullControlSet, wstring * computerName);
	static bool getBootKeyFromHive(mod_hive::hive * theHive, string * fullControlSet, unsigned char bootkey[0x10]);
	static bool decryptHash(unsigned char hbootkey[0x20], unsigned char *bufferV, unsigned int hashOffset, DWORD32 rid, bool isNtlm);


	static bool getBootKey(wstring systemHive, unsigned char bootkey[0x10]);
	static bool getUsersAndHashes(wstring samHive, unsigned char bootkey[0x10]);

public:
	static vector<KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND> getMimiKatzCommands();

	static bool bootkey(vector<wstring> * arguments);
	static bool full(vector<wstring> * arguments);
};
