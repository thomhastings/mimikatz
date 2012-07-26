/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence    : http://creativecommons.org/licenses/by-nc-sa/3.0/fr/
	Ce fichier : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "../sekurlsa.h"

bool searchKerberosFuncs();
__kextdll bool __cdecl getKerberosFunctions(mod_pipe * monPipe, vector<wstring> * mesArguments);
__kextdll bool __cdecl getKerberos(mod_pipe * monPipe, vector<wstring> * mesArguments);
bool WINAPI getKerberosLogonData(__in PLUID logId, __in mod_pipe * monPipe, __in bool justSecurity);

typedef struct _KIWI_KERBEROS_PRIMARY_CREDENTIAL
{
	DWORD unk0;
	PVOID unk1;
	PVOID unk2;
#ifdef _M_X64
	BYTE unk3[96];
#elif defined _M_IX86
	BYTE unk3[68];
#endif
	KIWI_GENERIC_PRIMARY_CREDENTIAL	credentials;
} KIWI_KERBEROS_PRIMARY_CREDENTIAL, *PKIWI_KERBEROS_PRIMARY_CREDENTIAL;

typedef struct _KIWI_KERBEROS_LOGON_AVL_SEARCH {
#ifdef _M_X64
	BYTE unk0[64];
#elif defined _M_IX86
	BYTE unk0[36];
#endif
	LUID LocallyUniqueIdentifier;
} KIWI_KERBEROS_LOGON_AVL_SEARCH, *PKIWI_KERBEROS_LOGON_AVL_SEARCH;


typedef struct _KIWI_KERBEROS_LOGON_SESSION
{
	struct _KIWI_KERBEROS_LOGON_SESSION *Flink;	// off_984C0 dd offset off_99540           ; DATA XREF: .data:_KERBEROS_LIST KerbLogonSessionListo
	struct _KIWI_KERBEROS_LOGON_SESSION *Blink; // dd offset ?KerbLogonSessionList@@3U_KERBEROS_LIST@@A ; _KERBEROS_LIST KerbLogonSessionList
	DWORD	UsageCount;							// dd 17
	PVOID	unk0;								// off_984CC dd offset off_984CC           ; DATA XREF: debug006:off_984CCo
	PVOID	unk1;								// dd offset off_984CC
	PVOID	unk2;								// dd offset unk_D56F0
	DWORD	unk3;								// dd 0FFFFFFFFh
	DWORD	unk4;								// dd 0
	PVOID	unk5;								// dd 0
	PVOID	unk6;								// dd 0
	PVOID	unk7;								// dd 0
	LUID LocallyUniqueIdentifier;				// _LUID <3E7h, 0>
#ifdef _M_IX86
	DWORD	unk8;								// dd 0
#endif
	DWORD	unk9;								// dd 0D5969FFFh
	DWORD	unk10;								// dd 7FFFFF36h
	PVOID	unk11;								// dd offset unk_D56C8
	DWORD	unk12;								// dd 0FFFFFFFFh
	DWORD	unk13;								// dd 0
	PVOID	unk14;								// dd 0
	PVOID	unk15;								// dd 0
	PVOID	unk16;								// dd 0
	KIWI_GENERIC_PRIMARY_CREDENTIAL	credentials;
} KIWI_KERBEROS_LOGON_SESSION, *PKIWI_KERBEROS_LOGON_SESSION;
