#include "ssdt.h"

#ifdef _M_X64
PSERVICE_DESCRIPTOR_TABLE	KeServiceDescriptorTable = NULL;
#endif

NTSTATUS kSSDT(LPWSTR pszDest, size_t cbDest, LPWSTR *ppszDestEnd, size_t *pcbRemaining)
{
	NTSTATUS status;
	USHORT idxFunction;
	ULONG_PTR funcAddr;

	#ifdef _M_X64
	status = getKeServiceDescriptorTable();
	if(NT_SUCCESS(status))
	{
	#endif
		*ppszDestEnd = pszDest; *pcbRemaining= cbDest;
		status = RtlStringCbPrintfExW(*ppszDestEnd, *pcbRemaining, ppszDestEnd, pcbRemaining, STRSAFE_NO_TRUNCATION , L"kSSDT - KeServiceDescriptorTable\t: %p\nkSSDT - KeServiceDescriptorTable.TableSize\t: %u\n", KeServiceDescriptorTable, KeServiceDescriptorTable->TableSize);
		for(idxFunction = 0; (idxFunction < KeServiceDescriptorTable->TableSize) && NT_SUCCESS(status) ; idxFunction++)
		{
			#ifdef _M_IX86
				funcAddr = (ULONG_PTR) KeServiceDescriptorTable->ServiceTable[idxFunction];
			#else
				funcAddr = (ULONG_PTR) KeServiceDescriptorTable->OffsetToService;
				if(INDEX_OS < INDEX_VISTA)
				{
					funcAddr += KeServiceDescriptorTable->OffsetToService[idxFunction] & ~EX_FAST_REF_MASK;
				}
				else
				{
					funcAddr += KeServiceDescriptorTable->OffsetToService[idxFunction] >> 4;
				}		
			#endif
			
			status = RtlStringCbPrintfExW(*ppszDestEnd, *pcbRemaining, ppszDestEnd, pcbRemaining, STRSAFE_NO_TRUNCATION, L"[%4u]\t: ", idxFunction);
			if(NT_SUCCESS(status))
			{
				status = getModuleFromAddr(funcAddr, *ppszDestEnd, *pcbRemaining, ppszDestEnd, pcbRemaining);
				if(NT_SUCCESS(status) || status == STATUS_NOT_FOUND)
				{
					status = RtlStringCbPrintfExW(*ppszDestEnd, *pcbRemaining, ppszDestEnd, pcbRemaining, STRSAFE_NO_TRUNCATION, L"\n");
				}
			}
		}
	#ifdef _M_X64
	}
	#endif
	return status;
}

#ifdef _M_X64
NTSTATUS getKeServiceDescriptorTable()
{
	NTSTATUS retour = STATUS_NOT_FOUND;
	
	UCHAR ptrn[] = {0x00, 0x00, 0x4d, 0x0f, 0x45, 0xd3, 0x42, 0x3b, 0x44, 0x17, 0x10, 0x0f, 0x83};
	LONG offsetToKe = -19;
	SIZE_T sizePtrn = sizeof(ptrn);

	LONG i;
	PLONG offset;
	UNICODE_STRING maRoutine;
	PVOID baseSearch = NULL;
	
	if(INDEX_OS >= INDEX_8)
		offsetToKe += 3;
		
	if(KeServiceDescriptorTable)
	{
		retour = STATUS_SUCCESS;
	}
	else
	{	
		RtlInitUnicodeString(&maRoutine, L"ZwUnloadKey");
		baseSearch = MmGetSystemRoutineAddress(&maRoutine);
		
		if(baseSearch)
		{
			for(i = -21*1024; i < 16*1024; i++)
			{
				if(RtlCompareMemory(ptrn, (PUCHAR) (((ULONG_PTR) baseSearch) + i), sizePtrn) == sizePtrn)
				{
					offset = (PLONG) (((ULONG_PTR) baseSearch) + i + offsetToKe);
					KeServiceDescriptorTable = (PSERVICE_DESCRIPTOR_TABLE) ((ULONG_PTR) offset + sizeof(LONG) + *offset);
					if(KeServiceDescriptorTable)
					{
						retour = STATUS_SUCCESS;
					}
					break;
				}
			}
		}
	}
	return retour;
}
#endif