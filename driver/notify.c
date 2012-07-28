#include "notify.h"

ULONG * PspCreateProcessNotifyRoutineCount = NULL;
ULONG * PspCreateProcessNotifyRoutineExCount = NULL;
PVOID * PspCreateProcessNotifyRoutine = NULL;

ULONG * PspCreateThreadNotifyRoutineCount = NULL;
PVOID * PspCreateThreadNotifyRoutine = NULL;

ULONG * PspLoadImageNotifyRoutineCount = NULL;
PVOID * PspLoadImageNotifyRoutine = NULL;

ULONG * CmpCallBackCount = NULL;
PVOID * CmpCallBackVector = NULL;
PLIST_ENTRY CallbackListHead = NULL;

POBJECT_DIRECTORY * ObpTypeDirectoryObject = NULL;

NTSTATUS kListNotifyProcesses(LPWSTR pszDest, size_t cbDest, LPWSTR *ppszDestEnd, size_t *pcbRemaining)
{
	NTSTATUS status;
	ULONG i;
	PKIWI_CALLBACK monCallBack;
	ULONG bonusCount;

	*ppszDestEnd = pszDest;	*pcbRemaining= cbDest;
	status = RtlStringCbPrintfExW(*ppszDestEnd, *pcbRemaining, ppszDestEnd, pcbRemaining, STRSAFE_NO_TRUNCATION, L"kListNotifyProcesses\n\n");
	if(NT_SUCCESS(status))
	{
		status = getPspCreateProcessNotifyRoutine();
		if(NT_SUCCESS(status))
		{
			bonusCount = *PspCreateProcessNotifyRoutineCount + ((INDEX_OS < INDEX_VISTA) ? 0 : *PspCreateProcessNotifyRoutineExCount);
			for(i = 0; (i < bonusCount) && NT_SUCCESS(status) ; i++)
			{
				monCallBack = (PKIWI_CALLBACK) KIWI_mask3bits(PspCreateProcessNotifyRoutine[i]);
				if(monCallBack != NULL)
				{
					status = RtlStringCbPrintfExW(*ppszDestEnd, *pcbRemaining, ppszDestEnd, pcbRemaining, STRSAFE_NO_TRUNCATION, L"[%.2u] ", i);
					if(NT_SUCCESS(status))
					{
						status = getModuleFromAddr((ULONG_PTR) monCallBack->callback, *ppszDestEnd, *pcbRemaining, ppszDestEnd, pcbRemaining);
						if(NT_SUCCESS(status) || status == STATUS_NOT_FOUND)
						{
							status = RtlStringCbPrintfExW(*ppszDestEnd, *pcbRemaining, ppszDestEnd, pcbRemaining, STRSAFE_NO_TRUNCATION, L"\n");
						}
					}
				}
			}
		}
	}
	return status;
}

NTSTATUS kListNotifyThreads(LPWSTR pszDest, size_t cbDest, LPWSTR *ppszDestEnd, size_t *pcbRemaining)
{
	NTSTATUS status;
	ULONG i;
	PKIWI_CALLBACK monCallBack;

	*ppszDestEnd = pszDest; *pcbRemaining= cbDest;
	status = RtlStringCbPrintfExW(*ppszDestEnd, *pcbRemaining, ppszDestEnd, pcbRemaining, STRSAFE_NO_TRUNCATION, L"kListNotifyThreads\n\n");
	if(NT_SUCCESS(status))
	{
		status = getPspCreateThreadNotifyRoutine();
		if(NT_SUCCESS(status))
		{
			for(i = 0; (i < *PspCreateThreadNotifyRoutineCount) && NT_SUCCESS(status) ; i++)
			{
				monCallBack = (PKIWI_CALLBACK) KIWI_mask3bits(PspCreateThreadNotifyRoutine[i]);
				if(monCallBack != NULL)
				{
					status = RtlStringCbPrintfExW(*ppszDestEnd, *pcbRemaining, ppszDestEnd, pcbRemaining, STRSAFE_NO_TRUNCATION, L"[%.2u] ", i);
					if(NT_SUCCESS(status))
					{
						status = getModuleFromAddr((ULONG_PTR) monCallBack->callback, *ppszDestEnd, *pcbRemaining, ppszDestEnd, pcbRemaining);
						if(NT_SUCCESS(status) || status == STATUS_NOT_FOUND)
						{
							status = RtlStringCbPrintfExW(*ppszDestEnd, *pcbRemaining, ppszDestEnd, pcbRemaining, STRSAFE_NO_TRUNCATION, L"\n");
						}
					}
				}
			}
		}
	}
	return status;
}

NTSTATUS kListNotifyImages(LPWSTR pszDest, size_t cbDest, LPWSTR *ppszDestEnd, size_t *pcbRemaining)
{
	NTSTATUS status;
	ULONG i;
	PKIWI_CALLBACK monCallBack;

	*ppszDestEnd = pszDest; *pcbRemaining= cbDest;
	status = RtlStringCbPrintfExW(*ppszDestEnd, *pcbRemaining, ppszDestEnd, pcbRemaining, STRSAFE_NO_TRUNCATION, L"kListNotifyImages\n\n");
	if(NT_SUCCESS(status))
	{
		status = getPspLoadImageNotifyRoutine();
		if(NT_SUCCESS(status))
		{
			for(i = 0; (i < *PspLoadImageNotifyRoutineCount) && NT_SUCCESS(status) ; i++)
			{
				monCallBack = (PKIWI_CALLBACK) KIWI_mask3bits(PspLoadImageNotifyRoutine[i]);
				if(monCallBack != NULL)
				{
					status = RtlStringCbPrintfExW(*ppszDestEnd, *pcbRemaining, ppszDestEnd, pcbRemaining, STRSAFE_NO_TRUNCATION, L"[%.2u] ", i);
					if(NT_SUCCESS(status))
					{
						status = getModuleFromAddr((ULONG_PTR) monCallBack->callback, *ppszDestEnd, *pcbRemaining, ppszDestEnd, pcbRemaining);
						if(NT_SUCCESS(status) || status == STATUS_NOT_FOUND)
						{
							status = RtlStringCbPrintfExW(*ppszDestEnd, *pcbRemaining, ppszDestEnd, pcbRemaining, STRSAFE_NO_TRUNCATION, L"\n");
						}
					}
				}
			}
		}
	}
	return status;
}

NTSTATUS kListNotifyRegistry(LPWSTR pszDest, size_t cbDest, LPWSTR *ppszDestEnd, size_t *pcbRemaining)
{
	NTSTATUS status;
	ULONG i;
	PKIWI_CALLBACK monCallBack;
	PLIST_ENTRY maListe;
	PKIWI_REGISTRY6_CALLBACK monCallBack6;

	*ppszDestEnd = pszDest; *pcbRemaining= cbDest;
	status = RtlStringCbPrintfExW(*ppszDestEnd, *pcbRemaining, ppszDestEnd, pcbRemaining, STRSAFE_NO_TRUNCATION, L"kListNotifyRegistry\n\n");
	if(NT_SUCCESS(status))
	{
		status = getNotifyRegistryRoutine();
		if(NT_SUCCESS(status))
		{
			if(INDEX_OS < INDEX_VISTA)
			{
				for(i = 0; (i < *CmpCallBackCount) && NT_SUCCESS(status) ; i++)
				{
					monCallBack = (PKIWI_CALLBACK) KIWI_mask3bits(CmpCallBackVector[i]);
					if(monCallBack != NULL)
					{
						status = RtlStringCbPrintfExW(*ppszDestEnd, *pcbRemaining, ppszDestEnd, pcbRemaining, STRSAFE_NO_TRUNCATION, L"[%.2u] ", i);
						if(NT_SUCCESS(status))
						{
							status = getModuleFromAddr((ULONG_PTR) monCallBack->callback, *ppszDestEnd, *pcbRemaining, ppszDestEnd, pcbRemaining);
							if(NT_SUCCESS(status) || status == STATUS_NOT_FOUND)
							{
								status = RtlStringCbPrintfExW(*ppszDestEnd, *pcbRemaining, ppszDestEnd, pcbRemaining, STRSAFE_NO_TRUNCATION,
									L" - cookie %#.I64x\n", *(monCallBack->opt_cookie)
								);
							}
						}
					}
				}
			}
			else
			{
				for(maListe = CallbackListHead->Flink, i = 0; (maListe != CallbackListHead) && NT_SUCCESS(status) ; maListe = maListe->Flink, i++)
				{
					monCallBack6 = (PKIWI_REGISTRY6_CALLBACK) (((ULONG_PTR) maListe) + sizeof(LIST_ENTRY) + 2*((INDEX_OS < INDEX_7) ? sizeof(PVOID) : sizeof(ULONG)));
					status = RtlStringCbPrintfExW(*ppszDestEnd, *pcbRemaining, ppszDestEnd, pcbRemaining, STRSAFE_NO_TRUNCATION, L"[%.2u] ", i);
					if(NT_SUCCESS(status))
					{
						status = getModuleFromAddr((ULONG_PTR) monCallBack6->callback, *ppszDestEnd, *pcbRemaining, ppszDestEnd, pcbRemaining);
						if(NT_SUCCESS(status) || status == STATUS_NOT_FOUND)
						{
							status = RtlStringCbPrintfExW(*ppszDestEnd, *pcbRemaining, ppszDestEnd, pcbRemaining, STRSAFE_NO_TRUNCATION,
								L" - alt %wZ - cookie %#.I64x\n", &(monCallBack6->altitude), monCallBack6->cookie);
						}
					}
				}
			}
		}
	}
	return status;
}

const WCHAR *procCallToName[] = {
	L"Dump       ",
	L"Open       ",
	L"Close      ",
	L"Delete     ",
	L"Parse      ",
	L"Security   ",
	L"QueryName  ",
	L"OkayToClose",
};

NTSTATUS kListNotifyObjects(LPWSTR pszDest, size_t cbDest, LPWSTR *ppszDestEnd, size_t *pcbRemaining)
{
	return listNotifyOrClearObjects(pszDest, cbDest, ppszDestEnd, pcbRemaining, ListNotif);	
}

NTSTATUS kClearNotifyObjects(LPWSTR pszDest, size_t cbDest, LPWSTR *ppszDestEnd, size_t *pcbRemaining)
{
	return listNotifyOrClearObjects(pszDest, cbDest, ppszDestEnd, pcbRemaining, ClearNotif);	
}

NTSTATUS listNotifyOrClearObjects(LPWSTR pszDest, size_t cbDest, LPWSTR *ppszDestEnd, size_t *pcbRemaining, KIWI_EPROCESS_ACTION action)
{
	NTSTATUS status;
	ULONG i, j;
	POBJECT_DIRECTORY_ENTRY monEntree;
	POBJECT_TYPE monType, monTypeDecal;
	PVOID * miniProc;
	POBJECT_CALLBACK_ENTRY pStruct;

	*ppszDestEnd = pszDest; *pcbRemaining= cbDest;
	status = RtlStringCbPrintfExW(*ppszDestEnd, *pcbRemaining, ppszDestEnd, pcbRemaining, STRSAFE_NO_TRUNCATION, L"kListNotifyObjects\n\n");
	
	if(NT_SUCCESS(status))
	{
		status = getObpTypeDirectoryObject();
		if(NT_SUCCESS(status))
		{
			for(i = 0; (i < OBJECT_HASH_TABLE_SIZE) && NT_SUCCESS(status); i++)
			{
				if((*ObpTypeDirectoryObject)->HashBuckets[i])
				{
					for(monEntree = (*ObpTypeDirectoryObject)->HashBuckets[i]; monEntree && NT_SUCCESS(status); monEntree = monEntree->NextEntry)
					{
						if(monType = monEntree->Object)
						{
							if(INDEX_OS < INDEX_VISTA)
								monType = (POBJECT_TYPE) ((ULONG_PTR) (monType) + sizeof(ERESOURCE));
							
							if(action == ListNotif)
							{
								status = RtlStringCbPrintfExW(*ppszDestEnd, *pcbRemaining, ppszDestEnd, pcbRemaining, STRSAFE_NO_TRUNCATION, L"\n%wZ\n", &(monType->Name));
								for(j = 0; (j < 8) && NT_SUCCESS(status); j++)
								{
									miniProc = (PVOID *) (((ULONG_PTR) &(monType->TypeInfo)) + OFFSETOF(OBJECT_TYPE_INITIALIZER, DumpProcedure) + sizeof(PVOID)*j
									#ifdef _M_IX86
										- ((INDEX_OS < INDEX_VISTA) ? sizeof(ULONG) : 0)
									#endif
									);
									if(*miniProc)
									{
										status = RtlStringCbPrintfExW(*ppszDestEnd, *pcbRemaining, ppszDestEnd, pcbRemaining, STRSAFE_NO_TRUNCATION, L" - %ws : ", procCallToName[j]);
										if(NT_SUCCESS(status))
										{
											status = getModuleFromAddr((ULONG_PTR) *miniProc, *ppszDestEnd, *pcbRemaining, ppszDestEnd, pcbRemaining);
											if(NT_SUCCESS(status) || status == STATUS_NOT_FOUND)
											{
												status = RtlStringCbPrintfExW(*ppszDestEnd, *pcbRemaining, ppszDestEnd, pcbRemaining, STRSAFE_NO_TRUNCATION, L"\n");
											}
										}
									}
								}
							}
							if(INDEX_OS >= INDEX_VISTA)
							{
								if(INDEX_OS < INDEX_7)
									monType = (POBJECT_TYPE) ((ULONG_PTR) (monType) + sizeof(ERESOURCE) + 32*sizeof(EX_PUSH_LOCK));
									
								for(pStruct = (POBJECT_CALLBACK_ENTRY) (monType->CallbackList.Flink) ; (pStruct != (POBJECT_CALLBACK_ENTRY) &(monType->CallbackList)) && NT_SUCCESS(status) ; pStruct = (POBJECT_CALLBACK_ENTRY) pStruct->CallbackList.Flink)
								{
									if(pStruct->PreOperation || pStruct->PostOperation)
									{
										status = RtlStringCbPrintfExW(*ppszDestEnd, *pcbRemaining, ppszDestEnd, pcbRemaining, STRSAFE_NO_TRUNCATION, L" * Callback %u  : ", pStruct->Operations, pStruct->PreOperation);;
										if(NT_SUCCESS(status))
										{
											status = getModuleFromAddr((ULONG_PTR) pStruct->PreOperation, *ppszDestEnd, *pcbRemaining, ppszDestEnd, pcbRemaining);
											if(NT_SUCCESS(status) || status == STATUS_NOT_FOUND)
											{
												status = RtlStringCbPrintfExW(*ppszDestEnd, *pcbRemaining, ppszDestEnd, pcbRemaining, STRSAFE_NO_TRUNCATION, L" / ");
												if(NT_SUCCESS(status))
												{
													status = getModuleFromAddr((ULONG_PTR) pStruct->PostOperation, *ppszDestEnd, *pcbRemaining, ppszDestEnd, pcbRemaining);
													if(NT_SUCCESS(status) || status == STATUS_NOT_FOUND)
													{
														status = RtlStringCbPrintfExW(*ppszDestEnd, *pcbRemaining, ppszDestEnd, pcbRemaining, STRSAFE_NO_TRUNCATION, L"\n");
													}
												}
											}
										}
										
										if(action == ClearNotif)
										{
											pStruct->PreOperation = NULL;
											pStruct->PostOperation = NULL;
											status = RtlStringCbPrintfExW(*ppszDestEnd, *pcbRemaining, ppszDestEnd, pcbRemaining, STRSAFE_NO_TRUNCATION, L" -> NULL !\n");
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
	return status;
}

NTSTATUS getPspCreateProcessNotifyRoutine()
{
	NTSTATUS retour = STATUS_NOT_FOUND;

	LONG i;
	#ifdef _M_X64
		PLONG offset;
		UCHAR ptrnProcessNT6[] = {0x40, 0xC0, 0xED, 0x02, 0x41, 0x22, 0xEE, 0xA8, 0x02, 0x0F, 0x84};
		LONG offsetToData6 = sizeof(ptrnProcessNT6) + 4 + 3;
		UCHAR ptrnProcessNT5[] = {0x41, 0xBC, 0x08, 0x00, 0x00, 0x00, 0x48, 0x8B, 0xEB};
		LONG offsetToData5 = -4;
		
		#define VARi_getPspCreateProcessNotifyRoutine	(-i)
		ULONG_PTR funcRef = (ULONG_PTR) CcMdlRead;
	#elif defined _M_IX86
		UCHAR ptrnProcessNT6[] = {0x33, 0xdb, 0xc7, 0x45};
		LONG offsetToData6 = sizeof(ptrnProcessNT6) + 1;
		UCHAR ptrnProcessNT5[] = {0x56, 0x57, 0x74};
		LONG offsetToData5 = sizeof(ptrnProcessNT5) + 2;
		
		#define VARi_getPspCreateProcessNotifyRoutine	(i)
		ULONG_PTR funcRef = (ULONG_PTR) PsSetCreateProcessNotifyRoutine;
	#endif
	
	PUCHAR ptrnProcess;
	LONG offsetToData;
	SIZE_T sizePtrnProcess;

	if(PspCreateProcessNotifyRoutine && ((INDEX_OS < INDEX_VISTA) || PspCreateProcessNotifyRoutineExCount) && PspCreateProcessNotifyRoutineCount)
	{
		retour = STATUS_SUCCESS;	
	}
	else
	{
		if(INDEX_OS < INDEX_VISTA)
		{
			sizePtrnProcess = sizeof(ptrnProcessNT5);
			offsetToData = offsetToData5;
			ptrnProcess = ptrnProcessNT5;
		}
		else
		{
			sizePtrnProcess = sizeof(ptrnProcessNT6);
			offsetToData = offsetToData6;
			ptrnProcess = ptrnProcessNT6;
		}
				
		for(i = 0; i < 25*PAGE_SIZE; i++)
		{
			if(RtlCompareMemory(ptrnProcess, (PUCHAR) (funcRef + VARi_getPspCreateProcessNotifyRoutine), sizePtrnProcess) == sizePtrnProcess)
			{
				#ifdef _M_IX86
					PspCreateProcessNotifyRoutine = *(PVOID *) (funcRef + VARi_getPspCreateProcessNotifyRoutine + offsetToData);
				#else
					offset = (PLONG) (funcRef + VARi_getPspCreateProcessNotifyRoutine + offsetToData);
					PspCreateProcessNotifyRoutine = (PVOID) ((ULONG_PTR) offset + sizeof(LONG) + *offset);
				#endif

				PspCreateProcessNotifyRoutineExCount = (PULONG) (PspCreateProcessNotifyRoutine + (INDEX_OS < INDEX_VISTA ? MAX_NT5_PspCreateProcessNotifyRoutine : MAX_NT6_PspCreateProcessNotifyRoutine));
				PspCreateProcessNotifyRoutineCount = PspCreateProcessNotifyRoutineExCount + 1;

				if(INDEX_OS < INDEX_VISTA)
				{
					PspCreateProcessNotifyRoutineCount = PspCreateProcessNotifyRoutineExCount;
					PspCreateProcessNotifyRoutineExCount = NULL;
				}
				
				if(PspCreateProcessNotifyRoutine && ((INDEX_OS < INDEX_VISTA) || PspCreateProcessNotifyRoutineExCount) && PspCreateProcessNotifyRoutineCount)
				{
					retour = STATUS_SUCCESS;
				}
				break;
			}
		}	
	}
	return retour;
}

NTSTATUS getPspCreateThreadNotifyRoutine()
{
	NTSTATUS retour = STATUS_NOT_FOUND;
	
	LONG i;
	#ifdef _M_X64
		PLONG offset;
		UCHAR ptrnProcessNT6[] = {0x48, 0x8d, 0x0d};
		LONG offsetToData6 = sizeof(ptrnProcessNT6);
		UCHAR ptrnProcessNT5[] = {0x48, 0x8d, 0x35};
		LONG offsetToData5 = sizeof(ptrnProcessNT5);
	#elif defined _M_IX86
		UCHAR ptrnProcessNT6[] = {0x56, 0xbe};
		LONG offsetToData6 = sizeof(ptrnProcessNT6);
		UCHAR ptrnProcessNT5[] = {0x56, 0xbe};
		LONG offsetToData5 = sizeof(ptrnProcessNT5);
	#endif
	
	PUCHAR ptrnProcess;
	LONG offsetToData;
	SIZE_T sizePtrnProcess;
	
	if(PspCreateThreadNotifyRoutine && PspCreateThreadNotifyRoutineCount)
	{
		retour = STATUS_SUCCESS;
	}
	else
	{
		if(INDEX_OS < INDEX_VISTA)
		{
			sizePtrnProcess = sizeof(ptrnProcessNT5);
			offsetToData = offsetToData5;
			ptrnProcess = ptrnProcessNT5;
		}
		else
		{
			sizePtrnProcess = sizeof(ptrnProcessNT6);
			offsetToData = offsetToData6;
			ptrnProcess = ptrnProcessNT6;
		}
				
		for(i = 0; i < PAGE_SIZE; i++)
		{
			if(RtlCompareMemory(ptrnProcess, (PUCHAR) (((ULONG_PTR) PsSetCreateThreadNotifyRoutine) + i), sizePtrnProcess) == sizePtrnProcess)
			{
				#ifdef _M_IX86
					PspCreateThreadNotifyRoutine = *(PVOID *) (((ULONG_PTR) PsSetCreateThreadNotifyRoutine) + i + offsetToData);
				#else
					offset = (PLONG) (((ULONG_PTR) PsSetCreateThreadNotifyRoutine) + i + offsetToData);
					PspCreateThreadNotifyRoutine = (PVOID) ((ULONG_PTR) offset + sizeof(LONG) + *offset);
				#endif

				PspCreateThreadNotifyRoutineCount = (PULONG) (PspCreateThreadNotifyRoutine + (INDEX_OS < INDEX_VISTA ? MAX_NT5_PspCreateThreadNotifyRoutine : MAX_NT6_PspCreateThreadNotifyRoutine));
				
				if(PspCreateThreadNotifyRoutine && PspCreateThreadNotifyRoutineCount)
				{
					retour = STATUS_SUCCESS;
				}
				break;
			}
		}	
	}
	return retour;
}

NTSTATUS getPspLoadImageNotifyRoutine()
{
	NTSTATUS retour = STATUS_NOT_FOUND;
	
	LONG i;
	#ifdef _M_X64
		PLONG offset;
		UCHAR ptrnProcessNT6[] = {0x48, 0x8d, 0x0d};
		LONG offsetToData6 = sizeof(ptrnProcessNT6);
		UCHAR ptrnProcessNT5[] = {0x48, 0x8d, 0x35};
		LONG offsetToData5 = sizeof(ptrnProcessNT5);
		LONG offsetToCount5 = -12;
	#elif defined _M_IX86
		UCHAR ptrnProcessNT6[] = {0x6a, 0x00, 0x8b, 0xCb, 0x8b, 0xc6};
		LONG offsetToData6 = -4;
		UCHAR ptrnProcessNT5[] = {0X6a, 0x00, 0x53, 0x56};
		LONG offsetToData5 = -4;
		LONG offsetToCount5 = -24;
	#endif
	
	PUCHAR ptrnProcess;
	LONG offsetToData;
	SIZE_T sizePtrnProcess;
		
	if(PspLoadImageNotifyRoutine && PspLoadImageNotifyRoutineCount)
	{
		retour = STATUS_SUCCESS;
	}
	else
	{
		if(INDEX_OS < INDEX_VISTA)
		{
			sizePtrnProcess = sizeof(ptrnProcessNT5);
			offsetToData = offsetToData5;
			ptrnProcess = ptrnProcessNT5;
		}
		else
		{
			sizePtrnProcess = sizeof(ptrnProcessNT6);
			offsetToData = offsetToData6;
			ptrnProcess = ptrnProcessNT6;
		}
				
		for(i = 0; i < PAGE_SIZE; i++)
		{
			if(RtlCompareMemory(ptrnProcess, (PUCHAR) (((ULONG_PTR) PsSetLoadImageNotifyRoutine) + i), sizePtrnProcess) == sizePtrnProcess)
			{
				#ifdef _M_IX86
					PspLoadImageNotifyRoutine = *(PVOID *) (((ULONG_PTR) PsSetLoadImageNotifyRoutine) + i + offsetToData);
				#else
					offset = (PLONG) (((ULONG_PTR) PsSetLoadImageNotifyRoutine) + i + offsetToData);
					PspLoadImageNotifyRoutine = (PVOID) ((ULONG_PTR) offset + sizeof(LONG) + *offset);
				#endif

				if(INDEX_OS < INDEX_VISTA)
				{
					PspLoadImageNotifyRoutineCount = (PULONG) ((ULONG_PTR) PspLoadImageNotifyRoutine + offsetToCount5);
				}
				else
				{
					PspLoadImageNotifyRoutineCount = (PULONG) (PspLoadImageNotifyRoutine + MAX_NT_PspLoadImageNotifyRoutine);
				}
				
				if(PspLoadImageNotifyRoutine && PspLoadImageNotifyRoutineCount)
				{
					retour = STATUS_SUCCESS;
				}
				break;
			}
		}	
	}
	return retour;
}

NTSTATUS getNotifyRegistryRoutine()
{
	NTSTATUS retour = STATUS_NOT_FOUND;
	LONG i, j;
	#ifdef _M_X64
		PLONG offset;
		UCHAR ptrnHead61[] = {0x48, 0x8b, 0xf8, 0x48};
		LONG offsetToHead61 = -9;
		UCHAR ptrnHead60[] = {0x48, 0x8b, 0xf0, 0x48};
		LONG offsetToHead60 = -9;

		UCHAR ptrnVector[] = {0x4c, 0x8d, 0x3d};
		UCHAR ptrnCount[] = {/*0xff, 0xff, 0xff, 0xff, 0xf0,*/ 0x0f, 0xc1, 0x05};
	#elif defined _M_IX86
		UCHAR ptrnHead61[] = {0x8b, 0xc7, 0xe8};
		LONG offsetToHead61 = -4;
		UCHAR ptrnHead60[] = {0x8b, 0xcb, 0xe8};
		LONG offsetToHead60 = 12;
		
		UCHAR ptrnVector[] = {0x53, 0x56, 0x57, 0xbb};
		UCHAR ptrnCount[] = {0xff, 0xb9};
	#endif

	SIZE_T sizePtrnHead;
	UCHAR * ptrnHead;
	LONG offsetToHead;
	
	SIZE_T sizePtrnVector = sizeof(ptrnVector);
	SIZE_T sizePtrnCount = sizeof(ptrnCount);
		
	if((CmpCallBackVector && CmpCallBackCount) || CallbackListHead)
	{
		retour = STATUS_SUCCESS;
	}
	else
	{
		if(INDEX_OS < INDEX_VISTA)
		{
			for(i = 0; i < PAGE_SIZE; i++)
			{
				if(RtlCompareMemory(ptrnVector, (PUCHAR) (((ULONG_PTR) CmUnRegisterCallback) + i), sizePtrnVector) == sizePtrnVector)
				{
					#ifdef _M_IX86
						CmpCallBackVector = *(PVOID *) (((ULONG_PTR) CmUnRegisterCallback) + i + sizePtrnVector);
					#else
						offset = (PLONG) (((ULONG_PTR) CmUnRegisterCallback) + i + sizePtrnVector);
						CmpCallBackVector = (PVOID) ((ULONG_PTR) offset + sizeof(LONG) + *offset);
					#endif
					
					for(j = 0; j < PAGE_SIZE; j++)
					{
						if(RtlCompareMemory(ptrnCount, (PUCHAR) (((ULONG_PTR) CmUnRegisterCallback) + i + j), sizePtrnCount) == sizePtrnCount)
						{
							#ifdef _M_IX86
								CmpCallBackCount = *(PULONG *) (((ULONG_PTR) CmUnRegisterCallback) + i + j + sizePtrnCount);
							#else
								offset = (PLONG) (((ULONG_PTR) CmUnRegisterCallback) + i + j + sizePtrnCount);
								CmpCallBackCount = (PVOID) ((ULONG_PTR) offset + sizeof(LONG) + *offset);
							#endif

							if(CmpCallBackVector && CmpCallBackCount)
							{
								retour = STATUS_SUCCESS;
							}
							break;
						}
					}
					break;
				}
			}	
		}
		else
		{
			if(INDEX_OS < INDEX_7)
			{
				sizePtrnHead = sizeof(ptrnHead60);
				ptrnHead = ptrnHead60;
				offsetToHead = offsetToHead60;
			}
			else
			{
				sizePtrnHead = sizeof(ptrnHead61);
				ptrnHead = ptrnHead61;
				offsetToHead = offsetToHead61;
			}
			
			for(i = 0; i < PAGE_SIZE; i++)
			{
				if(RtlCompareMemory(ptrnHead, (PUCHAR) (((ULONG_PTR) CmUnRegisterCallback) + i), sizePtrnHead) == sizePtrnHead)
				{
					#ifdef _M_IX86
						CallbackListHead = *(PVOID *) (((ULONG_PTR) CmUnRegisterCallback) + i + offsetToHead);
					#else
						offset = (PLONG) (((ULONG_PTR) CmUnRegisterCallback) + i + offsetToHead);
						CallbackListHead = (PVOID) ((ULONG_PTR) offset + sizeof(LONG) + *offset);
					#endif
					
					if(CallbackListHead)
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

NTSTATUS getObpTypeDirectoryObject()
{
	NTSTATUS retour = STATUS_NOT_FOUND;
	UNICODE_STRING maRoutine;
	PVOID baseSearch = NULL;
	
	LONG i;
	#ifdef _M_X64
		PLONG offset;
		LONG sens = ((INDEX_OS < INDEX_VISTA) ? 1 : -1);
		UCHAR ptrnObjType[] = {0x66, 0x83, 0xF8, 0x5C, 0x0F, 0x84};
		LONG offsetToData = sizeof(ptrnObjType) + 4 + ((INDEX_OS < INDEX_VISTA) ? (2 + 2 + 3*8) : (3 + 2)) + 3;
		#define VARi_getObpTypeDirectoryObject	(i*sens)
	#elif defined _M_IX86
		UCHAR ptrnObjType[] = {0x74, 0x14, 0x66, 0x8B, 0x11, 0x48, 0x41, 0x41, 0x66, 0x83, 0xFA, 0x5C, 0x0F, 0x84};
		LONG offsetToData = sizeof(ptrnObjType) + 4 + 2 + 2 + ((INDEX_OS < INDEX_VISTA) ? 2 : 1);
		#define VARi_getObpTypeDirectoryObject	(i)
	#endif
		
	if(ObpTypeDirectoryObject)
	{
		retour = STATUS_SUCCESS;
	}
	else
	{
		RtlInitUnicodeString(&maRoutine, L"ObCreateObjectType");
		baseSearch = MmGetSystemRoutineAddress(&maRoutine);
		
		if(baseSearch)
		{
			for(i = 0; i < PAGE_SIZE; i++)
			{
				if(RtlCompareMemory(ptrnObjType, (PUCHAR) (((ULONG_PTR) baseSearch) + VARi_getObpTypeDirectoryObject), sizeof(ptrnObjType)) == sizeof(ptrnObjType))
				{
					#ifdef _M_IX86
						ObpTypeDirectoryObject = *(PVOID *) (((ULONG_PTR) baseSearch) + VARi_getObpTypeDirectoryObject + offsetToData);
					#else
						offset = (PLONG) (((ULONG_PTR) baseSearch) + VARi_getObpTypeDirectoryObject + offsetToData);
						ObpTypeDirectoryObject = (PVOID) ((ULONG_PTR) offset + sizeof(LONG) + *offset);
					#endif
	
					if(ObpTypeDirectoryObject)
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