#pragma once

#include <Windows.h>
#include <fstream>
#include <Ntsecapi.h>
#include <iostream>
#pragma pack(push)
#pragma pack(1)
template <class T>
struct LIST_ENTRY_T
{
	T Flink;
	T Blink;
};

template <class T>
struct UNICODE_STRING_T
{
	union
	{
		struct
		{
			WORD Length;
			WORD MaximumLength;
		};
		T dummy;
	};
	T _Buffer;
};

template <class T, class NGF, int A>
struct _PEB_T
{
	union
	{
		struct
		{
			BYTE InheritedAddressSpace;
			BYTE ReadImageFileExecOptions;
			BYTE BeingDebugged;
			BYTE BitField;
		};
		T dummy01;
	};
	T Mutant;
	T ImageBaseAddress;
	T Ldr;
	T ProcessParameters;
	T SubSystemData;
	T ProcessHeap;
	T FastPebLock;
	T AtlThunkSListPtr;
	T IFEOKey;
	T CrossProcessFlags;
	T UserSharedInfoPtr;
	DWORD SystemReserved;
	DWORD AtlThunkSListPtr32;
	T ApiSetMap;
	T TlsExpansionCounter;
	T TlsBitmap;
	DWORD TlsBitmapBits[2];
	T ReadOnlySharedMemoryBase;
	T HotpatchInformation;
	T ReadOnlyStaticServerData;
	T AnsiCodePageData;
	T OemCodePageData;
	T UnicodeCaseTableData;
	DWORD NumberOfProcessors;
	union
	{
		DWORD NtGlobalFlag;
		NGF dummy02;
	};
	LARGE_INTEGER CriticalSectionTimeout;
	T HeapSegmentReserve;
	T HeapSegmentCommit;
	T HeapDeCommitTotalFreeThreshold;
	T HeapDeCommitFreeBlockThreshold;
	DWORD NumberOfHeaps;
	DWORD MaximumNumberOfHeaps;
	T ProcessHeaps;
	T GdiSharedHandleTable;
	T ProcessStarterHelper;
	T GdiDCAttributeList;
	T LoaderLock;
	DWORD OSMajorVersion;
	DWORD OSMinorVersion;
	WORD OSBuildNumber;
	WORD OSCSDVersion;
	DWORD OSPlatformId;
	DWORD ImageSubsystem;
	DWORD ImageSubsystemMajorVersion;
	T ImageSubsystemMinorVersion;
	T ActiveProcessAffinityMask;
	T GdiHandleBuffer[A];
	T PostProcessInitRoutine;
	T TlsExpansionBitmap;
	DWORD TlsExpansionBitmapBits[32];
	T SessionId;
	ULARGE_INTEGER AppCompatFlags;
	ULARGE_INTEGER AppCompatFlagsUser;
	T pShimData;
	T AppCompatInfo;
	UNICODE_STRING_T<T> CSDVersion;
	T ActivationContextData;
	T ProcessAssemblyStorageMap;
	T SystemDefaultActivationContextData;
	T SystemAssemblyStorageMap;
	T MinimumStackCommit;
	T FlsCallback;
	LIST_ENTRY_T<T> FlsListHead;
	T FlsBitmap;
	DWORD FlsBitmapBits[4];
	T FlsHighIndex;
	T WerRegistrationData;
	T WerShipAssertPtr;
	T pContextData;
	T pImageHeaderHash;
	T TracingFlags;
};

typedef _PEB_T<DWORD, DWORD64, 34> PEB32;
typedef _PEB_T<DWORD64, DWORD, 30> PEB64;
#pragma pack(pop)

inline PEB64* NtCurrentPeb() {
#ifdef _M_X64
	return (PEB64*)(__readgsqword(0x60));
#elif _M_IX86
	return (PEB*)(__readfsdword(0x30));
#else
#endif
}

typedef struct _ANSI_STRING {
	USHORT  Length;
	USHORT  MaximumLength;
	PSTR    Buffer;
} ANSI_STRING, * PANSI_STRING;
typedef const UNICODE_STRING* PCUNICODE_STRING;
typedef struct _LDR_DLL_LOADED_NOTIFICATION_DATA {
	ULONG Flags;                    //Reserved.
	PCUNICODE_STRING FullDllName;   //The full path name of the DLL module.
	PCUNICODE_STRING BaseDllName;   //The base file name of the DLL module.
	PVOID DllBase;                  //A pointer to the base address for the DLL in memory.
	ULONG SizeOfImage;              //The size of the DLL image, in bytes.
} LDR_DLL_LOADED_NOTIFICATION_DATA, * PLDR_DLL_LOADED_NOTIFICATION_DATA;

typedef union _LDR_DLL_NOTIFICATION_DATA {
	LDR_DLL_LOADED_NOTIFICATION_DATA Loaded;
	LDR_DLL_LOADED_NOTIFICATION_DATA Unloaded;
} LDR_DLL_NOTIFICATION_DATA, * PLDR_DLL_NOTIFICATION_DATA;

typedef const _LDR_DLL_NOTIFICATION_DATA* PCLDR_DLL_NOTIFICATION_DATA;

static uint64_t zepta_get_proc_address(uint64_t base, PCSTR export_name) {
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
	if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((uint64_t)base + dos->e_lfanew);
	if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

	IMAGE_DATA_DIRECTORY exp = nt->OptionalHeader.DataDirectory[0];
	IMAGE_EXPORT_DIRECTORY* dir = (IMAGE_EXPORT_DIRECTORY*)(base + exp.VirtualAddress);

	PDWORD addresses = (PDWORD)(base + dir->AddressOfFunctions);
	PDWORD names = (PDWORD)(base + dir->AddressOfNames);
	uint16_t* ordinals = (uint16_t*)(base + dir->AddressOfNameOrdinals);

	for (int i = 0; i < dir->NumberOfNames; i++) {
		PCSTR name = (PCSTR)(base + names[i]);
		if (!_strcmpi(name, export_name)) {
			return base + addresses[ordinals[i]];
		}
	}

	return 0;
}

typedef VOID(CALLBACK* PLDR_DLL_NOTIFICATION_FUNCTION)(
	_In_      ULONG NotificationReason,
	_In_      PCLDR_DLL_NOTIFICATION_DATA NotificationData,
	_In_opt_  PVOID Context
	);


#define LDR_DLL_NOTIFICATION_REASON_LOADED 1
#define LDR_DLL_NOTIFICATION_REASON_UNLOADED 2
