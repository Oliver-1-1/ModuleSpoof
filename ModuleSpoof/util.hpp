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
typedef unsigned __int64 QWORD;
static BOOL read(QWORD address, PVOID buffer, QWORD length)
{


	SIZE_T ret = 0;
	if (!ReadProcessMemory(GetCurrentProcess(), (LPCVOID)address, buffer, length, &ret))
	{
		return 0;
	}
	return ret == length;
}

inline WORD read_i16(QWORD address)
{
	WORD result = 0;
	if (!read(address, &result, sizeof(result)))
	{
		return 0;
	}
	return result;
}

inline DWORD read_i32(QWORD address)
{
	DWORD result = 0;
	if (!read(address, &result, sizeof(result)))
	{
		return 0;
	}
	return result;
}

//Thank u ekknod :)
static QWORD get_module_export(QWORD base, PCSTR export_name)
{
	QWORD a0;
	DWORD a1[4]{};
	char  a2[120]{};

	a0 = base + read_i16(base + 0x3C);
	if (a0 == base)
	{
		return 0;
	}

	DWORD wow64_off = read_i16(a0 + 0x4) == 0x8664 ? 0x88 : 0x78;

	a0 = base + (QWORD)read_i32(a0 + wow64_off);
	if (a0 == base)
	{
		return 0;
	}

	int name_length = (int)strlen(export_name);
	if (name_length > 119)
		name_length = 119;

	read(a0 + 0x18, &a1, sizeof(a1));
	while (a1[0]--)
	{
		a0 = (QWORD)read_i32(base + a1[2] + ((QWORD)a1[0] * 4));
		if (a0 == 0)
		{
			continue;
		}

		read(base + a0, &a2, name_length + 1);
		a2[name_length + 1] = 0;

		if (!strcmp(a2, export_name))
		{
			a0 = read_i16(base + a1[3] + ((QWORD)a1[0] * 2)) * 4;
			a0 = read_i32(base + a1[1] + a0);
			return (base + a0);
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
