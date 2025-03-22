#pragma once
#include <ntddk.h>

#define SystemProcessInformationSize 1024 * 1024 * 2
#define BYTE CHAR 
#define DWORD ULONG

//0x10 bytes (sizeof)
union _KIDTENTRY64
{
    struct
    {
        USHORT OffsetLow;                                                   //0x0
        USHORT Selector;                                                    //0x2
    };
    USHORT IstIndex : 3;                                                    //0x4
    USHORT Reserved0 : 5;                                                   //0x4
    USHORT Type : 5;                                                        //0x4
    USHORT Dpl : 2;                                                         //0x4
    struct
    {
        USHORT Present : 1;                                                 //0x4
        USHORT OffsetMiddle;                                                //0x6
    };
    struct
    {
        ULONG OffsetHigh;                                                   //0x8
        ULONG Reserved1;                                                    //0xc
    };
    ULONGLONG Alignment;                                                    //0x0
};

typedef struct _IDT_ENTRY
{
    DWORD32 Vector;			// The vector number of the relative interrupt in the IDT
    PVOID ServiceRoutine;	// The kernel address of the service routine
} IDT_ENTRY, *PIDT_ENTRY;

typedef struct _MSR_ENTRY
{
    DWORD32 MSRIndex;		// The MSR Index (i.e 0xC0000082)
    ULONG_PTR MSRValue;		// The inital value within the relative MSR register
} MSR_ENTRY, *PMSR_ENTRY;

typedef struct _SSDT_ENTRY
{
	DWORD32 SyscallNumber;	// Will serve as the index in the SSDT
	DWORD32 SSDTValue;		// The SSDT value in the relative SCN
} SSDT_ENTRY, *PSSDT_ENTRY;

typedef struct _KERNEL_INFO
{
	PVOID KernelBaseAddress;
	SIZE_T Size;
} KERNEL_INFO, *PKERNEL_INFO;

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation = 0,
	SystemProcessorInformation = 1,           
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3,
	SystemPathInformation = 4,
	SystemProcessInformation = 5,
	SystemCallCountInformation = 6,
	SystemDeviceInformation = 7,
	SystemProcessorPerformanceInformation = 8,
	SystemFlagsInformation = 9,
	SystemCallTimeInformation = 10,
	SystemModuleInformation = 11,
	SystemLocksInformation = 12,
	SystemStackTraceInformation = 13,
	SystemPagedPoolInformation = 14,
	SystemNonPagedPoolInformation = 15,
	SystemHandleInformation = 16,
	SystemObjectInformation = 17,
	SystemPageFileInformation = 18,
	SystemVdmInstemulInformation = 19,
	SystemVdmBopInformation = 20,
	SystemFileCacheInformation = 21,
	SystemPoolTagInformation = 22,
	SystemInterruptInformation = 23,
	SystemDpcBehaviorInformation = 24,
	SystemFullMemoryInformation = 25,
	SystemLoadGdiDriverInformation = 26,
	SystemUnloadGdiDriverInformation = 27,
	SystemTimeAdjustmentInformation = 28,
	SystemSummaryMemoryInformation = 29,
	SystemMirrorMemoryInformation = 30,
	SystemPerformanceTraceInformation = 31,
	SystemObsolete0 = 32,
	SystemExceptionInformation = 33,
	SystemCrashDumpStateInformation = 34,
	SystemKernelDebuggerInformation = 35,
	SystemContextSwitchInformation = 36,
	SystemRegistryQuotaInformation = 37,
	SystemExtendServiceTableInformation = 38,
	SystemPrioritySeperation = 39,
	SystemVerifierAddDriverInformation = 40,
	SystemVerifierRemoveDriverInformation = 41,
	SystemProcessorIdleInformation = 42,
	SystemLegacyDriverInformation = 43,
	SystemCurrentTimeZoneInformation = 44,
	SystemLookasideInformation = 45,
	SystemTimeSlipNotification = 46,
	SystemSessionCreate = 47,
	SystemSessionDetach = 48,
	SystemSessionInformation = 49,
	SystemRangeStartInformation = 50,
	SystemVerifierInformation = 51,
	SystemVerifierThunkExtend = 52,
	SystemSessionProcessInformation = 53,
	SystemLoadGdiDriverInSystemSpace = 54,
	SystemNumaProcessorMap = 55,
	SystemPrefetcherInformation = 56,
	SystemExtendedProcessInformation = 57,
	SystemRecommendedSharedDataAlignment = 58,
	SystemComPlusPackage = 59,
	SystemNumaAvailableMemory = 60,
	SystemProcessorPowerInformation = 61,
	SystemEmulationBasicInformation = 62,
	SystemEmulationProcessorInformation = 63,
	SystemExtendedHandleInformation = 64,
	SystemLostDelayedWriteInformation = 65,
	SystemBigPoolInformation = 66,
	SystemSessionPoolTagInformation = 67,
	SystemSessionMappedViewInformation = 68,
	SystemHotpatchInformation = 69,
	SystemObjectSecurityMode = 70,
	SystemWatchdogTimerHandler = 71,
	SystemWatchdogTimerInformation = 72,
	SystemLogicalProcessorInformation = 73,
	SystemWow64SharedInformation = 74,
	SystemRegisterFirmwareTableInformationHandler = 75,
	SystemFirmwareTableInformation = 76,
	SystemModuleInformationEx = 77,
	SystemVerifierTriageInformation = 78,
	SystemSuperfetchInformation = 79,
	SystemMemoryListInformation = 80,
	SystemFileCacheInformationEx = 81,
	MaxSystemInfoClass = 82  // MaxSystemInfoClass should always be the last enum

} SYSTEM_INFORMATION_CLASS;


typedef struct _SYSTEM_MODULE {
	PVOID  Reserved1;
	PVOID  Reserved2;
	PVOID  ImageBase;		// Base address of the module
	ULONG  ImageSize;		// Size of the image
	ULONG  Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT ModuleNameOffset;
	CHAR   ImageName[256]; // Full path of the module
} SYSTEM_MODULE, * PSYSTEM_MODULE;

typedef struct _SYSTEM_MODULE_INFORMATION {
	ULONG ModuleCount;
	SYSTEM_MODULE Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;



