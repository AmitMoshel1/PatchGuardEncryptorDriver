#pragma once
#include <ntddk.h>

//0x10 bytes (sizeof)
union _KIDTENTRY64
{
    struct
    {
        USHORT OffsetLow;                                                   //0x0
        USHORT Selector;                                                    //0x2
    };
    USHORT IstIndex : 3;                                                      //0x4
    USHORT Reserved0 : 5;                                                     //0x4
    USHORT Type : 5;                                                          //0x4
    USHORT Dpl : 2;                                                           //0x4
    struct
    {
        USHORT Present : 1;                                                   //0x4
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
    DWORD32 Vector;
//    _KINTERRUPT* KInterrupt;
    PVOID ServiceRoutine;
} IDT_ENTRY, *PIDT_ENTRY;

typedef struct _MSR_ENTRY
{
    DWORD32 MSRIndex;
    ULONG_PTR MSRValue;
} MSR_ENTRY, *PMSR_ENTRY;

