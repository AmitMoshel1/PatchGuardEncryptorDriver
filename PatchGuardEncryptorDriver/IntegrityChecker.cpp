#include "IntegrityChecker.h"
#include <ntddk.h>
#include "Helper.h"

#pragma warning(push)
#pragma warning(disable: 4244)  // Disable specific warning
#pragma warning(disable: 4293)	// Disable specific warning
#pragma warning(disable: 4201)	// Disable specific warning
#pragma warning(disable: 4996)	// Disable specific warning
#pragma warning(disable: 6066)	// Disable specific warning
#pragma warning(disable: 4018)	// Disable specific warning
#pragma warning(disable: 4838)	// Disable specific warning
#pragma warning(disable: 4309)	// Disable specific warning

//// new operator overloading
//void* __cdecl operator new(size_t size, DWORD32 NumberOfAllocations, POOL_TYPE PoolType)
//{
//	return ExAllocatePool(PoolType, NumberOfAllocations * size);
//}
//
//// delete operator overloading
//void __cdecl operator delete(void* p, size_t)
//{
//	ExFreePool(p);
//}

extern "C" PKERNEL_INFO g_KernelInfo = nullptr;
//extern "C" ULONG_PTR g_KernelBaseAddress = NULL;

IntegrityCheck::IntegrityCheck(PTIMER_INFO TimerInfoArr) : TimerInfoArray(TimerInfoArr)
{
	KdPrint(("[*] PatchGuardEncryptorDriver::IntegrityCheck constructor invoked!\n"));

	KeInitializeTimerEx(&TimerVerifierIDT, NotificationTimer);
	KdPrint(("IntegrityCheck::IntegrityCheck() IDT Verifier _KTIMER object initialized successfully at address: 0x%p\n", &(TimerVerifierIDT)));


	//KeInitializeTimerEx(&TimerVerifierSSDT, NotificationTimer);
	//KdPrint(("IntegrityCheck::IntegrityCheck() SSDT Verifier _KTIMER object initialized successfully at address: 0x%p\n", &(TimerVerifierSSDT)));
	
	//KeInitializeTimerEx(&TimerVerifierMSR, NotificationTimer);
	//KdPrint(("IntegrityCheck::IntegrityCheck() MSR Verifier _KTIMER object initialized successfully at address: 0x%p\n", &(TimerVerifierMSR)));

	
	//g_DefferedContext = new(3, NonPagedPool)DeferredContextDPC; 

	// 3 is the Number of times to allocate the DeferredContextDPC structure in non-paged pool,
	// since we have 3 "IntegrityCheck" timers for each mechanism (IDT, SSDT, MSRs), we'll allocate 3 structures.
	g_DefferedContext = (PDeferredContextDPC)ExAllocatePool(NonPagedPool, sizeof(DeferredContextDPC) * 3);
	if (!g_DefferedContext)
	{
		KdPrint(("[*] IntegrityCheck::IntegrityCheck(): failed to allocate g_DefferedContext memory!\n"));
		return;
	}

	//TimerInfo of TimerIDT
	g_DefferedContext[0].TimerInfo = &TimerInfoArray[0];
	g_DefferedContext[0].TimerObjectPointer = TimerInfoArray[0].Timer;

	//TimerInfo of TimerSSDT
	g_DefferedContext[1].TimerInfo = &TimerInfoArray[1];
	g_DefferedContext[1].TimerObjectPointer = TimerInfoArray[1].Timer;

	//TimerInfo of TimerMSRs
	g_DefferedContext[2].TimerInfo = &TimerInfoArray[2];	//(PTIMER_INFO)((ULONG_PTR)TimerInfoArray + (sizeof(TIMER_INFO)*2))
	g_DefferedContext[2].TimerObjectPointer = TimerInfoArray[2].Timer;


	KdPrint(("[*] g_DefferedContext allocated at address: 0x%p\n", g_DefferedContext));

	InitializeDPC(&TimerVerifierIDT,
		&DPCVerifierIDT,
		&DPCIntegrityCheckIDT,
		(PVOID)&g_DefferedContext[0]);

	/*InitializeDPC(&TimerVerifierSSDT,
		&DPCVerifierSSDT,
		&DPCIntegrityCheckSSDT,
		(PVOID)&g_DefferedContext[1]);*/

	//IntegrityCheck::InitializeDPC();
	//IntegrityCheck::InitializeDPC();

}


BOOLEAN IntegrityCheck::CancelVerifierTimer(PKTIMER Timer)
{
	/*BOOLEAN b = KeCancelTimer(&Timer);
	KdPrint(("IntegrityCheck::CancelVerifierTimer: verifier _KTIMER located at kernel address: 0x%p was cancelled succesfully!\n", &Timer));*/
	return KeCancelTimer(Timer);;
}


// Right rotate function for 64-bit values
static inline ULONG_PTR ROR8(ULONG_PTR value, BYTE shift)
{
	return (value >> shift) | (value << (64 - shift));
}

/*
	I implemented the IntegrityCheck::CalculateTimerDPCValue() method through reversing the nt!KeSetTimerEx()
	which performs the following operations when attaching a DPC to the target _KTIMER object and stores
	the calculated result in _KTIMER->Dpc field.
*/

ULONG_PTR IntegrityCheck::CalculateTimerDPCValue(PKDPC Dpc, PKTIMER KTimer)
{
	ULONG_PTR KernelBaseAddress = (ULONG_PTR)g_KernelInfo->KernelBaseAddress;
	//ULONG_PTR KernelBaseAddress = (ULONG_PTR)g_KernelBaseAddress;

	// Offsets for nt!KiWaitAlways and nt!KiWaitNever (These offsets change between builds!!!)
	ULONG_PTR KiWaitAlwaysAddress = KernelBaseAddress + 0x00fc5260;
	ULONG_PTR KiWaitNeverAddress = KernelBaseAddress + 0x00fc4f80;

	// Read values from memory
	ULONG_PTR KiWaitAlwaysValue = *(ULONG_PTR*)KiWaitAlwaysAddress;
	ULONG_PTR KiWaitNeverValue = *(ULONG_PTR*)KiWaitNeverAddress;

	// Read the shift count from KiWaitNever (ensuring it's a valid rotation amount)
	BYTE shift = *(BYTE*)(KiWaitNeverAddress) & 0x3F; // Masking to avoid invalid shifts (0x3F = 63)

	ULONG_PTR intermediate = _byteswap_uint64((ULONG_PTR)Dpc ^ KiWaitAlwaysValue);
	ULONG_PTR rotated = ROR8(intermediate ^ (ULONG_PTR)KTimer, shift);

	return rotated ^ KiWaitNeverValue;
}

//BOOLEAN IntegrityCheck::TimerChecker(PKTIMER TimerObjectPointer, PTIMER_INFO TimerInfo)
BOOLEAN IntegrityCheck::TimerChecker(PKTIMER TimerObjectPointer, PTIMER_INFO TimerInfo)
{
	// Verifying that the KTIMER's DPC wasn't manipulated 
	// Wrong: IntegrityCheck::TimerChecker: KTIMER->Dpc structure pointer was manipulated:
	// TimerInfo->Dpc: 0xFFFFF800210E7130 and TimerObjectPointer->Dpc: 0x4B3AE633466F0072 <-- Not correct!!

	ULONG_PTR CalculatedDPCValue = CalculateTimerDPCValue(TimerInfo->Dpc, TimerInfo->Timer);
	KdPrint(("CalculatedDPCValue received is: 0x%p\n", CalculatedDPCValue));

	if (CalculatedDPCValue != (ULONG_PTR)TimerObjectPointer->Dpc)
	//if ((ULONG_PTR)TimerInfo->Dpc != (ULONG_PTR)TimerObjectPointer->Dpc)
	{
		KdPrint(("IntegrityCheck::TimerChecker: KTIMER->Dpc structure pointer was manipulated: TimerInfo->Dpc: 0x%p and TimerObjectPointer->Dpc: 0x%p\n", TimerInfo->Dpc, TimerObjectPointer->Dpc));
		return FALSE;
	}

	// Verifying that the DPC's routine wasn't manipulated 
	/*if (TimerInfo->DeferredRoutine != TimerObjectPointer->Dpc->DeferredRoutine)
	{
		KdPrint(("IntegrityCheck::TimerChecker: DPC's Routine was manipulated: TimerInfo->DeferredRoutine: 0x%p and TimerObjectPointer->Dpc->DeferredRoutine: 0x%p\n", TimerInfo->DeferredRoutine, TimerObjectPointer->Dpc->DeferredRoutine));
		return FALSE;
	}*/
	return TRUE;
}

VOID IntegrityCheck::InitializeDPC(PKTIMER Timer, PKDPC Dpc, PVOID DeferredRoutine, PVOID DeferredContext)
{

	KdPrint(("IntegrityCheck::InitializeDPC: Timer pointer: 0x%p\n", Timer));
	KdPrint(("IntegrityCheck::InitializeDPC: Dpc pointer: 0x%p\n", Dpc));
	KdPrint(("IntegrityCheck::InitializeDPC: DeferredRoutine pointer: 0x%p\n", DeferredRoutine));
	KdPrint(("IntegrityCheck::InitializeDPC: DeferredContext pointer: 0x%p\n", DeferredContext));

	LARGE_INTEGER DueTime;
	DueTime.QuadPart = -5 * 10 * 1000 * 1000;	// 5 seconds
	LONG Period = 2 * 1000;						// 2 seconds interval

	KeInitializeDpc(Dpc, (PKDEFERRED_ROUTINE)DeferredRoutine, DeferredContext);
	if (!Dpc->DeferredRoutine)
	{
		KdPrint(("IntegrityCheck::InitializeDPC: Failed to initialize DPC\n"));
		return;
	}

	if (!KeSetTimerEx(Timer, DueTime, Period, Dpc))
	{
		KdPrint(("[*] IntegrityCheck::InitializeDPCs: _KTIMER object at address: 0x%p was setted successfully with its associated DPC\n", Timer));
		return;
	}

	KdPrint(("[*] IntegrityCheck::InitializeDPCs: Failed to set _KTIMER object at address: 0x%p\n", Timer));
	KeCancelTimer(Timer);
}

VOID IntegrityCheck::DPCIntegrityCheckIDT(
	PKDPC Dpc,
	PVOID DeferredContext,		// PKTIMER TimerObjectPointer + PTIMER_INFO TimerInfo 
	PVOID SystemArgument1,
	PVOID SystemArgument2)
{
	KdPrint(("[*] IntegrityCheck::DPCIntegrityCheckIDT Invoked!!\n"));
	PDeferredContextDPC DeferredStruct = (PDeferredContextDPC)DeferredContext;

	KIRQL OldIrql;
	KeRaiseIrql(HIGH_LEVEL, &OldIrql); // Rising IRQL to HIGH_LEVEL

	if(!TimerChecker(DeferredStruct->TimerObjectPointer, DeferredStruct->TimerInfo))
	{
		KdPrint(("IntegrityCheck::DPCIntegrityCheckIDT: PatchGuard's IDT Timer's DPC was manipulated!\n"));
		KeLowerIrql(OldIrql);

		//0xC7: TIMER_OR_DPC_INVALID 
		/*KeBugCheckEx(
			TIMER_OR_DPC_INVALID,
			(ULONG_PTR)DeferredStruct->TimerInfo->Dpc,
			(ULONG_PTR)DeferredStruct->TimerObjectPointer,
			(ULONG_PTR)((ULONG_PTR)DeferredStruct->TimerObjectPointer+sizeof(_KTIMER)),
			0x1);*/
		return;
	}
	KdPrint(("IntegrityCheck::DPCIntegrityCheckIDT: PatchGuard's IDT Timer's DPC is valid!\n"));

	KeLowerIrql(OldIrql);
}

//VOID IntegrityCheck::DPCIntegrityCheckSSDT(
//	PKDPC Dpc,
//	PVOID DeferredContext,		// PKTIMER TimerObjectPointer + PTIMER_INFO TimerInfo 
//	PVOID SystemArgument1,
//	PVOID SystemArgument2)
//{
//	KdPrint(("[*] IntegrityCheck::DPCIntegrityCheckSSDT Invoked!!\n"));
//	PDeferredContextDPC DeferredStruct = (PDeferredContextDPC)DeferredContext;
//
//	KIRQL OldIrql;
//	KeRaiseIrql(HIGH_LEVEL, &OldIrql); // Rising IRQL to HIGH_LEVEL
//
//	if (!TimerChecker(DeferredStruct->TimerObjectPointer, DeferredStruct->TimerInfo))
//	{
//		KdPrint(("IntegrityCheck::DPCIntegrityCheckSSDT: PatchGuard's SSDT Timer's DPC was manipulated!\n"));
//		KeLowerIrql(OldIrql);
//
//		//0xC7: TIMER_OR_DPC_INVALID 
//		/*KeBugCheckEx(
//			TIMER_OR_DPC_INVALID,
//			(ULONG_PTR)DeferredStruct->TimerInfo->Dpc,
//			(ULONG_PTR)DeferredStruct->TimerObjectPointer,
//			(ULONG_PTR)((ULONG_PTR)DeferredStruct->TimerObjectPointer+sizeof(_KTIMER)),
//			0x1);*/
//		return;
//	}
//	KdPrint(("IntegrityCheck::DPCIntegrityCheckSSDT: PatchGuard's SSDT Timer's DPC is valid!\n"));
//
//	KeLowerIrql(OldIrql);
//}

IntegrityCheck::~IntegrityCheck()
{
	KdPrint(("[*] PatchGuardEncryptorDriver::~IntegrityCheck Destructor invoked!\n"));
	if (CancelVerifierTimer(&TimerVerifierIDT)){
		KdPrint(("[*] PatchGuardEncryptorDriver::~IntegrityCheck: TimerVerifierIDT at address: 0x%p was cancelled successfully!\n", &TimerVerifierIDT));
	}

	else{
		KdPrint(("[*] PatchGuardEncryptorDriver::~IntegrityCheck: TimerVerifierIDT wasn't initialized!\n"));
	}

	//if (CancelVerifierTimer(&TimerVerifierSSDT)){
	//	KdPrint(("[*] PatchGuardEncryptorDriver::~IntegrityCheck: TimerVerifierSSDT at address: 0x%p was cancelled successfully!\n", &TimerVerifierSSDT));
	//}

	//else{
	//	KdPrint(("[*] PatchGuardEncryptorDriver::~IntegrityCheck: TimerVerifierSSDT wasn't initialized!\n"));
	//}


	//if (CancelVerifierTimer(&TimerVerifierMSR)){
	//	KdPrint(("[*] PatchGuardEncryptorDriver::~IntegrityCheck: TimerVerifierMSR at address: 0x%p was cancelled successfully!\n", &TimerVerifierMSR));
	//}
	//else{
	//	KdPrint(("[*] PatchGuardEncryptorDriver::~IntegrityCheck: TimerVerifierMSR wasn't initialized!\n"));
	//}

	if (g_DefferedContext){
		KdPrint(("[*] PatchGuardEncryptorDriver::~IntegrityCheck: successfully freed g_DefferedContext in address: 0x%p\n", g_DefferedContext));
		ExFreePool(g_DefferedContext);
	}

}