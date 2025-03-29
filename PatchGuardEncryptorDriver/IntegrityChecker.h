#pragma once
#include <ntddk.h>
#include "Helper.h"

/*
	This code will be responsible to verify that the timers haven't been modified in the following ways:
		- The DPCs haven't been patched (Verify that _KDPC->Dpc haven't been changed, DPC+0x18 is the function pointer to the
		  deferred routine.
		- Verify the _KTIMERs haven't been patched (especially the _KTIMER+0x30, which is the pointer to the DPC associated to the _KTIMER object
*/

typedef struct DeferredContextDPC
{
	PKTIMER TimerObjectPointer;
	PTIMER_INFO TimerInfo;
} DeferredContextDPC, * PDeferredContextDPC;

struct IntegrityCheck
{
	IntegrityCheck(PTIMER_INFO TimerInfoArr);
	~IntegrityCheck();

	BOOLEAN CancelVerifierTimer(PKTIMER Timer);
	VOID InitializeDPC(PKTIMER Timer, PKDPC Dpc, PVOID DeferredRoutine, PVOID DeferredContext);

	static VOID DPCIntegrityCheckIDT(_KDPC* Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2);
	static VOID DPCIntegrityCheckSSDT(_KDPC* Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2);
	static VOID DPCIntegrityCheckMSRs(_KDPC* Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2);

	static ULONG_PTR CalculateTimerDPCValue(PKDPC Dpc, PKTIMER KTimer);
	static BOOLEAN TimerChecker(PKTIMER TimerObjectPointer, PTIMER_INFO TimerInfo);

	KTIMER TimerVerifierSSDT;
	KTIMER TimerVerifierIDT;
	KTIMER TimerVerifierMSR;

	KDPC DPCVerifierSSDT;
	KDPC DPCVerifierIDT;
	KDPC DPCVerifierMSR;

	PTIMER_INFO TimerInfoArray;

	PDeferredContextDPC g_DefferedContext;
};