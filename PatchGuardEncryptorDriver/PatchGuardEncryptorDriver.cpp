#include <ntddk.h>
#include <intrin.h>
#include "Helper.h"
#include "intrin.h"
#include "MSRs.h"

#pragma warning(push)
#pragma warning(disable: 4244)  // Disable specific warning
#pragma warning(disable: 4293)	// Disable specific warning
#pragma warning(disable: 4201)	// Disable specific warning
#pragma warning(disable: 4996)	// Disable specific warning


BOOLEAN g_IsInitial = TRUE;
PIDT_ENTRY g_InitialIDTEntries;
PIDT_ENTRY g_DPC_IDTEntries;	// Might not be needed
int g_MaxVectorNumber = 0;

NTSTATUS CompleteRequest(PIRP Irp, NTSTATUS status, ULONG information)
{
	Irp->IoStatus.Information = information;
	Irp->IoStatus.Status = status;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return status;
}

NTSTATUS CreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	return CompleteRequest(Irp, STATUS_SUCCESS, 0);
}

VOID UnloadRoutine(PDRIVER_OBJECT DriverObject)
{
	PDEVICE_OBJECT Device = DriverObject->DeviceObject;
	UNICODE_STRING DeviceSymlink = RTL_CONSTANT_STRING(L"\\??\\PatchGuardEncryptor");

	IoDeleteDevice(Device);
	IoDeleteSymbolicLink(&DeviceSymlink);

	if(g_InitialIDTEntries)
	{
		ExFreePool(g_InitialIDTEntries);
		KdPrint(("PatchGuardEncryptor::UnloadRoutine: released Allocted IDT Entries copy allocated from non paged pool!\n"));
	}

	KdPrint(("PatchGuardEncryptor::UnloadRoutine: Driver unloaded successfully!\n"));
}

VOID NTAPI EnumerateIDT()
{

	PKPCR CurrentKPCR = (PKPCR)__readgsqword(0x18);
	PVOID CurrentPrcb = CurrentKPCR->CurrentPrcb;
	PVOID IdtBaseAddress = (PVOID)CurrentKPCR->IdtBase;

	KdPrint(("PatchGuardEncryptor::EnumerateIDT: _KPCR Base Address: 0x%p\n", CurrentKPCR));
	KdPrint(("PatchGuardEncryptor::EnumerateIDT: _KPRCB Base Address: 0x%p\n", CurrentPrcb));
	KdPrint(("PatchGuardEncryptor::EnumerateIDT: _KPCR.IdtBase Base Address: 0x%p\n", IdtBaseAddress));

	// taken from reversing nt!KiGetGdtIdt()
	//PVOID IDT_BaseAddress2;
	//__sidt(&IDT_BaseAddress2); // stores the value in the IDTR register <- For testing purposes only!
	//KdPrint(("PatchGuardEncryptor::EnumerateIDT: IdtBase Base Address from __sidt instruction: 0x%p\n", IdtBaseAddress));

	_KIDTENTRY64* IDTEntry = (_KIDTENTRY64*)(IdtBaseAddress);

	if (g_IsInitial)
	{
		for(int i = 0; i < 256; i++)
		{
			_KIDTENTRY64* IDTEntry = (_KIDTENTRY64*)((ULONG_PTR)IdtBaseAddress + (0x10 * i));
			KdPrint(("IDTEntry: 0x%p\n", IDTEntry));
			if(*(ULONG_PTR*)IDTEntry == 0x0 && *(ULONG_PTR*)((CHAR*)IDTEntry+0x8) == 0)
			{
				KdPrint(("[*] PatchGuardEncryptor::EnumerateIDT: Finished running on the Interrupt Dispatch Table\n"));
				break;
			}

			ULONG_PTR High = *(DWORD32*)((CHAR*)IDTEntry + 8);		// Using IDTEntry->OffsetHigh returned a false value
			ULONG_PTR Middle = *(USHORT*)((CHAR*)IDTEntry + 6);		// Using IDTEntry->OffsetMedium returned a false value
			ULONG_PTR Low = IDTEntry->OffsetLow;

			ULONG_PTR ServiceRoutine = High << 32;
			ServiceRoutine = ServiceRoutine ^ (Middle << 16);
			ServiceRoutine = ServiceRoutine ^ Low;

			g_InitialIDTEntries[i].ServiceRoutine = (PVOID)ServiceRoutine;
			g_InitialIDTEntries[i].Vector = i;
			g_MaxVectorNumber++;

			KdPrint(("g_InitialIDTEntries[%d].Vector: 0%x | IDT_ENTRY[%x].ServiceRoutine: 0x%p\n", i, g_InitialIDTEntries[i].Vector, i, g_InitialIDTEntries[i].ServiceRoutine));
		}		

		g_IsInitial = FALSE;
		return;
	}

	if(*(PVOID*)g_InitialIDTEntries || *(PVOID*)(g_InitialIDTEntries+0x8))	// Verifying that at least the first entry or the second entry the value isn't 0
	{

		KdPrint(("PatchGuardEncryptor: IDTEntry at second if 0x%p\n", IDTEntry));
		for (int i = 0; i < g_MaxVectorNumber; i++)
		{
			_KIDTENTRY64* IDTEntry = (_KIDTENTRY64*)((ULONG_PTR)IdtBaseAddress + (0x10 * i));

			ULONG_PTR High = *(DWORD32*)((CHAR*)IDTEntry + 8);		
			ULONG_PTR Middle = *(USHORT*)((CHAR*)IDTEntry + 6);	
			ULONG_PTR Low = IDTEntry->OffsetLow;
	
			ULONG_PTR ServiceRoutine = High << 32;
			ServiceRoutine = ServiceRoutine ^ (Middle << 16);
			ServiceRoutine = ServiceRoutine ^ Low;
	
			KdPrint(("PatchGuardEncryptor::EnumerateIDT: Comparing Service Routine[%d]: 0x%p with g_InitialIDTEntries[%d].ServiceRoutine: 0x%p\n", i, ServiceRoutine, i, g_InitialIDTEntries[i].ServiceRoutine));
			if ((PVOID)ServiceRoutine != g_InitialIDTEntries[i].ServiceRoutine)
			{
				/*
				 Which BugCheck to use: https://www.geoffchappell.com/studies/windows/km/bugchecks/index.htm
					  				    https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-0x109---critical-structure-corruption
				*/

				//KeBugCheckEx(CRITICAL_STRUCTURE_CORRUPTION, 0, 0, 0, 0x2); // 0x2 = A processor interrupt dispatch table (IDT)
	
				//For testing purposes, instead of bugcheck, we'll use KdPrint() to print that a modification was detected
				KdPrint(("PatchGuardEncryptor::EnumerateIDT: IDT DPC detected a change in Vector: 0x%x\n", i));
				break;
			}
			KdPrint(("PatchGuardEncryptor: Vector 0x%x is verified\n", i));
		}
	}
}

VOID EnumerateMSRs()
{
	/*
		Captures MSR values that are supposed to be static
		and through a timer, this function will be executed as DPC routine with IRQL = DISPATCH_LEVEL 
		after each clock time of the timer is passed
	*/

	//Todo.. and allocate non-paged!! (since it's executed at IRQL >= 2 which means that no page faults are allowed)
	// pool memory using ExAllocatePool() and use the MSR_ENTRY structure to store the information
}


VOID DPCInterruptDispatchTable(_KDPC Dpc, PVOID DeferredContext, PVOID, PVOID)
{
	UNREFERENCED_PARAMETER(DeferredContext); // Might pass the base address of the IDT in the DeferredContext
	UNREFERENCED_PARAMETER(Dpc); 

	NT_ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);

	/*
	 Increases IRQL to HIGH_LEVEL (0xF) to avoid potential evasion from an attacker when overriding a function pointer
	 with a malicious function pointer that automatically increases the IRQL to HIGH_LEVEL and prevent the timer DPC from being invoked.
	 Since working in a HIGH_LEVEL IRQL is an expensive operation, it must to be minimal and effective.
	*/
	KIRQL CurrentIRQL;
	KeRaiseIrql(HIGH_LEVEL, &CurrentIRQL);

	EnumerateIDT();

	KeLowerIrql(CurrentIRQL); // Lowers IRQL to DISPATCH_LEVEL (0x2)
}


void * __cdecl operator new(size_t size, DWORD32 NumberOfAllocations, POOL_FLAGS PoolFlags, ULONG tag)
{
	return ExAllocatePool2(PoolFlags, size*NumberOfAllocations, tag);
}

extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(L"\\Device\\PatchGuardEncryptor");
	UNICODE_STRING DeviceSymlink = RTL_CONSTANT_STRING(L"\\??\\PatchGuardEncryptor");


	KTIMER TimerIDT;
	KDPC DPC_IDT;

	/*
	KTIMER TimerSSDT;
	KDPC DPC_SSDT;

	KTIMER TimerMSRs;
	KDPC DPC_MSRs;
	*/

	PDEVICE_OBJECT DeviceObject;
	NTSTATUS status = STATUS_SUCCESS;

	status = IoCreateDevice(DriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("[-]PatchGuardEncryptor::DriverEntry - Failed to created Device Object [0x%x]\n", status));
		return status;
	}

	status = IoCreateSymbolicLink(&DeviceSymlink, &DeviceName);
	if(!NT_SUCCESS(status))
	{
		KdPrint(("[-]PatchGuardEncryptor::DriverEntry - Failed to created Device symlink [0x%x]\n", status));
		IoDeleteDevice(DeviceObject);
	}

	DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateClose;
	DriverObject->DriverUnload = UnloadRoutine;

	// for each KeInitializeTimer() there need to be a call first to KeInitializeDpc() to create the DPC
	// that will verify it's target table (IDT, SSDT, etc...) and then call KeSetTimerEx()

	g_InitialIDTEntries = (PIDT_ENTRY)ExAllocatePool(NonPagedPool, sizeof(IDT_ENTRY) * 256);
	if(!g_InitialIDTEntries)
	{
		KdPrint(("PatchGuardEncryptor::DriverEntry: Allocating with ExAllocatePool2() failed! g_InitialIDTEntries: 0x%p\n", g_InitialIDTEntries));
		//return STATUS_INSUFFICIENT_RESOURCES;
		UnloadRoutine(DriverObject); // Need to verify if it's valid. I execute the UnloadRoutine() because for some reason
									 // the driver and the device object allocated can't be unloaded from kernel space if the status isn't STATUS_SUCCESS.
		return status;
	}

	KdPrint(("Allocated an array in non-paged pool of 256 IDT_ENTRY structures in: 0x%p\n", g_InitialIDTEntries));

	EnumerateIDT(); // This is supposed to be executed both in the DriverEntry and both in the IDT DPC

	//// Timer causes a BSOD!!! WITH KERNEL_SECURITY_CHECK bugcheck
	//KeInitializeDpc(&DPC_IDT, (PKDEFERRED_ROUTINE)DPCInterruptDispatchTable, nullptr);
	
	//LARGE_INTEGER DueTime;
	//DueTime.QuadPart = -10000 * 10; // check

	//KeInitializeTimer(&TimerIDT);
	//KeSetTimer(&TimerIDT, DueTime, &DPC_IDT);
	
	return status;
}