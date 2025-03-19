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


BOOLEAN g_IsInitial_IDT = TRUE;
BOOLEAN g_IsInitial_MSRs = TRUE;
PIDT_ENTRY g_InitialIDTEntries;
PMSR_ENTRY g_InitialMSRs;

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

	if (g_IsInitial_IDT)
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

		g_IsInitial_IDT = FALSE;
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

	/*
	ULONG_PTR IA32_VMX_BASIC = __readmsr(MSR_IA32_VMX_BASIC);
	ULONG_PTR IA32_VMX_PINBASED_CTLS = __readmsr(MSR_IA32_VMX_PINBASED_CTLS);
	ULONG_PTR IA32_VMX_PROCBASED_CTLS = __readmsr(MSR_IA32_VMX_PROCBASED_CTLS);
	ULONG_PTR IA32_VMX_EXIT_CTLS = __readmsr(MSR_IA32_VMX_EXIT_CTLS);
	ULONG_PTR IA32_VMX_ENTRY_CTLS = __readmsr(MSR_IA32_VMX_ENTRY_CTLS);
	ULONG_PTR IA32_VMX_MISC = __readmsr(MSR_IA32_VMX_MISC);
	ULONG_PTR IA32_VMX_CR0_FIXED0 = __readmsr(MSR_IA32_VMX_CR0_FIXED0);
	ULONG_PTR IA32_VMX_CR0_FIXED1 = __readmsr(MSR_IA32_VMX_CR0_FIXED1);
	ULONG_PTR IA32_VMX_CR4_FIXED0 = __readmsr(MSR_IA32_VMX_CR4_FIXED0);
	ULONG_PTR IA32_VMX_CR4_FIXED1 = __readmsr(MSR_IA32_VMX_CR4_FIXED1);
	ULONG_PTR IA32_VMX_VMCS_ENUM = __readmsr(MSR_IA32_VMX_VMCS_ENUM);
	ULONG_PTR IA32_VMX_PROCBASED_CTLS2 = __readmsr(MSR_IA32_VMX_PROCBASED_CTLS2);
	ULONG_PTR IA32_VMX_EPT_VPID_CAP = __readmsr(MSR_IA32_VMX_EPT_VPID_CAP);

	ULONG_PTR EFER = __readmsr(MSR_EFER);
	ULONG_PTR STAR = __readmsr(MSR_STAR);
	ULONG_PTR LSTAR = __readmsr(MSR_LSTAR);
	ULONG_PTR CSTAR = __readmsr(MSR_CSTAR);
	ULONG_PTR SYSCALL_MASK = __readmsr(MSR_SYSCALL_MASK);
	ULONG_PTR FS_BASE = __readmsr(MSR_FS_BASE);
	ULONG_PTR GS_BASE = __readmsr(MSR_GS_BASE);
	ULONG_PTR KERNEL_GS_BASE = __readmsr(MSR_KERNEL_GS_BASE);

	ULONG_PTR IA32_APICBASE = __readmsr(MSR_IA32_APICBASE);
	ULONG_PTR IA32_APICBASE_BSP = __readmsr(MSR_IA32_APICBASE_BSP);
	ULONG_PTR IA32_APICBASE_ENABLE = __readmsr(MSR_IA32_APICBASE_ENABLE);
	ULONG_PTR IA32_APICBASE_BASE = __readmsr(MSR_IA32_APICBASE_BASE);
	*/

	if(g_IsInitial_MSRs)
	{
		g_InitialMSRs[0].MSRIndex = MSR_IA32_VMX_BASIC;
		g_InitialMSRs[0].MSRValue = __readmsr(MSR_IA32_VMX_BASIC);

		g_InitialMSRs[1].MSRIndex = MSR_IA32_VMX_PINBASED_CTLS;
		g_InitialMSRs[1].MSRValue = __readmsr(MSR_IA32_VMX_PINBASED_CTLS);

		g_InitialMSRs[2].MSRIndex = MSR_IA32_VMX_PROCBASED_CTLS;
		g_InitialMSRs[2].MSRValue = __readmsr(MSR_IA32_VMX_PROCBASED_CTLS);

		g_InitialMSRs[3].MSRIndex = MSR_IA32_VMX_EXIT_CTLS;
		g_InitialMSRs[3].MSRValue = __readmsr(MSR_IA32_VMX_EXIT_CTLS);

		g_InitialMSRs[4].MSRIndex = MSR_IA32_VMX_ENTRY_CTLS;
		g_InitialMSRs[4].MSRValue = __readmsr(MSR_IA32_VMX_ENTRY_CTLS);

		g_InitialMSRs[5].MSRIndex = MSR_IA32_VMX_MISC;
		g_InitialMSRs[5].MSRValue = __readmsr(MSR_IA32_VMX_MISC);

		g_InitialMSRs[6].MSRIndex = MSR_IA32_VMX_CR0_FIXED0;
		g_InitialMSRs[6].MSRValue = __readmsr(MSR_IA32_VMX_CR0_FIXED0);

		g_InitialMSRs[7].MSRIndex = MSR_IA32_VMX_CR0_FIXED1;
		g_InitialMSRs[7].MSRValue = __readmsr(MSR_IA32_VMX_CR0_FIXED1);

		g_InitialMSRs[8].MSRIndex = MSR_IA32_VMX_CR4_FIXED0;
		g_InitialMSRs[8].MSRValue = __readmsr(MSR_IA32_VMX_CR4_FIXED0);

		g_InitialMSRs[9].MSRIndex = MSR_IA32_VMX_CR4_FIXED1;
		g_InitialMSRs[9].MSRValue = __readmsr(MSR_IA32_VMX_CR4_FIXED1);

		g_InitialMSRs[10].MSRIndex = MSR_IA32_VMX_VMCS_ENUM;
		g_InitialMSRs[10].MSRValue = __readmsr(MSR_IA32_VMX_VMCS_ENUM);

		g_InitialMSRs[11].MSRIndex = MSR_IA32_VMX_PROCBASED_CTLS2;
		g_InitialMSRs[11].MSRValue = __readmsr(MSR_IA32_VMX_PROCBASED_CTLS2);

		g_InitialMSRs[12].MSRIndex = MSR_IA32_VMX_EPT_VPID_CAP;
		g_InitialMSRs[12].MSRValue = __readmsr(MSR_IA32_VMX_EPT_VPID_CAP);

		g_InitialMSRs[13].MSRIndex = MSR_EFER;
		g_InitialMSRs[13].MSRValue = __readmsr(MSR_EFER);

		g_InitialMSRs[14].MSRIndex = MSR_STAR;
		g_InitialMSRs[14].MSRValue = __readmsr(MSR_STAR);

		g_InitialMSRs[15].MSRIndex = MSR_LSTAR;
		g_InitialMSRs[15].MSRValue = __readmsr(MSR_LSTAR);

		g_InitialMSRs[16].MSRIndex = MSR_CSTAR;
		g_InitialMSRs[16].MSRValue = __readmsr(MSR_CSTAR);

		g_InitialMSRs[17].MSRIndex = MSR_FS_BASE;
		g_InitialMSRs[17].MSRValue = __readmsr(MSR_FS_BASE);

		g_InitialMSRs[18].MSRIndex = MSR_GS_BASE;
		g_InitialMSRs[18].MSRValue = __readmsr(MSR_GS_BASE);

		g_InitialMSRs[19].MSRIndex = MSR_KERNEL_GS_BASE;
		g_InitialMSRs[19].MSRValue = __readmsr(MSR_KERNEL_GS_BASE);

		g_InitialMSRs[20].MSRIndex = MSR_IA32_APICBASE;
		g_InitialMSRs[20].MSRValue = __readmsr(MSR_IA32_APICBASE);

		g_InitialMSRs[21].MSRIndex = MSR_IA32_APICBASE_BSP;
		g_InitialMSRs[21].MSRValue = __readmsr(MSR_IA32_APICBASE_BSP);

		g_InitialMSRs[22].MSRIndex = MSR_IA32_APICBASE_ENABLE;
		g_InitialMSRs[22].MSRValue = __readmsr(MSR_IA32_APICBASE_ENABLE);

		g_InitialMSRs[23].MSRIndex = MSR_IA32_APICBASE_BASE;
		g_InitialMSRs[23].MSRValue = __readmsr(MSR_IA32_APICBASE_BASE);	

		g_InitialMSRs[24].MSRIndex = MSR_SYSCALL_MASK;
		g_InitialMSRs[24].MSRValue = __readmsr(MSR_SYSCALL_MASK);

		KdPrint(("PatchGuardEncryptor::EnumerateMSR: successfully filled g_InitialMSRs at base address: 0x%p\n", g_InitialMSRs));

		g_IsInitial_MSRs = FALSE;
		return;
	}


	// Verify if each "if" statement compares with the correct index!!

	if(g_InitialMSRs[0].MSRValue != __readmsr(MSR_IA32_VMX_BASIC))
	{
		KdPrint(("MSR_IA32_VMX_BASIC (0x%x) was changed!\n", MSR_IA32_VMX_BASIC));
		//KeBugCheckEx(CRITICAL_STRUCTURE_CORRUPTION, 0, 0, 0, 0x2); //0x7 = A critical MSR modification
	}

	if (g_InitialMSRs[1].MSRValue != __readmsr(MSR_IA32_VMX_PINBASED_CTLS))
	{
		KdPrint(("MSR_IA32_VMX_PINBASED_CTLS (0x%x) was changed!\n", MSR_IA32_VMX_PINBASED_CTLS));
		//KeBugCheckEx(CRITICAL_STRUCTURE_CORRUPTION, 0, 0, 0, 0x2); //0x7 = A critical MSR modification
	}

	if (g_InitialMSRs[2].MSRValue != __readmsr(MSR_IA32_VMX_PROCBASED_CTLS))
	{
		KdPrint(("MSR_IA32_VMX_PROCBASED_CTLS (0x%x) was changed!\n", MSR_IA32_VMX_PROCBASED_CTLS));
		//KeBugCheckEx(CRITICAL_STRUCTURE_CORRUPTION, 0, 0, 0, 0x2); //0x7 = A critical MSR modification
	}

	if (g_InitialMSRs[3].MSRValue != __readmsr(MSR_IA32_VMX_EXIT_CTLS))
	{
		KdPrint(("MSR_IA32_VMX_EXIT_CTLS (0x%x) was changed!\n", MSR_IA32_VMX_EXIT_CTLS));
		//KeBugCheckEx(CRITICAL_STRUCTURE_CORRUPTION, 0, 0, 0, 0x2); //0x7 = A critical MSR modification
	}

	if (g_InitialMSRs[4].MSRValue != __readmsr(MSR_IA32_VMX_ENTRY_CTLS))
	{
		KdPrint(("MSR_IA32_VMX_ENTRY_CTLS (0x%x) was changed!\n", MSR_IA32_VMX_ENTRY_CTLS));
		//KeBugCheckEx(CRITICAL_STRUCTURE_CORRUPTION, 0, 0, 0, 0x2); //0x7 = A critical MSR modification
	}

	if (g_InitialMSRs[5].MSRValue != __readmsr(MSR_IA32_VMX_MISC))
	{
		KdPrint(("MSR_IA32_VMX_MISC (0x%x) was changed!\n", MSR_IA32_VMX_MISC));
		//KeBugCheckEx(CRITICAL_STRUCTURE_CORRUPTION, 0, 0, 0, 0x2); //0x7 = A critical MSR modification
	}

	if (g_InitialMSRs[6].MSRValue != __readmsr(MSR_IA32_VMX_CR0_FIXED0))
	{
		KdPrint(("MSR_IA32_VMX_CR0_FIXED0 (0x%x) was changed!\n", MSR_IA32_VMX_CR0_FIXED0));
		//KeBugCheckEx(CRITICAL_STRUCTURE_CORRUPTION, 0, 0, 0, 0x2); //0x7 = A critical MSR modification
	}

	if (g_InitialMSRs[7].MSRValue != __readmsr(MSR_IA32_VMX_CR0_FIXED1))
	{
		KdPrint(("MSR_IA32_VMX_CR0_FIXED1 (0x%x) was changed!\n", MSR_IA32_VMX_CR0_FIXED1));
		//KeBugCheckEx(CRITICAL_STRUCTURE_CORRUPTION, 0, 0, 0, 0x2); //0x7 = A critical MSR modification
	}

	if (g_InitialMSRs[8].MSRValue != __readmsr(MSR_IA32_VMX_CR4_FIXED0))
	{
		KdPrint(("MSR_IA32_VMX_CR4_FIXED0 (0x%x) was changed!\n", MSR_IA32_VMX_CR4_FIXED0));
		//KeBugCheckEx(CRITICAL_STRUCTURE_CORRUPTION, 0, 0, 0, 0x2); //0x7 = A critical MSR modification
	}

	if (g_InitialMSRs[9].MSRValue != __readmsr(MSR_IA32_VMX_CR4_FIXED1))
	{
		KdPrint(("MSR_IA32_VMX_CR4_FIXED1 (0x%x) was changed!\n", MSR_IA32_VMX_CR4_FIXED1));
		//KeBugCheckEx(CRITICAL_STRUCTURE_CORRUPTION, 0, 0, 0, 0x2); //0x7 = A critical MSR modification
	}

	if (g_InitialMSRs[10].MSRValue != __readmsr(MSR_IA32_VMX_VMCS_ENUM))
	{
		KdPrint(("MSR_IA32_VMX_VMCS_ENUM (0x%x) was changed!\n", MSR_IA32_VMX_VMCS_ENUM));
		//KeBugCheckEx(CRITICAL_STRUCTURE_CORRUPTION, 0, 0, 0, 0x2); //0x7 = A critical MSR modification
	}

	if (g_InitialMSRs[11].MSRValue != __readmsr(MSR_IA32_VMX_PROCBASED_CTLS2))
	{
		KdPrint(("MSR_IA32_VMX_PROCBASED_CTLS2 (0x%x) was changed!\n", MSR_IA32_VMX_PROCBASED_CTLS2));
		//KeBugCheckEx(CRITICAL_STRUCTURE_CORRUPTION, 0, 0, 0, 0x2); //0x7 = A critical MSR modification
	}

	if (g_InitialMSRs[12].MSRValue != __readmsr(MSR_IA32_VMX_EPT_VPID_CAP))
	{
		KdPrint(("MSR_IA32_VMX_EPT_VPID_CAP (0x%x) was changed!\n", MSR_IA32_VMX_EPT_VPID_CAP));
		//KeBugCheckEx(CRITICAL_STRUCTURE_CORRUPTION, 0, 0, 0, 0x2); //0x7 = A critical MSR modification
	}

	if (g_InitialMSRs[13].MSRValue != MSR_EFER)
	{
		KdPrint(("MSR_EFER (0x%x) was changed!\n", MSR_EFER));
		//KeBugCheckEx(CRITICAL_STRUCTURE_CORRUPTION, 0, 0, 0, 0x2); //0x7 = A critical MSR modification
	}

	if (g_InitialMSRs[14].MSRValue != __readmsr(MSR_STAR))
	{
		KdPrint(("MSR_STAR (0x%x) was changed!\n", MSR_STAR));
		//KeBugCheckEx(CRITICAL_STRUCTURE_CORRUPTION, 0, 0, 0, 0x2); //0x7 = A critical MSR modification
	}

	if (g_InitialMSRs[15].MSRValue != __readmsr(MSR_LSTAR))
	{
		KdPrint(("MSR_LSTAR (0x%x) was changed!\n", MSR_LSTAR));
		//KeBugCheckEx(CRITICAL_STRUCTURE_CORRUPTION, 0, 0, 0, 0x2); //0x7 = A critical MSR modification
	}

	if (g_InitialMSRs[16].MSRValue != __readmsr(MSR_CSTAR))
	{
		KdPrint(("MSR_CSTAR (0x%x) was changed!\n", MSR_CSTAR));
		//KeBugCheckEx(CRITICAL_STRUCTURE_CORRUPTION, 0, 0, 0, 0x2); //0x7 = A critical MSR modification
	}

	if (g_InitialMSRs[17].MSRValue != __readmsr(MSR_FS_BASE))
	{
		KdPrint(("MSR_FS_BASE (0x%x) was changed!\n", MSR_FS_BASE));
		//KeBugCheckEx(CRITICAL_STRUCTURE_CORRUPTION, 0, 0, 0, 0x2); //0x7 = A critical MSR modification
	}

	if (g_InitialMSRs[18].MSRValue != __readmsr(MSR_GS_BASE))
	{
		KdPrint(("MSR_GS_BASE (0x%x) was changed!\n", MSR_GS_BASE));
		//KeBugCheckEx(CRITICAL_STRUCTURE_CORRUPTION, 0, 0, 0, 0x2); //0x7 = A critical MSR modification
	}

	if (g_InitialMSRs[19].MSRValue != __readmsr(MSR_KERNEL_GS_BASE))
	{
		KdPrint(("MSR_KERNEL_GS_BASE (0x%x) was changed!\n", MSR_KERNEL_GS_BASE));
		//KeBugCheckEx(CRITICAL_STRUCTURE_CORRUPTION, 0, 0, 0, 0x2); //0x7 = A critical MSR modification
	}

	if (g_InitialMSRs[20].MSRValue != __readmsr(MSR_IA32_APICBASE))
	{
		KdPrint(("MSR_IA32_APICBASE (0x%x) was changed!\n", MSR_IA32_APICBASE));
		//KeBugCheckEx(CRITICAL_STRUCTURE_CORRUPTION, 0, 0, 0, 0x2); //0x7 = A critical MSR modification
	}

	if (g_InitialMSRs[21].MSRValue != __readmsr(MSR_IA32_APICBASE_BSP))
	{
		KdPrint(("MSR_IA32_APICBASE_BSP (0x%x) was changed!\n", MSR_IA32_APICBASE_BSP));
		//KeBugCheckEx(CRITICAL_STRUCTURE_CORRUPTION, 0, 0, 0, 0x2); //0x7 = A critical MSR modification
	}

	if (g_InitialMSRs[22].MSRValue != __readmsr(MSR_IA32_APICBASE_ENABLE))
	{
		KdPrint(("MSR_IA32_APICBASE_ENABLE (0x%x) was changed!\n", MSR_IA32_APICBASE_ENABLE));
		//KeBugCheckEx(CRITICAL_STRUCTURE_CORRUPTION, 0, 0, 0, 0x2); //0x7 = A critical MSR modification
	}

	if (g_InitialMSRs[23].MSRValue != __readmsr(MSR_IA32_APICBASE_BASE))
	{
		KdPrint(("MSR_IA32_APICBASE_BASE (0x%x) was changed!\n", MSR_IA32_APICBASE_BASE));
		//KeBugCheckEx(CRITICAL_STRUCTURE_CORRUPTION, 0, 0, 0, 0x2); //0x7 = A critical MSR modification
	}


	if (g_InitialMSRs[24].MSRValue != __readmsr(MSR_SYSCALL_MASK))
	{
		KdPrint(("MSR_IA32_APICBASE_BASE (0x%x) was changed!\n", MSR_IA32_APICBASE_BASE));
		//KeBugCheckEx(CRITICAL_STRUCTURE_CORRUPTION, 0, 0, 0, 0x2); //0x7 = A critical MSR modification
	}
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
		KdPrint(("PatchGuardEncryptor::DriverEntry: Allocating with ExAllocatePool() failed! g_InitialIDTEntries: 0x%p\n", g_InitialIDTEntries));
		//status = STATUS_INSUFFICIENT_RESOURCES;
		UnloadRoutine(DriverObject); // Need to verify if it's valid. I execute the UnloadRoutine() because for some reason
									 // the driver and the device object allocated can't be unloaded from kernel space if the status isn't STATUS_SUCCESS.
		return status;
	}

	KdPrint(("Allocated an array in non-paged pool of 256 IDT_ENTRY structures at address: 0x%p\n", g_InitialIDTEntries));

	g_InitialMSRs = (PMSR_ENTRY)ExAllocatePool(NonPagedPool, 27 * sizeof(MSR_ENTRY)); // There are actually 26 MSRs being check, but rounding the allocation to 27 for safety.
	if(!g_InitialMSRs)
	{
		KdPrint(("PatchGuardEncryptor::DriverEntry: Allocating with ExAllocatePool() failed! g_InitialMSRs: 0x%p\n", g_InitialMSRs));
		//status = STATUS_INSUFFICIENT_RESOURCES;
		UnloadRoutine(DriverObject); // Need to verify if it's valid. I execute the UnloadRoutine() because for some reason
		// the driver and the device object allocated can't be unloaded from kernel space if the status isn't STATUS_SUCCESS.
		return status;
	}

	KdPrint(("Allocated an array in non-paged pool of 256 MSR_ENTRY structures at address: 0x%p\n", g_InitialMSRs));


	EnumerateIDT(); // This is supposed to be executed both in the DriverEntry and both in the IDT DPC

	//// Timer causes a BSOD!!! WITH KERNEL_SECURITY_CHECK bugcheck
	//KeInitializeDpc(&DPC_IDT, (PKDEFERRED_ROUTINE)DPCInterruptDispatchTable, nullptr);
	
	//LARGE_INTEGER DueTime;
	//DueTime.QuadPart = -10000 * 10; // check

	//KeInitializeTimer(&TimerIDT);
	//KeSetTimer(&TimerIDT, DueTime, &DPC_IDT);
	
	return status;
}