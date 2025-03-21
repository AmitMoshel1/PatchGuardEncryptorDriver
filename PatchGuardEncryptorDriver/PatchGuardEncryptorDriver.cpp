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
#pragma warning(disable: 6066)	// Disable specific warning
#pragma warning(disable: 4018)	// Disable specific warning

// Booleans that are used in each Enumerate (IDT,SSDT, MSRs) functions to determine first run and VMX state
BOOLEAN g_IsInitial_IDT = TRUE;
BOOLEAN g_IsInitial_MSRs = TRUE;
BOOLEAN g_CR4_VMXE_Enabled = FALSE;

PIDT_ENTRY	g_InitialIDTEntries;
PMSR_ENTRY	g_InitialMSRs;
PSSDT_ENTRY g_InitialSSDT;
ULONG_PTR	g_SystemInformation;
DWORD32		g_MaxVectorNumber = 0;

// Global Timer objects for each Patch Guard check
KTIMER TimerIDT;
KTIMER TimerSSDT;
KTIMER TimerMSRs;

// Global DPC objects for each Patch Guard Check
KDPC DPC_IDT;
KDPC DPC_SSDT;
KDPC DPC_MSRs;

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
		KdPrint(("[*] PatchGuardEncryptor::UnloadRoutine: successfully released Allocted IDT Entries copy allocated from non paged pool!\n"));
	}

	if(g_InitialMSRs)
	{
		ExFreePool(g_InitialMSRs);
		KdPrint(("[*] PatchGuardEncryptor::UnloadRoutine: successfully released Allocted MSR_ENTRY Entries allocated from non paged pool!\n"));
	}

	// Cancelling the PatchGuardEncryptorDriver timers - if it's already cancelled/unset, then nothing will happen
	if (KeCancelTimer(&TimerIDT))
		KdPrint(("[*] PatchGuardEncryptor::UnloadRoutine: IDT Timer was cancelled successfully!\n"));
	else
		KdPrint(("[*] PatchGuardEncryptor::UnloadRoutine: IDT Timer was not active.\n"));

	if (KeCancelTimer(&TimerMSRs))
		KdPrint(("[*] PatchGuardEncryptor::UnloadRoutine: MSRs Timer was cancelled successfully!\n"));
	else
		KdPrint(("[*] PatchGuardEncryptor::UnloadRoutine: MSRs Timer was not active.\n"));

	if (KeCancelTimer(&TimerSSDT))
		KdPrint(("[*] PatchGuardEncryptor::UnloadRoutine: SSDT Timer was cancelled successfully!\n"));
	else
		KdPrint(("[*] PatchGuardEncryptor::UnloadRoutine: SSDT Timer was not active.\n"));

	KdPrint(("[*] PatchGuardEncryptor::UnloadRoutine: Driver unloaded successfully!\n"));
}

PVOID GetNtosBaseAddress()
{
	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING NtQuerySystemInformationName = RTL_CONSTANT_STRING(L"NtQuerySystemInformation");
	typedef NTSTATUS (NTAPI * fNtQuerySytsemInformation)(SYSTEM_INFORMATION_CLASS SystemInformationClass,
		PVOID SystemInformation,
		ULONG SystemInformationLength,
		PULONG ReturnLength
		);

	fNtQuerySytsemInformation NtQuerySystemInformation = (fNtQuerySytsemInformation)MmGetSystemRoutineAddress(&NtQuerySystemInformationName);
	PVOID DummyMemory = ExAllocatePool(NonPagedPool, 1);
	if(!DummyMemory)
	{
		KdPrint(("[*] PatchGuardEncryptor::GetNtosBaseAddress: Unable to allocate DummyMemory!\n"));
		return 0;
	}
	ULONG ReturnLength;
	status = NtQuerySystemInformation(SystemModuleInformation, DummyMemory, 1, &ReturnLength);
	if(status == STATUS_INFO_LENGTH_MISMATCH)
	{

		PSYSTEM_MODULE_INFORMATION ModuleInformationMemory = (PSYSTEM_MODULE_INFORMATION)ExAllocatePool(NonPagedPool, ReturnLength);
		if (!ModuleInformationMemory) {
			KdPrint(("[*] PatchGuardEncryptor::GetNtosBaseAddress: Unable to allocate ModuleInformationMemory\n"));
			return 0;
		}
		status = NtQuerySystemInformation(SystemModuleInformation, ModuleInformationMemory, ReturnLength, nullptr);
		if(!NT_SUCCESS(status))
		{
			KdPrint(("[*] PatchGuardEncryptor::GetNtosBaseAddress: NtQuerySystemInformation failed with: 0x%x\n", status));
			return 0;
		}
		PVOID NtosBase = ModuleInformationMemory->Modules[0].ImageBase;
		return NtosBase;
	}
	return 0;
}

VOID NTAPI EnumerateIDT()
{
	PKPCR CurrentKPCR = (PKPCR)__readgsqword(0x18);
	PVOID CurrentPrcb = CurrentKPCR->CurrentPrcb;
	PVOID IdtBaseAddress = (PVOID)CurrentKPCR->IdtBase;

	KdPrint(("[*] PatchGuardEncryptor::EnumerateIDT: _KPCR Base Address: 0x%p\n", CurrentKPCR));
	KdPrint(("[*] PatchGuardEncryptor::EnumerateIDT: _KPRCB Base Address: 0x%p\n", CurrentPrcb));
	KdPrint(("[*] PatchGuardEncryptor::EnumerateIDT: _KPCR.IdtBase Base Address: 0x%p\n", IdtBaseAddress));

	// taken from reversing nt!KiGetGdtIdt()
	//PVOID IDT_BaseAddress2;
	//__sidt(&IDT_BaseAddress2); // stores the value in the IDTR register <- For testing purposes only!
	//KdPrint(("[*] PatchGuardEncryptor::EnumerateIDT: IdtBase Base Address from __sidt instruction: 0x%p\n", IdtBaseAddress));

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
		for (int i = 0; i < g_MaxVectorNumber; i++)
		{
			_KIDTENTRY64* IDTEntry = (_KIDTENTRY64*)((ULONG_PTR)IdtBaseAddress + (0x10 * i));

			ULONG_PTR High = *(DWORD32*)((CHAR*)IDTEntry + 8);		
			ULONG_PTR Middle = *(USHORT*)((CHAR*)IDTEntry + 6);	
			ULONG_PTR Low = IDTEntry->OffsetLow;
	
			ULONG_PTR ServiceRoutine = High << 32;
			ServiceRoutine = ServiceRoutine ^ (Middle << 16);
			ServiceRoutine = ServiceRoutine ^ Low;
	
			KdPrint(("[*] PatchGuardEncryptor::EnumerateIDT: Comparing Service Routine[%x]: 0x%p with g_InitialIDTEntries[%x].ServiceRoutine: 0x%p\n", i, ServiceRoutine, i, g_InitialIDTEntries[i].ServiceRoutine));
			if ((PVOID)ServiceRoutine != g_InitialIDTEntries[i].ServiceRoutine)
			{
				/*
				 Which BugCheck to use: https://www.geoffchappell.com/studies/windows/km/bugchecks/index.htm
					  				    https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-0x109---critical-structure-corruption
				*/

				//KeBugCheckEx(CRITICAL_STRUCTURE_CORRUPTION, 0, 0, 0, 0x2); // 0x2 = A processor interrupt dispatch table (IDT)
	
				//For testing purposes, instead of bugcheck, we'll use KdPrint() to print that a modification was detected
				KdPrint(("[*] PatchGuardEncryptor::EnumerateIDT: IDT DPC detected a change in Vector: 0x%x\n", i));
				break;
			}
			KdPrint(("[*] PatchGuardEncryptor: Vector 0x%x is verified\n", i));
		}
	}
}

VOID EnumerateSSDT() 
{
	/*
		The EnumerateSSDT function will first check if it's the first run using a global boolean variable that
		will be initially set to TRUE.

		If the boolean variable is TRUE:
		The function will set the boolean variable to false,
		and will contiue by dynamically resolving the address of nt!KiServiceTable and stroring it in a global variable.
		Next, initialize a while loop from nt!KiServiceTable base address and in each iteration will read 4 bytes 
		from the address, while the DWORD value read isn't 00000000, increment the SSDT Entries counter by one.
		This will be used to know how many SSDT_ENTRY structures to allocated in the non-paged pool using ExAllocatePool().

		The allocated pool base address will be stored in a global variable and will be freed in the UnloadRoutine().

		Next, A for loop will iterate over each SSDT entry and will allocate SSDT_ENTRY structure within the SSDT_ENTRY array
		allocated using ExAllocatePool().

		If the boolean is false, meaning it's isn't the first time the function runs.
		A for loop will iterate over each current value in the SSDT, and will dynamically compare the relative value with
		the current SSDT entry value, if it fails, a BSOD will be invoked!
	*/
}

VOID EnumerateMSRs()
{
	/*
		Captures MSR values that are supposed to be static
		and through a timer, this function will be executed as DPC routine with IRQL = DISPATCH_LEVEL 
		after each clock time of the timer is passed
	*/

	if(g_IsInitial_MSRs) // Checking if it's being executed from DriverEntry() when the driver is first being loaded in kernel space.
	{
		g_IsInitial_MSRs = FALSE;

		ULONG reg_cr4 = __readcr4();
		KdPrint(("CR4 value: 0x%x\n", reg_cr4));
		
		// CR4.VMXE (Virtual Machine Extension Enabled) is at index 13 
		// If CR4.VMXE = 1 -> VMX MSR registers will also be captured at initial run.
		if ((reg_cr4 & (1 << 13)) != 0x0) 
		{
			KdPrint(("[*] PatchGuardEncryptorDriver::EnumerateMSRs: CR4.VMXE = 0x1\n"));
			g_CR4_VMXE_Enabled = TRUE;
		
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

			g_InitialMSRs[21].MSRIndex = MSR_SYSCALL_MASK;
			g_InitialMSRs[21].MSRValue = __readmsr(MSR_SYSCALL_MASK);

			KdPrint(("[*] PatchGuardEncryptor::EnumerateMSR: CR4.VMXE=1 -> successfully filled g_InitialMSRs at base address: 0x%p\n", g_InitialMSRs));
			return;
		}

		g_InitialMSRs[0].MSRIndex = MSR_EFER;
		g_InitialMSRs[0].MSRValue = __readmsr(MSR_EFER);

		g_InitialMSRs[1].MSRIndex = MSR_STAR;
		g_InitialMSRs[1].MSRValue = __readmsr(MSR_STAR);

		g_InitialMSRs[2].MSRIndex = MSR_LSTAR;
		g_InitialMSRs[2].MSRValue = __readmsr(MSR_LSTAR);

		g_InitialMSRs[3].MSRIndex = MSR_CSTAR;
		g_InitialMSRs[3].MSRValue = __readmsr(MSR_CSTAR);

		g_InitialMSRs[4].MSRIndex = MSR_FS_BASE;
		g_InitialMSRs[4].MSRValue = __readmsr(MSR_FS_BASE);

		g_InitialMSRs[5].MSRIndex = MSR_GS_BASE;
		g_InitialMSRs[5].MSRValue = __readmsr(MSR_GS_BASE);

		g_InitialMSRs[6].MSRIndex = MSR_KERNEL_GS_BASE;
		g_InitialMSRs[6].MSRValue = __readmsr(MSR_KERNEL_GS_BASE);

		g_InitialMSRs[7].MSRIndex = MSR_IA32_APICBASE;
		g_InitialMSRs[7].MSRValue = __readmsr(MSR_IA32_APICBASE);

		g_InitialMSRs[8].MSRIndex = MSR_SYSCALL_MASK;
		g_InitialMSRs[8].MSRValue = __readmsr(MSR_SYSCALL_MASK);

		KdPrint(("[*] PatchGuardEncryptor::EnumerateMSR: CR4.VMXE=0 successfully filled g_InitialMSRs at base address: 0x%p\n", g_InitialMSRs));
		return;
	}

	// An MSR integrity check if the CR4.VXME bit is set to 1 (which means that the CPU supports VMX operations)
	// This check will include both the regular MSRs and also the VMX related MSRs
	if(g_CR4_VMXE_Enabled)
	{
		KdPrint(("[*] PatchGuardEncryptor::EnumerateMSRs: CR4.VMXE=1 -> Comparing current MSRs with initial MSRs\n"));

		// Verify if each "if" statement compares with the correct index!!
		if (g_InitialMSRs[0].MSRValue != __readmsr(MSR_IA32_VMX_BASIC))
		{
			KdPrint(("[*] MSR_IA32_VMX_BASIC (0x%x) was changed from: 0x%p to: 0x%p\n", MSR_IA32_VMX_BASIC, g_InitialMSRs[0].MSRValue, __readmsr(MSR_IA32_VMX_BASIC)));
			//KeBugCheckEx(CRITICAL_STRUCTURE_CORRUPTION, 0, 0, 0, 0x2); //0x7 = A critical MSR modification
		}

		if (g_InitialMSRs[1].MSRValue != __readmsr(MSR_IA32_VMX_PINBASED_CTLS))
		{
			KdPrint(("[*] MSR_IA32_VMX_PINBASED_CTLS (0x%x) was changed from: 0x%p to: 0x%p\n", MSR_IA32_VMX_PINBASED_CTLS, g_InitialMSRs[1].MSRValue, __readmsr(MSR_IA32_VMX_PINBASED_CTLS)));
			//KeBugCheckEx(CRITICAL_STRUCTURE_CORRUPTION, 0, 0, 0, 0x2); //0x7 = A critical MSR modification
		}

		if (g_InitialMSRs[2].MSRValue != __readmsr(MSR_IA32_VMX_PROCBASED_CTLS))
		{
			KdPrint(("[*] MSR_IA32_VMX_PROCBASED_CTLS (0x%x) was changed from: 0x%p to: 0x%p\n", MSR_IA32_VMX_PROCBASED_CTLS, g_InitialMSRs[2].MSRValue, __readmsr(MSR_IA32_VMX_PROCBASED_CTLS)));
			//KeBugCheckEx(CRITICAL_STRUCTURE_CORRUPTION, 0, 0, 0, 0x2); //0x7 = A critical MSR modification
		}

		if (g_InitialMSRs[3].MSRValue != __readmsr(MSR_IA32_VMX_EXIT_CTLS))
		{
			KdPrint(("[*] MSR_IA32_VMX_EXIT_CTLS (0x%x) was changed from: 0x%p to: 0x%p\n", MSR_IA32_VMX_EXIT_CTLS, g_InitialMSRs[3].MSRValue, __readmsr(MSR_IA32_VMX_EXIT_CTLS)));
			//KeBugCheckEx(CRITICAL_STRUCTURE_CORRUPTION, 0, 0, 0, 0x2); //0x7 = A critical MSR modification
		}

		if (g_InitialMSRs[4].MSRValue != __readmsr(MSR_IA32_VMX_ENTRY_CTLS))
		{
			KdPrint(("[*] MSR_IA32_VMX_ENTRY_CTLS (0x%x) was changed from: 0x%p to: 0x%p\n", MSR_IA32_VMX_ENTRY_CTLS, g_InitialMSRs[4].MSRValue, __readmsr(MSR_IA32_VMX_ENTRY_CTLS)));
			//KeBugCheckEx(CRITICAL_STRUCTURE_CORRUPTION, 0, 0, 0, 0x2); //0x7 = A critical MSR modification
		}

		if (g_InitialMSRs[5].MSRValue != __readmsr(MSR_IA32_VMX_MISC))
		{
			KdPrint(("[*] MSR_IA32_VMX_MISC (0x%x) was changed from: 0x%p to: 0x%p\n", MSR_IA32_VMX_MISC, g_InitialMSRs[5].MSRValue, __readmsr(MSR_IA32_VMX_MISC)));
			//KeBugCheckEx(CRITICAL_STRUCTURE_CORRUPTION, 0, 0, 0, 0x2); //0x7 = A critical MSR modification
		}

		if (g_InitialMSRs[6].MSRValue != __readmsr(MSR_IA32_VMX_CR0_FIXED0))
		{
			KdPrint(("[*] MSR_IA32_VMX_CR0_FIXED0 (0x%x) was changed from: 0x%p to: 0x%p\n", MSR_IA32_VMX_CR0_FIXED0, g_InitialMSRs[6].MSRValue, __readmsr(MSR_IA32_VMX_CR0_FIXED0)));
			//KeBugCheckEx(CRITICAL_STRUCTURE_CORRUPTION, 0, 0, 0, 0x2); //0x7 = A critical MSR modification
		}

		if (g_InitialMSRs[7].MSRValue != __readmsr(MSR_IA32_VMX_CR0_FIXED1))
		{
			KdPrint(("[*] MSR_IA32_VMX_CR0_FIXED1 (0x%x) was changed from: 0x%p to: 0x%p\n", MSR_IA32_VMX_CR0_FIXED1, g_InitialMSRs[7].MSRValue, __readmsr(MSR_IA32_VMX_CR0_FIXED1)));
			//KeBugCheckEx(CRITICAL_STRUCTURE_CORRUPTION, 0, 0, 0, 0x2); //0x7 = A critical MSR modification
		}

		if (g_InitialMSRs[8].MSRValue != __readmsr(MSR_IA32_VMX_CR4_FIXED0))
		{
			KdPrint(("[*] MSR_IA32_VMX_CR4_FIXED0 (0x%x) was changed from: 0x%p to: 0x%p\n", MSR_IA32_VMX_CR4_FIXED0, g_InitialMSRs[8].MSRValue, __readmsr(MSR_IA32_VMX_CR4_FIXED0)));
			//KeBugCheckEx(CRITICAL_STRUCTURE_CORRUPTION, 0, 0, 0, 0x2); //0x7 = A critical MSR modification
		}

		if (g_InitialMSRs[9].MSRValue != __readmsr(MSR_IA32_VMX_CR4_FIXED1))
		{
			KdPrint(("[*] MSR_IA32_VMX_CR4_FIXED1 (0x%x) was changed from: 0x%p to: 0x%p\n", MSR_IA32_VMX_CR4_FIXED1, g_InitialMSRs[9].MSRValue, __readmsr(MSR_IA32_VMX_CR4_FIXED1)));
			//KeBugCheckEx(CRITICAL_STRUCTURE_CORRUPTION, 0, 0, 0, 0x2); //0x7 = A critical MSR modification
		}

		if (g_InitialMSRs[10].MSRValue != __readmsr(MSR_IA32_VMX_VMCS_ENUM))
		{
			KdPrint(("[*] MSR_IA32_VMX_VMCS_ENUM (0x%x) was changed from: 0x%p to: 0x%p\n", MSR_IA32_VMX_VMCS_ENUM, g_InitialMSRs[10].MSRValue, __readmsr(MSR_IA32_VMX_VMCS_ENUM)));
			//KeBugCheckEx(CRITICAL_STRUCTURE_CORRUPTION, 0, 0, 0, 0x2); //0x7 = A critical MSR modification
		}

		if (g_InitialMSRs[11].MSRValue != __readmsr(MSR_IA32_VMX_PROCBASED_CTLS2))
		{
			KdPrint(("[*] MSR_IA32_VMX_PROCBASED_CTLS2 (0x%x) was changed from: 0x%p to: 0x%p\n", MSR_IA32_VMX_PROCBASED_CTLS2, g_InitialMSRs[11].MSRValue, __readmsr(MSR_IA32_VMX_PROCBASED_CTLS2)));
			//KeBugCheckEx(CRITICAL_STRUCTURE_CORRUPTION, 0, 0, 0, 0x2); //0x7 = A critical MSR modification
		}

		if (g_InitialMSRs[12].MSRValue != __readmsr(MSR_IA32_VMX_EPT_VPID_CAP))
		{
			KdPrint(("[*] MSR_IA32_VMX_EPT_VPID_CAP (0x%x) was changed from: 0x%p to: 0x%p\n", MSR_IA32_VMX_EPT_VPID_CAP, g_InitialMSRs[12].MSRValue, __readmsr(MSR_IA32_VMX_EPT_VPID_CAP)));
			//KeBugCheckEx(CRITICAL_STRUCTURE_CORRUPTION, 0, 0, 0, 0x2); //0x7 = A critical MSR modification
		}

		if (g_InitialMSRs[13].MSRValue != __readmsr(MSR_EFER))
		{
			KdPrint(("[*] MSR_EFER (0x%x) was changed from: 0x%p to: 0x%p\n", MSR_EFER, g_InitialMSRs[13].MSRValue, __readmsr(MSR_EFER)));
			//KeBugCheckEx(CRITICAL_STRUCTURE_CORRUPTION, 0, 0, 0, 0x2); //0x7 = A critical MSR modification
		}

		if (g_InitialMSRs[14].MSRValue != __readmsr(MSR_STAR))
		{
			KdPrint(("[*] MSR_STAR (0x%x) was changed from: 0x%p to: 0x%p\n", MSR_STAR, g_InitialMSRs[14].MSRValue, __readmsr(MSR_STAR)));
			//KeBugCheckEx(CRITICAL_STRUCTURE_CORRUPTION, 0, 0, 0, 0x2); //0x7 = A critical MSR modification
		}

		if (g_InitialMSRs[15].MSRValue != __readmsr(MSR_LSTAR))
		{
			KdPrint(("[*] MSR_LSTAR (0x%x) was changed from: 0x%p to: 0x%p!\n", MSR_LSTAR, g_InitialMSRs[15].MSRValue, __readmsr(MSR_LSTAR)));
			//KeBugCheckEx(CRITICAL_STRUCTURE_CORRUPTION, 0, 0, 0, 0x2); //0x7 = A critical MSR modification
		}

		if (g_InitialMSRs[16].MSRValue != __readmsr(MSR_CSTAR))
		{
			KdPrint(("[*] MSR_CSTAR (0x%x) was changed from: 0x%p to: 0x%p\n", MSR_CSTAR, g_InitialMSRs[16].MSRValue, __readmsr(MSR_CSTAR)));
			//KeBugCheckEx(CRITICAL_STRUCTURE_CORRUPTION, 0, 0, 0, 0x2); //0x7 = A critical MSR modification
		}

		if (g_InitialMSRs[17].MSRValue != __readmsr(MSR_FS_BASE))
		{
			KdPrint(("[*] MSR_FS_BASE (0x%x) was changed from: 0x%p to: 0x%p\n", MSR_FS_BASE, g_InitialMSRs[17].MSRValue, __readmsr(MSR_FS_BASE)));
			//KeBugCheckEx(CRITICAL_STRUCTURE_CORRUPTION, 0, 0, 0, 0x2); //0x7 = A critical MSR modification
		}

		if (g_InitialMSRs[18].MSRValue != __readmsr(MSR_GS_BASE))
		{
			KdPrint(("[*] MSR_GS_BASE (0x%x) was changed from: 0x%p to: 0x%p\n", MSR_GS_BASE, g_InitialMSRs[18].MSRValue, __readmsr(MSR_GS_BASE)));
		}

		if (g_InitialMSRs[19].MSRValue != __readmsr(MSR_KERNEL_GS_BASE))
		{
			KdPrint(("[*] MSR_KERNEL_GS_BASE (0x%x) was changed from: 0x%p to: 0x%p\n", MSR_KERNEL_GS_BASE, g_InitialMSRs[19].MSRValue, __readmsr(MSR_KERNEL_GS_BASE)));
		}

		if (g_InitialMSRs[20].MSRValue != __readmsr(MSR_IA32_APICBASE))
		{
			KdPrint(("[*] MSR_IA32_APICBASE (0x%x) was changed from: 0x%p to: 0x%p\n", MSR_IA32_APICBASE, g_InitialMSRs[20].MSRValue, __readmsr(MSR_IA32_APICBASE)));
			//KeBugCheckEx(CRITICAL_STRUCTURE_CORRUPTION, 0, 0, 0, 0x2); //0x7 = A critical MSR modification
		}

		if (g_InitialMSRs[21].MSRValue != __readmsr(MSR_SYSCALL_MASK))
		{
			KdPrint(("[*] MSR_SYSCALL_MASK (0x%x) was changed from: 0x%p to: 0x%p\n", MSR_SYSCALL_MASK, g_InitialMSRs[21].MSRValue, __readmsr(MSR_SYSCALL_MASK)));
			//KeBugCheckEx(CRITICAL_STRUCTURE_CORRUPTION, 0, 0, 0, 0x2); //0x7 = A critical MSR modification
		}

		return;
	}


	if (g_InitialMSRs[0].MSRValue != __readmsr(MSR_EFER))
	{
		KdPrint(("[*] MSR_EFER (0x%x) was changed from: 0x%p to: 0x%p\n", MSR_EFER, g_InitialMSRs[0].MSRValue, __readmsr(MSR_EFER)));
		//KeBugCheckEx(CRITICAL_STRUCTURE_CORRUPTION, 0, 0, 0, 0x2); //0x7 = A critical MSR modification
	}

	if (g_InitialMSRs[1].MSRValue != __readmsr(MSR_STAR))
	{
		KdPrint(("[*] MSR_STAR (0x%x) was changed from: 0x%p to: 0x%p\n", MSR_STAR, g_InitialMSRs[1].MSRValue, __readmsr(MSR_STAR)));
		//KeBugCheckEx(CRITICAL_STRUCTURE_CORRUPTION, 0, 0, 0, 0x2); //0x7 = A critical MSR modification
	}

	if (g_InitialMSRs[2].MSRValue != __readmsr(MSR_LSTAR))
	{
		KdPrint(("[*] MSR_LSTAR (0x%x) was changed from: 0x%p to: 0x%p\n", MSR_LSTAR, g_InitialMSRs[2].MSRValue, __readmsr(MSR_LSTAR)));
		//KeBugCheckEx(CRITICAL_STRUCTURE_CORRUPTION, 0, 0, 0, 0x2); //0x7 = A critical MSR modification
	}

	if (g_InitialMSRs[3].MSRValue != __readmsr(MSR_CSTAR))
	{
		KdPrint(("[*] MSR_CSTAR (0x%x) was changed from: 0x%p to: 0x%p\n", MSR_CSTAR, g_InitialMSRs[3].MSRValue, __readmsr(MSR_CSTAR)));
		//KeBugCheckEx(CRITICAL_STRUCTURE_CORRUPTION, 0, 0, 0, 0x2); //0x7 = A critical MSR modification
	}

	if (g_InitialMSRs[4].MSRValue != __readmsr(MSR_FS_BASE))
	{
		KdPrint(("[*] MSR_FS_BASE (0x%x) was changed from: 0x%p to: 0x%p\n", MSR_FS_BASE, g_InitialMSRs[4].MSRValue, __readmsr(MSR_FS_BASE)));
		//KeBugCheckEx(CRITICAL_STRUCTURE_CORRUPTION, 0, 0, 0, 0x2); //0x7 = A critical MSR modification
	}

	if (g_InitialMSRs[5].MSRValue != __readmsr(MSR_GS_BASE))
	{
		KdPrint(("[*] MSR_GS_BASE (0x%x) was changed from: 0x%p to: 0x%p\n", MSR_GS_BASE, g_InitialMSRs[5].MSRValue, __readmsr(MSR_GS_BASE)));
		//KeBugCheckEx(CRITICAL_STRUCTURE_CORRUPTION, 0, 0, 0, 0x2); //0x7 = A critical MSR modification
	}

	if (g_InitialMSRs[6].MSRValue != __readmsr(MSR_KERNEL_GS_BASE))
	{
		KdPrint(("[*] MSR_KERNEL_GS_BASE (0x%x) was changed from: 0x%p to: 0x%p\n", MSR_KERNEL_GS_BASE, g_InitialMSRs[6].MSRValue, __readmsr(MSR_KERNEL_GS_BASE)));
		//KeBugCheckEx(CRITICAL_STRUCTURE_CORRUPTION, 0, 0, 0, 0x2); //0x7 = A critical MSR modification
	}

	if (g_InitialMSRs[7].MSRValue != __readmsr(MSR_IA32_APICBASE))
	{
		KdPrint(("[*] MSR_IA32_APICBASE (0x%x) was changed from: 0x%p to: 0x%p\n", MSR_IA32_APICBASE, g_InitialMSRs[7].MSRValue, __readmsr(MSR_IA32_APICBASE)));
		//KeBugCheckEx(CRITICAL_STRUCTURE_CORRUPTION, 0, 0, 0, 0x2); //0x7 = A critical MSR modification
	}

	if (g_InitialMSRs[8].MSRValue != __readmsr(MSR_SYSCALL_MASK))
	{
		KdPrint(("[*] MSR_SYSCALL_MASK (0x%x) was changed from: 0x%p to: 0x%p\n", MSR_SYSCALL_MASK, g_InitialMSRs[8].MSRValue, __readmsr(MSR_SYSCALL_MASK)));
		//KeBugCheckEx(CRITICAL_STRUCTURE_CORRUPTION, 0, 0, 0, 0x2); //0x7 = A critical MSR modification
	}
}


VOID DPCInterruptDispatchTable(PKDPC Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
	NT_ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);

	/*
	 Increases IRQL to HIGH_LEVEL (0xF) to avoid potential evasion from an attacker when overriding a function pointer
	 with a malicious function pointer that automatically increases the IRQL to HIGH_LEVEL and prevent the timer DPC from being invoked.
	 Since working in a HIGH_LEVEL IRQL is an expensive operation, it must to be minimal and effective.
	*/

	KIRQL CurrentIRQL;
	KeRaiseIrql(HIGH_LEVEL, &CurrentIRQL);

	KdPrint(("[*] DPCInterruptDispatchTable was invoked!\n"));

	EnumerateIDT();

	KeLowerIrql(CurrentIRQL); // Lowers IRQL to DISPATCH_LEVEL (0x2)
}


VOID DPCMSRs(PKDPC Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
	NT_ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);

	KIRQL CurrentIrql;
	KeRaiseIrql(HIGH_LEVEL, &CurrentIrql);

	KdPrint(("[*] PatchGuardEncryptorDriver::DPCMSRs: MSR DPC is invoked, Current IRQL: %d\n", KeGetCurrentIrql()));
	EnumerateMSRs();

	KeLowerIrql(CurrentIrql);

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

	PDEVICE_OBJECT DeviceObject;
	NTSTATUS status = STATUS_SUCCESS;

	status = IoCreateDevice(DriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("[-] PatchGuardEncryptor::DriverEntry - Failed to created Device Object [0x%x]\n", status));
		return status;
	}

	status = IoCreateSymbolicLink(&DeviceSymlink, &DeviceName);
	if(!NT_SUCCESS(status))
	{
		KdPrint(("[-] PatchGuardEncryptor::DriverEntry - Failed to created Device symlink [0x%x]\n", status));
		IoDeleteDevice(DeviceObject);
	}

	DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateClose;
	DriverObject->DriverUnload = UnloadRoutine;

	g_InitialIDTEntries = (PIDT_ENTRY)ExAllocatePool(NonPagedPool, sizeof(IDT_ENTRY) * 256);
	if(!g_InitialIDTEntries)
	{
		KdPrint(("[-] PatchGuardEncryptor::DriverEntry: Failed allocating g_InitialIDTEntries with ExAllocatePool()!\n"));
		status = STATUS_INSUFFICIENT_RESOURCES;
		//IoDeleteDevice(DeviceObject);
		if (!NT_SUCCESS(IoDeleteSymbolicLink(&DeviceSymlink)))
		{
			KdPrint(("[-] PatchGuardEncryptor::DriverEntry: Unable to Delete symbolic Link!\n"));
		}

		return status;
	}

	KdPrint(("Allocated an array in non-paged pool of 256 IDT_ENTRY structures at address: 0x%p\n", g_InitialIDTEntries));

	g_InitialMSRs = (PMSR_ENTRY)ExAllocatePool(NonPagedPool, 27 * sizeof(MSR_ENTRY)); // There are actually 26 MSRs being check, but rounding the allocation to 27 for safety.
	if (!g_InitialMSRs)
	{
		KdPrint(("[-] PatchGuardEncryptor::DriverEntry: Failed allocating g_InitialMSRs with ExAllocatePool()!\n"));
		status = STATUS_INSUFFICIENT_RESOURCES;
		//IoDeleteDevice(DeviceObject);
		if (!NT_SUCCESS(IoDeleteSymbolicLink(&DeviceSymlink)))
		{
			KdPrint(("[-] PatchGuardEncryptor::DriverEntry: Unable to Delete symbolic Link!\n"));
		}

		return status;
	}

	KdPrint(("Allocated an array in non-paged pool of 256 MSR_ENTRY structures at address: 0x%p\n", g_InitialMSRs));

	EnumerateIDT();		// Captures the initial state of the Interrupt Dispatch Table when the driver is being loaded into kernel space.
	EnumerateMSRs();	// Captures the initial state of MSR registers when the driver is being loaded into kernel space.
	
	LARGE_INTEGER DueTime;
	DueTime.QuadPart = -3 * 10 * 1000 * 1000;	// 3 seconds
	LONG Period = 2 * 1000;						// 2 seconds interval

	// Allocating IDT, MSRs and SSDT timers using KeInitializeTimerEx()
	KeInitializeTimerEx(&TimerIDT, NotificationTimer);			// NotificationTimer makes the timer periodic
	KeInitializeTimerEx(&TimerMSRs, NotificationTimer);			// NotificationTimer makes the timer periodic


	// Initializing the IDT, MSR and SSDT DPCs with their relevant DPC routines
	KeInitializeDpc(&DPC_IDT, (PKDEFERRED_ROUTINE)DPCInterruptDispatchTable, nullptr);
	KeInitializeDpc(&DPC_MSRs, (PKDEFERRED_ROUTINE)DPCMSRs, nullptr);


	// Setting the timer with a certain Period, DueTime, and their DPCs
	KeSetTimerEx(&TimerIDT, DueTime, Period, &DPC_IDT);
	KeSetTimerEx(&TimerMSRs, DueTime, Period, &DPC_MSRs);


	// Will be used for the Anti-Remote Kernel debugger (implemented by checking the nt!KdDebuggerEnabled global variable)
	KdPrint(("Ntoskrnl base address: 0x%p\n", GetNtosBaseAddress())); 

	return status;
}