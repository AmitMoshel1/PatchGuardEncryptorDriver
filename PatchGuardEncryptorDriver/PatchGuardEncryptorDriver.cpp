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
#pragma warning(disable: 4838)	// Disable specific warning
#pragma warning(disable: 4309)	// Disable specific warning

// Booleans that are used in each Enumerate (IDT,SSDT, MSRs) functions to determine first run and VMX state
BOOLEAN g_IsInitial_IDT = TRUE;
BOOLEAN g_IsInitial_MSRs = TRUE;
BOOLEAN g_IsInitialSSDT = TRUE;

BOOLEAN g_CR4_VMXE_Enabled = FALSE;

PIDT_ENTRY	g_InitialIDTEntries;
PMSR_ENTRY	g_InitialMSRs;
PSSDT_ENTRY g_InitialSSDTEntries;
PKERNEL_INFO g_KernelInfo;
ULONG_PTR	g_SystemInformation;
DWORD32		g_MaxVectorNumber = 0;
DWORD32		g_Number_Of_SSDT_Entries = 0;
PVOID		g_KiServiceTableAddress;

//BYTE KiServiceTableOpCodes[] = {0xF0, 0x87, 0x26, 0x00, 0x00, 0x50, 0x27, 0x00};
BYTE KiServiceTableOpCodes[] = {0x60, 0x41,0x32, 0x00, 0xF0, 0xA4, 0x43, 0x00 };

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
		KdPrint(("[*] PatchGuardEncryptor::UnloadRoutine: successfully freed the allocated IDT_ENTRY entries copy allocated from non paged pool!\n"));
	}

	if(g_InitialMSRs)
	{
		ExFreePool(g_InitialMSRs);
		KdPrint(("[*] PatchGuardEncryptor::UnloadRoutine: successfully freed the allocated MSR_ENTRY Entries allocated from non paged pool!\n"));
	}

	if(g_KernelInfo)
	{
		ExFreePool(g_KernelInfo);
		KdPrint(("[*] PatchGuardEncryptor::UnloadRoutine: successfully freed the allocated KERNEL_INFO structure allocated from non-paged pool!\n"));
	}

	if(g_InitialSSDTEntries)
	{
		ExFreePool(g_InitialSSDTEntries);
		KdPrint(("[*] PatchGuardEncryptor::UnloadRoutine: successfully freed the allocated SSDT_ENTRY entries allocated from non-paged pool!\n"));
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
				KdPrint(("[*] PatchGuardEncryptor::EnumerateIDT: detected a change in Vector: 0x%x\n", i));
				break;
			}
			KdPrint(("[*] PatchGuardEncryptor: Vector 0x%x is verified\n", i));
		}
	}
}

VOID GetNtosBaseAddress()
{
	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING NtQuerySystemInformationName = RTL_CONSTANT_STRING(L"NtQuerySystemInformation");
	typedef NTSTATUS(NTAPI* fNtQuerySytsemInformation)(SYSTEM_INFORMATION_CLASS SystemInformationClass,
		PVOID SystemInformation,
		ULONG SystemInformationLength,
		PULONG ReturnLength
		);

	fNtQuerySytsemInformation NtQuerySystemInformation = (fNtQuerySytsemInformation)MmGetSystemRoutineAddress(&NtQuerySystemInformationName);
	PVOID DummyMemory = ExAllocatePool(NonPagedPool, 1);
	if (!DummyMemory)
	{
		KdPrint(("[*] PatchGuardEncryptor::GetNtosBaseAddress: Unable to allocate DummyMemory!\n"));
		return;
	}
	ULONG ReturnLength;
	status = NtQuerySystemInformation(SystemModuleInformation, DummyMemory, 1, &ReturnLength);
	if (status == STATUS_INFO_LENGTH_MISMATCH)
	{

		PSYSTEM_MODULE_INFORMATION ModuleInformationMemory = (PSYSTEM_MODULE_INFORMATION)ExAllocatePool(NonPagedPool, ReturnLength);
		if (!ModuleInformationMemory) {
			KdPrint(("[*] PatchGuardEncryptor::GetNtosBaseAddress: Unable to allocate ModuleInformationMemory\n"));
			return;
		}
		status = NtQuerySystemInformation(SystemModuleInformation, ModuleInformationMemory, ReturnLength, nullptr);
		if (!NT_SUCCESS(status))
		{
			KdPrint(("[*] PatchGuardEncryptor::GetNtosBaseAddress: NtQuerySystemInformation failed with: 0x%x\n", status));
			return;
		}
		g_KernelInfo->KernelBaseAddress = ModuleInformationMemory->Modules[0].ImageBase;
		g_KernelInfo->Size = ModuleInformationMemory->Modules[0].ImageSize;
		
	}
}

PVOID GetKiServiceTableBaseAddress()
{
	/*
		This function is responsible to dynamically resolve the base address of the nt!KiServiceTable,
		which is the SSDT base address through checking a set of opcodes as a pattern used to dynamically
		deteremine the base address of nt!KiServiceTable.
	*/

	GetNtosBaseAddress(); // should fill the g_KernelInfo data structure with kernel base address and size

	KdPrint(("Ntoskrnl base address: 0x%p\n", g_KernelInfo->KernelBaseAddress));
	KdPrint(("Ntoskrnl size: %d bytes\n", g_KernelInfo->Size));

	if(g_KernelInfo->KernelBaseAddress && g_KernelInfo->Size)
	{
		ULONG_PTR BaseAddress = (ULONG_PTR)g_KernelInfo->KernelBaseAddress;
		int internal_counter = 0;
		for (int i = 0; i < g_KernelInfo->Size; i++)
		{
			CHAR CurrentOpCode = *(CHAR*)((CHAR*)BaseAddress + i);
			if (CurrentOpCode == KiServiceTableOpCodes[0])
			{
				for(int j = i; j < i+sizeof(KiServiceTableOpCodes); j++)
				{
					if(*(CHAR*)((CHAR*)BaseAddress + j) != KiServiceTableOpCodes[internal_counter])
					{
						internal_counter = 0;
						break;
					}

					internal_counter++;
				}

				if(internal_counter == sizeof(KiServiceTableOpCodes))
				{
					KdPrint(("[*] PatchGuardEncryptorDriver::GetKiServiceTableBaseAddress: nt!KiServiceTable Base Address: 0x%p\n", (PVOID)(BaseAddress + i)));
					return (PVOID)(BaseAddress + i);
				}
			}
		}
	}

	return 0;
}

VOID FillNumberOfSSDTEntries()
{
	/*
		The function will fill g_Number_Of_SSDT_Entries global variable with the number of SSDT enrties available on the system
		by dynamically resolving it through iterating over the SSDT.
	*/

	if (!g_KernelInfo->KernelBaseAddress)
	{
		GetNtosBaseAddress();
	}
	if(!g_KiServiceTableAddress)
	{
		//The KiServiceTable offset is currently hardcoded for testing purposes
		g_KiServiceTableAddress = (PVOID)(((ULONG_PTR)g_KernelInfo->KernelBaseAddress) + 0xd4270);
		KdPrint(("nt!KiServiceTable address: 0x%p\n", g_KiServiceTableAddress));
	}
	ULONG_PTR CurrentSSDTEntry = (ULONG_PTR)g_KiServiceTableAddress;

	int limiter = 300;
	while(*(DWORD*)CurrentSSDTEntry || limiter--)
	{
		// I made some bitwise operations that determines if the currently iterated DWORD
		// is a valid SSDT entry. I created it through researching how a SSDT entry is constructed  
		// and found a common base that each valid SSDT entry won't have
		if (((*(DWORD*)CurrentSSDTEntry) == 00000000)					// Checking if the currently iterated SSDT entry is 0
			|| (((*(DWORD*)CurrentSSDTEntry) & 0xff000000) == 00000000) // Checking if the first byte in the currently iterated SSDT is 00
			|| (((*(DWORD*)CurrentSSDTEntry) & 0xfffff000) == 00000000) // Checking if only the last 12 bits in the currently iterated SSDT are set
			|| (((*(DWORD*)CurrentSSDTEntry) ^ 0xff000000) == 0))		// checking if first byte in the currently iterated SSDT entry is bigger than 0x0f
		{
			break;
		}

		CurrentSSDTEntry += sizeof(DWORD);
		g_Number_Of_SSDT_Entries++;
	}
	KdPrint(("[*] PatchGuardEncryptorDriver::FillNumberOfSSDTEntries: Number of SSDT entries found: %d\n", g_Number_Of_SSDT_Entries));

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

	if(g_IsInitialSSDT)
	{
		g_IsInitialSSDT = FALSE;
		if (!g_InitialSSDTEntries)
		{
			KdPrint(("[*] PatchGuardEncryptor::EnumerateSSDT: g_InitialSSDTEntries is not allocated, returning...\n"));
			return;
		}

		//g_KiServiceTableAddress = GetKiServiceTableBaseAddress(); // This will fill the g_KiServiceTableAddress with nt!KiServiceTable base address
		g_KiServiceTableAddress = (PVOID)(((ULONG_PTR)g_KernelInfo->KernelBaseAddress) + 0xd4270); // hardcoded offset for testing purposes
		
		//FillNumberOfSSDTEntries();
		//
		//if(!g_Number_Of_SSDT_Entries)
		//{
		//	KdPrint(("[*] PatchGuardEncryptor::EnumerateSSDT: g_Number_Of_SSDT_Entries is %d!\n", g_Number_Of_SSDT_Entries));
		//	return;
		//}

		KdPrint(("[*] PatchGuardEncryptor::EnumerateSSDT: Number of SSDT entries found: %d!\n", g_Number_Of_SSDT_Entries));
		
		ULONG_PTR LocalKiServiceTableAddress = (ULONG_PTR)g_KiServiceTableAddress;
		DWORD CurrentSSDTEntry;
		for (int i = 0; i < g_Number_Of_SSDT_Entries; i++)
		{
			CurrentSSDTEntry = *(DWORD*)((BYTE*)LocalKiServiceTableAddress + (i * sizeof(DWORD)));
			g_InitialSSDTEntries[i].SyscallNumber = i; // since a syscall number is an index in the SSDT table, i is the SCN
			g_InitialSSDTEntries[i].SSDTValue = *(DWORD*)((BYTE*)LocalKiServiceTableAddress + (i * sizeof(DWORD)));
		}
		return;
	}

	ULONG_PTR LocalKiServiceTableAddress = (ULONG_PTR)g_KiServiceTableAddress;
	for (int i = 0; i < g_Number_Of_SSDT_Entries; i++)
	{
		ULONG_PTR CurrentSSDTEntryPointer = (ULONG_PTR)(((BYTE*)LocalKiServiceTableAddress) + (i * sizeof(DWORD)));

		//if (g_InitialSSDTEntries[i].SSDTValue != *(DWORD*)((BYTE*)LocalKiServiceTableAddress + (i * sizeof(DWORD))))
		if (g_InitialSSDTEntries[i].SSDTValue != *(DWORD*)CurrentSSDTEntryPointer)
		{
			KdPrint(("[*] PatchGuardEncryptor::EnumerateSSDT: Original SSDT entry value: 0x%x at 0x%p was changed to: 0x%x!!\n", g_InitialSSDTEntries[i].SSDTValue, CurrentSSDTEntryPointer, *(DWORD*)CurrentSSDTEntryPointer));
			continue;
		}
		//KdPrint(("[*] PatchGuardEncryptor::EnumerateSSDT: SSDT Entry[%d]: Original SSDT Entry Value = 0x%x | Current SSDT Entry value: 0x%x are verified!\n", i, g_InitialSSDTEntries[i].SSDTValue, *(DWORD*)CurrentSSDTEntryPointer));
		KdPrint(("[*] PatchGuardEncryptor::EnumerateSSDT: SSDT Entry at %d is valid and has the original value of 0x%x\n", i, g_InitialSSDTEntries[i].SSDTValue));
	}

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

			KdPrint(("[*] PatchGuardEncryptor::EnumerateMSR: CR4.VMXE=1\n"));
			KdPrint(("[*] PatchGuardEncryptor::EnumerateMSR: successfully filled g_InitialMSRs at base address : 0x%p\n", g_InitialMSRs));
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

		KdPrint(("[*] PatchGuardEncryptor::EnumerateMSR: CR4.VMXE=0\n"));
		KdPrint(("[*] PatchGuardEncryptor::EnumerateMSR: successfully filled g_InitialMSRs at base address : 0x%p\n", g_InitialMSRs));

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

	/*
	 Increases IRQL to HIGH_LEVEL (0xF) to avoid potential evasion from an attacker when overriding a function pointer
	 with a malicious function pointer that automatically increases the IRQL to HIGH_LEVEL and prevent the timer DPC from being invoked.
	 Since working in a HIGH_LEVEL IRQL is an expensive operation, it must to be minimal and effective.
	*/

	KIRQL CurrentIrql;
	KeRaiseIrql(HIGH_LEVEL, &CurrentIrql);

	KdPrint(("[*] PatchGuardEncryptorDriver::DPCMSRs: MSR DPC is invoked, Current IRQL: %d\n", KeGetCurrentIrql()));
	EnumerateMSRs();

	KeLowerIrql(CurrentIrql);

}

VOID DPCSSDT(PKDPC Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
	NT_ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);

	/*
	 Increases IRQL to HIGH_LEVEL (0xF) to avoid potential evasion from an attacker when overriding a function pointer
	 with a malicious function pointer that automatically increases the IRQL to HIGH_LEVEL and prevent the timer DPC from being invoked.
	 Since working in a HIGH_LEVEL IRQL is an expensive operation, it must to be minimal and effective.
	*/

	KIRQL CurrentIrql;
	KeRaiseIrql(HIGH_LEVEL, &CurrentIrql);

	KdPrint(("[*] PatchGuardEncryptorDriver::DPC_SSDT: SSDT DPC is invoked, Current IRQL: %d\n", KeGetCurrentIrql()));
	EnumerateSSDT();

	KeLowerIrql(CurrentIrql);
}

// new operator overloading
void * __cdecl operator new(size_t size, DWORD32 NumberOfAllocations, POOL_TYPE PoolType) 
{
	return ExAllocatePool(PoolType, NumberOfAllocations*size);
}

// delete operator overloading
void __cdecl operator delete(void *p, size_t)
{
	ExFreePool(p);
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

	//g_InitialIDTEntries = new(256, NonPagedPool)IDT_ENTRY;
	
	g_InitialIDTEntries = (PIDT_ENTRY)ExAllocatePool(NonPagedPool, sizeof(IDT_ENTRY) * 256);
	if(!g_InitialIDTEntries)
	{
		KdPrint(("[-] PatchGuardEncryptor::DriverEntry: Failed allocating g_InitialIDTEntries with ExAllocatePool()!\n"));
		status = STATUS_INSUFFICIENT_RESOURCES;
		UnloadRoutine(DriverObject);

		return status;
	}

	KdPrint(("Allocated an array in non-paged pool of 256 IDT_ENTRY structures at address: 0x%p\n", g_InitialIDTEntries));

	g_InitialMSRs = (PMSR_ENTRY)ExAllocatePool(NonPagedPool, 27 * sizeof(MSR_ENTRY)); // There are actually 26 MSRs being check, but rounding the allocation to 27 for safety.
	if (!g_InitialMSRs)
	{
		KdPrint(("[-] PatchGuardEncryptor::DriverEntry: Failed allocating g_InitialMSRs with ExAllocatePool()!\n"));
		status = STATUS_INSUFFICIENT_RESOURCES;
		UnloadRoutine(DriverObject);
		return status;
	}

	KdPrint(("Allocated an array in non-paged pool of 256 MSR_ENTRY structures at address: 0x%p\n", g_InitialMSRs));

	g_KernelInfo = (PKERNEL_INFO)ExAllocatePool(NonPagedPool, sizeof(KERNEL_INFO));
	if (!g_KernelInfo)
	{
		KdPrint(("[-] PatchGuardEncryptor::DriverEntry: Failed allocating g_KernelInfo with ExAllocatePool()!\n"));
		status = STATUS_INSUFFICIENT_RESOURCES;
		UnloadRoutine(DriverObject);
		return status;
	}
	
	FillNumberOfSSDTEntries();
	if (!g_Number_Of_SSDT_Entries)	// if the number of SSDT entries returned from FillNumberOfSSDTEntries() is 0...
	{
		KdPrint(("[*] PatchGuardEncryptor::EnumerateSSDT: g_Number_Of_SSDT_Entries is not allocated, returning...\n"));
		UnloadRoutine(DriverObject);
		return STATUS_BAD_DATA;
	}
	
	g_InitialSSDTEntries = (PSSDT_ENTRY)ExAllocatePool(NonPagedPool, g_Number_Of_SSDT_Entries * sizeof(SSDT_ENTRY));
	if(!g_InitialSSDTEntries)
	{
		KdPrint(("[-] PatchGuardEncryptor::DriverEntry: Failed allocating g_InitialSSDTEntries with ExAllocatePool()!\n"));
		status = STATUS_INSUFFICIENT_RESOURCES;
		UnloadRoutine(DriverObject);
		return status;
	}

	KdPrint(("Allocated an array in non-paged pool %d SSDT_ENTRY structures at address: 0x%p\n", g_Number_Of_SSDT_Entries, g_InitialSSDTEntries));

	EnumerateIDT();		// Captures the initial state of the Interrupt Dispatch Table when the driver is being loaded into kernel space.
	EnumerateMSRs();	// Captures the initial state of MSR registers when the driver is being loaded into kernel space.
	EnumerateSSDT();	// Captures the initial state of the SSDT when the driver is being loaded into kernel space.

	LARGE_INTEGER DueTime;
	DueTime.QuadPart = -3 * 10 * 1000 * 1000;	// 3 seconds
	LONG Period = 2 * 1000;						// 2 seconds interval

	// Allocating IDT, MSRs and SSDT timers using KeInitializeTimerEx()
	KeInitializeTimerEx(&TimerIDT,  NotificationTimer);			// NotificationTimer makes the timer periodic
	KeInitializeTimerEx(&TimerMSRs, NotificationTimer);			// NotificationTimer makes the timer periodic
	KeInitializeTimerEx(&TimerSSDT, NotificationTimer);			// NotificationTimer makes the timer periodic


	// Initializing the IDT, MSR and SSDT DPCs with their relevant DPC routines
	KeInitializeDpc(&DPC_IDT, (PKDEFERRED_ROUTINE)DPCInterruptDispatchTable, nullptr);
	KeInitializeDpc(&DPC_MSRs, (PKDEFERRED_ROUTINE)DPCMSRs, nullptr);
	KeInitializeDpc(&DPC_SSDT, (PKDEFERRED_ROUTINE)DPCSSDT, nullptr);


	// Setting the timer with a certain Period, DueTime, and their DPCs
	KeSetTimerEx(&TimerIDT, DueTime, Period, &DPC_IDT);
	KeSetTimerEx(&TimerMSRs, DueTime, Period, &DPC_MSRs);
	KeSetTimerEx(&TimerSSDT, DueTime, Period, &DPC_SSDT);

	/*
		it's possible to dynamically get the address of exported kernel variables (yes, variables not only functions)
		using the MmGetSystemRoutineAddress() kernel function.

		The KdDebuggerEnabled variable, is global exported kernel variable, which means that it's possible to 
		dynamically resolve the address of it using the MmGetSystemRoutineAddress() as done below:
	*/

	//UNICODE_STRING KdDebuggerEnabledName = RTL_CONSTANT_STRING(L"KdDebuggerEnabled");
	//PVOID KdDebuggerEnabledAddress = MmGetSystemRoutineAddress(&KdDebuggerEnabledName);
	//KdPrint(("[*] PatchGuardEncryptorDriver: nt!KdDebuggerEnabled global kernel variable at address: 0x%p\n", KdDebuggerEnabledAddress));

	return status;
}