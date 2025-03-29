# PatchGuardEncryptorDriver

I created My own **Patch Guard** driver that dynamically monitors the following mechanisms in kernel space:
- **System Service Descriptor Table** (**SSDT**)
- **Interrupt Dispatch Table** (**IDT**)
- **Model Specific Registers** (**MSRs**)

At `DriverEntry()` the driver starts by initially capturing each mechanism's state (**initial MSR state**, **initial IDT state** and **initial SSDT state**) at **driver load time** and saves it into **kernel memory**.

The monitoring is performed through allocating **3 timers** (`_KTIMER` objects) in **kernel space** (for each monitored mechanism) and each timer has an associated **DPC** attached to it.
- The **SSDT monitoring timer** has an **associated DPC routine** that gets the **base address** of the **SSDT** and compares each **SSDT entry** with the inital state's relative **SSDT** entry. The number of **SSDT** entries available on the system is resolved at `DriverEntry()` using the function `FillNumberOfSSDTEntries()` function in the driver and is saved into a global driver variable.
   
- The **IDT monitoring timer** has an **associated DPC routine** that runs over each entry in the **IDT** and compares each entry with the initial **IDT** entry value captured at driver load.

- The **MSRs monitoring timer** has an **associated DPC routine** that read the values of certain MSRs and dynamically compares it to their relevant MSR state.
  The number of **MSRs** that are being checked is different based on if **VMX** is available on the system (I performed the check by reading the `CR4.VMXE` bit value which is the **13th bit** in the **CR4 register**).

At the **start of the Each DPC routine**, the **IRQL** of the processor immediately increases to **HIGH_LEVEL** (**0xf**), this is because an attacker can potentially overwrite an entry in one of the monitored mechanisms and also immediately increase the **IRQL** to **HIGH_LEVEL** to avoid the timer's DPCs from invoking.
At the **end of the DPC routine**, the **IRQL** is lowered back to **DISPATCH_LEVEL** (**0x2**) using the `KeLowerIrql()` function.

The second thing I implemented is an `IntegrityCheck` structure that allocates another 3 timer (`_KTIMER`) objects.
Each `IntegrityCheck` timer object is responsible to perform an integrity check on its relative **patch guard** timer.

Each integrity check timer has an associated **DPC** that is responsible to check that the following didn't occur:
- The `_KTIMER->Dpc` field of the patch guard timer object isn't being overwritten with a malicious `_KDPC` routine potentially overwritten by an attacker.
- The `DeferredRoutine` value of the patch guard's DPC isn't being overwritten with a malicious function pointer by an attacker.

The first check with `_KTIMER->Dpc` was a bit tricky since the value of the **DPC** shown in the `_KTIMER` field is bitwise manipulated:
```c++
dt nt!_KTIMER 0xFFFFF8073BA68080
```
![image](https://github.com/user-attachments/assets/c55d1597-541f-45f6-999c-3f0c49d6569c)

To discover how it's constructed, I needed to reverse the `KeSetTimerEx()` kernel function:
![image](https://github.com/user-attachments/assets/2651340f-f358-45e0-83b5-e80df180d2f7)

After reversing the bitwise operations shown above, I created a function called `CalculateTimerDPCValue()` and a helper function called `ROR8()` function.
The `CalculateTimerDPCValue()` takes 2 arguments:
- The `_KDPC` base address of the associated timer. 
- The `_KTIMER` kernel object base address.

```c++
// Right rotate function for 64-bit values
static inline ULONG_PTR ROR8(ULONG_PTR value, BYTE shift)
{
	return (value >> shift) | (value << (64 - shift));
}

ULONG_PTR IntegrityCheck::CalculateTimerDPCValue(PKDPC Dpc, PKTIMER KTimer)
{
	ULONG_PTR KernelBaseAddress = (ULONG_PTR)g_KernelInfo->KernelBaseAddress;

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
```

After calculating the bitwised **DPC** value of the relative patch guard timer's **DPC**, I compared this value, with the currently setted value within the patch guard's timer.

The second check performed takes the original `DeferredRoutine` function pointer associated with the patch guard timer's DPC and dynamically compares it with the current `DeferredRoutine` function pointer setted in the `_KDPC` object.

These checks are performed in each IntegrityCheck timer responsible for the integrity of each patch guard's timer initially created by the driver.
