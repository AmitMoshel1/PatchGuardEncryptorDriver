#pragma once

/* Intel VT MSRs */
#define MSR_IA32_VMX_BASIC              0x00000480
#define MSR_IA32_VMX_PINBASED_CTLS      0x00000481
#define MSR_IA32_VMX_PROCBASED_CTLS     0x00000482
#define MSR_IA32_VMX_EXIT_CTLS          0x00000483
#define MSR_IA32_VMX_ENTRY_CTLS         0x00000484
#define MSR_IA32_VMX_MISC               0x00000485
#define MSR_IA32_VMX_CR0_FIXED0         0x00000486
#define MSR_IA32_VMX_CR0_FIXED1         0x00000487
#define MSR_IA32_VMX_CR4_FIXED0         0x00000488
#define MSR_IA32_VMX_CR4_FIXED1         0x00000489
#define MSR_IA32_VMX_VMCS_ENUM          0x0000048a
#define MSR_IA32_VMX_PROCBASED_CTLS2    0x0000048b
#define MSR_IA32_VMX_EPT_VPID_CAP       0x0000048c

/* x86-64 specific MSRs */
#define MSR_EFER					    0xc0000080			// extended feature register 
#define MSR_STAR						0xc0000081			// legacy mode SYSCALL target
#define MSR_LSTAR						0xc0000082			// long mode SYSCALL target 
#define MSR_CSTAR						0xc0000083			// compat mode SYSCALL target
#define MSR_SYSCALL_MASK				0xc0000084			// EFLAGS mask for syscall 
#define MSR_FS_BASE						0xc0000100			// 64bit FS base 
#define MSR_GS_BASE						0xc0000101			// 64bit GS base 
#define MSR_KERNEL_GS_BASE				0xc0000102			// SwapGS GS shadow 

#define MSR_IA32_APICBASE               0x0000001b
#define MSR_IA32_APICBASE_BSP           (1<<8)
#define MSR_IA32_APICBASE_ENABLE		(1<<11)
#define MSR_IA32_APICBASE_BASE          (0xfffff<<12)


