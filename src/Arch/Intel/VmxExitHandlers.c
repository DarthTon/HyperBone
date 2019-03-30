/*++

Copyright (c) Alex Ionescu.  All rights reserved.

Module Name:

    VmxExitHandlers.c

Abstract:

    This module implements the Simple Hyper Visor itself.

Author:

    Alex Ionescu (@aionescu) 16-Mar-2016 - Initial version

Environment:

    Hypervisor mode only, IRQL HIGH_LEVEL

--*/

#include "VMX.h"
#include "EPT.h"
#include "VmxEvent.h"
#include "../../Include/CPU.h"
#include "../../Hooks/PageHook.h"

VOID VmExitUnknown( IN PGUEST_STATE GuestState );
VOID VmExitINVD( IN PGUEST_STATE GuestState );
VOID VmExitCPUID( IN PGUEST_STATE GuestState );
VOID VmExitRdtsc( IN PGUEST_STATE GuestState );
VOID VmExitRdtscp( IN PGUEST_STATE GuestState );
VOID VmExitXSETBV( IN PGUEST_STATE GuestState );
VOID VmExitVMOP( IN PGUEST_STATE GuestState );

VOID VmExitVmCall( IN PGUEST_STATE GuestState );

VOID VmExitCR( IN PGUEST_STATE GuestState );
VOID VmExitMSRRead( IN PGUEST_STATE GuestState );
VOID VmExitMSRWrite( IN PGUEST_STATE GuestState );

VOID VmExitEvent( IN PGUEST_STATE GuestState );
VOID VmExitMTF( IN PGUEST_STATE GuestState );

VOID VmExitEptViolation( IN PGUEST_STATE GuestState );
VOID VmExitEptMisconfig( IN PGUEST_STATE GuestState );

VOID VmExitStartFailed( IN PGUEST_STATE GuestState );
VOID VmExitTripleFault( IN PGUEST_STATE GuestState );

// Handlers table
typedef VOID( *pfnExitHandler )(IN PGUEST_STATE GuestState);
pfnExitHandler g_ExitHandler[VMX_MAX_GUEST_VMEXIT] =
{
    VmExitEvent,        // 00 EXIT_REASON_EXCEPTION_NMI
    VmExitUnknown,      // 01 EXIT_REASON_EXTERNAL_INTERRUPT
    VmExitTripleFault,  // 02 EXIT_REASON_TRIPLE_FAULT
    VmExitUnknown,      // 03 EXIT_REASON_INIT
    VmExitUnknown,      // 04 EXIT_REASON_SIPI
    VmExitUnknown,      // 05 EXIT_REASON_IO_SMI
    VmExitUnknown,      // 06 EXIT_REASON_OTHER_SMI
    VmExitUnknown,      // 07 EXIT_REASON_PENDING_INTERRUPT
    VmExitUnknown,      // 08 EXIT_REASON_NMI_WINDOW
    VmExitUnknown,      // 09 EXIT_REASON_TASK_SWITCH
    VmExitCPUID,        // 10 EXIT_REASON_CPUID
    VmExitUnknown,      // 11 EXIT_REASON_GETSEC
    VmExitUnknown,      // 12 EXIT_REASON_HLT
    VmExitINVD,         // 13 EXIT_REASON_INVD
    VmExitUnknown,      // 14 EXIT_REASON_INVLPG
    VmExitUnknown,      // 15 EXIT_REASON_RDPMC
    VmExitRdtsc,        // 16 EXIT_REASON_RDTSC
    VmExitUnknown,      // 17 EXIT_REASON_RSM
    VmExitVmCall,       // 18 EXIT_REASON_VMCALL
    VmExitVMOP,         // 19 EXIT_REASON_VMCLEAR
    VmExitVMOP,         // 20 EXIT_REASON_VMLAUNCH
    VmExitVMOP,         // 21 EXIT_REASON_VMPTRLD
    VmExitVMOP,         // 22 EXIT_REASON_VMPTRST
    VmExitVMOP,         // 23 EXIT_REASON_VMREAD
    VmExitVMOP,         // 24 EXIT_REASON_VMRESUME
    VmExitVMOP,         // 25 EXIT_REASON_VMWRITE
    VmExitVMOP,         // 26 EXIT_REASON_VMXOFF
    VmExitVMOP,         // 27 EXIT_REASON_VMXON
    VmExitCR,           // 28 EXIT_REASON_CR_ACCESS
    VmExitUnknown,      // 29 EXIT_REASON_DR_ACCESS
    VmExitUnknown,      // 30 EXIT_REASON_IO_INSTRUCTION
    VmExitMSRRead,      // 31 EXIT_REASON_MSR_READ
    VmExitMSRWrite,     // 32 EXIT_REASON_MSR_WRITE
    VmExitStartFailed,  // 33 EXIT_REASON_INVALID_GUEST_STATE
    VmExitStartFailed,  // 34 EXIT_REASON_MSR_LOADING
    VmExitUnknown,      // 35 EXIT_REASON_RESERVED_35
    VmExitUnknown,      // 36 EXIT_REASON_MWAIT_INSTRUCTION
    VmExitMTF,          // 37 EXIT_REASOM_MTF
    VmExitUnknown,      // 38 EXIT_REASON_RESERVED_38
    VmExitUnknown,      // 39 EXIT_REASON_MONITOR_INSTRUCTION
    VmExitUnknown,      // 40 EXIT_REASON_PAUSE_INSTRUCTION
    VmExitStartFailed,  // 41 EXIT_REASON_MACHINE_CHECK
    VmExitUnknown,      // 42 EXIT_REASON_RESERVED_42
    VmExitUnknown,      // 43 EXIT_REASON_TPR_BELOW_THRESHOLD
    VmExitUnknown,      // 44 EXIT_REASON_APIC_ACCESS
    VmExitUnknown,      // 45 EXIT_REASON_VIRTUALIZED_EIO
    VmExitUnknown,      // 46 EXIT_REASON_XDTR_ACCESS
    VmExitUnknown,      // 47 EXIT_REASON_TR_ACCESS
    VmExitEptViolation, // 48 EXIT_REASON_EPT_VIOLATION
    VmExitEptMisconfig, // 49 EXIT_REASON_EPT_MISCONFIG
    VmExitVMOP,         // 50 EXIT_REASON_INVEPT
    VmExitRdtscp,       // 51 EXIT_REASON_RDTSCP
    VmExitUnknown,      // 52 EXIT_REASON_PREEMPT_TIMER
    VmExitVMOP,         // 53 EXIT_REASON_INVVPID
    VmExitINVD,         // 54 EXIT_REASON_WBINVD
    VmExitXSETBV,       // 55 EXIT_REASON_XSETBV
    VmExitUnknown,      // 56 EXIT_REASON_APIC_WRITE
    VmExitUnknown,      // 57 EXIT_REASON_RDRAND
    VmExitUnknown,      // 58 EXIT_REASON_INVPCID
    VmExitUnknown,      // 59 EXIT_REASON_VMFUNC
    VmExitUnknown,      // 60 EXIT_REASON_RESERVED_60
    VmExitUnknown,      // 61 EXIT_REASON_RDSEED
    VmExitUnknown,      // 62 EXIT_REASON_RESERVED_62
    VmExitUnknown,      // 63 EXIT_REASON_XSAVES
    VmExitUnknown       // 64 EXIT_REASON_XRSTORS
};


/// <summary>
/// Advance guest EIP to the next instruction
/// </summary>
/// <param name="GuestState">Guest VM state</param>
inline VOID VmxpAdvanceEIP( IN PGUEST_STATE GuestState )
{
    GuestState->GuestRip += VmcsRead( VM_EXIT_INSTRUCTION_LEN );
    __vmx_vmwrite( GUEST_RIP, GuestState->GuestRip );
}

/// <summary>
/// VM Exit entry point
/// </summary>
/// <param name="Context">Guest registers</param>
DECLSPEC_NORETURN EXTERN_C VOID VmxpExitHandler( IN PCONTEXT Context )
{
    GUEST_STATE guestContext = { 0 };

    KeRaiseIrql( HIGH_LEVEL, &guestContext.GuestIrql );

    Context->Rcx = *(PULONG64)((ULONG_PTR)Context - sizeof( Context->Rcx ));

    PVCPU Vcpu = &g_Data->cpu_data[CPU_IDX];

    guestContext.Vcpu = Vcpu;
    guestContext.GuestEFlags.All = VmcsRead( GUEST_RFLAGS );
    guestContext.GuestRip = VmcsRead( GUEST_RIP );
    guestContext.GuestRsp = VmcsRead( GUEST_RSP );
    guestContext.ExitReason = VmcsRead( VM_EXIT_REASON ) & 0xFFFF;
    guestContext.ExitQualification = VmcsRead( EXIT_QUALIFICATION );
    guestContext.LinearAddress = VmcsRead( GUEST_LINEAR_ADDRESS );
    guestContext.PhysicalAddress.QuadPart = VmcsRead( GUEST_PHYSICAL_ADDRESS );
    guestContext.GpRegs = Context;
    guestContext.ExitPending = FALSE;

    (g_ExitHandler[guestContext.ExitReason])(&guestContext);

    if (guestContext.ExitPending)
    {
        _lgdt( &Vcpu->HostState.SpecialRegisters.Gdtr.Limit );
        __lidt( &Vcpu->HostState.SpecialRegisters.Idtr.Limit );

        __writecr3( VmcsRead( GUEST_CR3 ) );

        Context->Rsp = guestContext.GuestRsp;
        Context->Rip = (ULONG64)guestContext.GuestRip;

        __vmx_off();
        Vcpu->VmxState = VMX_STATE_OFF;
    }
    else
    {
        Context->Rsp += sizeof( Context->Rcx );
        Context->Rip = (ULONG64)VmxpResume;
    }

    KeLowerIrql( guestContext.GuestIrql );
    VmRestoreContext( Context );
}

/// <summary>
/// Default handler
/// </summary>
/// <param name="GuestRegs">Guest VM state</param>
VOID VmExitUnknown( IN PGUEST_STATE GuestState )
{
    DPRINT( "HyperBone: Unhandled exit reason 0x%llX, guest EIP 0x%p\n", GuestState->ExitReason, GuestState->GuestRip );
    NT_ASSERT( FALSE );
}

/// <summary>
/// INVD handler
/// </summary>
/// <param name="GuestState">Guest VM state</param>
VOID VmExitINVD( IN PGUEST_STATE GuestState )
{
    // This is the handler for the INVD instruction. Technically it may be more
    // correct to use __invd instead of __wbinvd, but that intrinsic doesn't
    // actually exist. Additionally, the Windows kernel (or HAL) don't contain
    // any example of INVD actually ever being used. Finally, Hyper-V itself
    // handles INVD by issuing WBINVD as well, so we'll just do that here too.
    __wbinvd();
    VmxpAdvanceEIP( GuestState );
}

/// <summary>
/// CPUID handler
/// </summary>
/// <param name="GuestState">Guest VM state</param>
VOID VmExitCPUID( IN PGUEST_STATE GuestState )
{
    CPUID cpu_info = { 0 };
    __cpuidex( (int*)&cpu_info, (int)GuestState->GpRegs->Rax, (int)GuestState->GpRegs->Rcx );

    GuestState->GpRegs->Rax = cpu_info.eax;
    GuestState->GpRegs->Rbx = cpu_info.ebx;
    GuestState->GpRegs->Rcx = cpu_info.ecx;
    GuestState->GpRegs->Rdx = cpu_info.edx;

    VmxpAdvanceEIP( GuestState );
}

/// <summary>
/// RDTSC handler
/// </summary>
/// <param name="GuestState">Guest VM state</param>
VOID VmExitRdtsc( IN PGUEST_STATE GuestState )
{
    ULARGE_INTEGER tsc = { 0 };
    tsc.QuadPart = __rdtsc();
    GuestState->GpRegs->Rdx = tsc.HighPart;
    GuestState->GpRegs->Rax = tsc.LowPart;

    VmxpAdvanceEIP( GuestState );
}

/// <summary>
/// RDTSCP handler
/// </summary>
/// <param name="GuestState">Guest VM state</param>
VOID VmExitRdtscp( IN PGUEST_STATE GuestState )
{
    unsigned int tscAux = 0;
    ULARGE_INTEGER tsc = { 0 };
    tsc.QuadPart = __rdtscp( &tscAux );
    GuestState->GpRegs->Rdx = tsc.HighPart;
    GuestState->GpRegs->Rax = tsc.LowPart;
    GuestState->GpRegs->Rcx = tscAux;

    VmxpAdvanceEIP( GuestState );
}

/// <summary>
/// XSETBV handler
/// </summary>
/// <param name="GuestState">Guest VM state</param>
VOID VmExitXSETBV( IN PGUEST_STATE GuestState )
{
    _xsetbv( (ULONG)GuestState->GpRegs->Rcx, GuestState->GpRegs->Rdx << 32 | GuestState->GpRegs->Rax );
    VmxpAdvanceEIP( GuestState );
}

/// <summary>
/// VMX instructions (vmxon, vmread, etc.) handler
/// </summary>
/// <param name="GuestState">Guest VM state</param>
VOID VmExitVMOP( IN PGUEST_STATE GuestState )
{
    // Set the CF flag, which is how VMX instructions indicate failure
    //GuestState->GuestEFlags.Fields.CF = TRUE;
    //__vmx_vmwrite( GUEST_RFLAGS, GuestState->GuestEFlags.All );
    //VmxpAdvanceEIP( GuestState );
    UNREFERENCED_PARAMETER( GuestState );
    VmxInjectEvent( INTERRUPT_HARDWARE_EXCEPTION, VECTOR_INVALID_OPCODE_EXCEPTION, 0 );
}

/// <summary>
/// VMCALL handler
/// </summary>
/// <param name="GuestState">Guest VM state</param>
VOID VmExitVmCall( IN PGUEST_STATE GuestState )
{
    ULONG32 HypercallNumber = (ULONG32)(GuestState->GpRegs->Rcx & 0xFFFF);
    EPT_CTX ctx = { 0 };

    switch (HypercallNumber)
    {
    case HYPERCALL_UNLOAD:
        GuestState->ExitPending = TRUE;
        break;

    case HYPERCALL_HOOK_LSTAR:
        //DPRINT( "HyperBone: CPU %d: %s: HYPERCALL_HOOKLSTAR new address 0x%p\n", i, __FUNCTION__, GuestRegs->rdx );
        GuestState->Vcpu->OriginalLSTAR = __readmsr( MSR_LSTAR );
        __writemsr( MSR_LSTAR, GuestState->GpRegs->Rdx );
        break;

    case HYPERCALL_UNHOOK_LSTAR:
        //DPRINT( "HyperBone: CPU %d: %s: HYPERCALL_UNHOOKLSTAR, original address 0x%p\n", i, __FUNCTION__, g_origLSTAR[i] );
        __writemsr( MSR_LSTAR, GuestState->Vcpu->OriginalLSTAR );
        GuestState->Vcpu->OriginalLSTAR = 0;
        break;

    case HYPERCALL_HOOK_PAGE:
        EptUpdateTableRecursive(
            &GuestState->Vcpu->EPT, GuestState->Vcpu->EPT.PML4Ptr, 
            EPT_TOP_LEVEL, GuestState->GpRegs->Rdx, EPT_ACCESS_EXEC,
            GuestState->GpRegs->R8, 1 
            );
        __invept( INV_ALL_CONTEXTS, &ctx );
        break;

    case HYPERCALL_UNHOOK_PAGE:
        EptUpdateTableRecursive(
            &GuestState->Vcpu->EPT, GuestState->Vcpu->EPT.PML4Ptr, 
            EPT_TOP_LEVEL, GuestState->GpRegs->Rdx, EPT_ACCESS_ALL, 
            GuestState->GpRegs->Rdx, 1 
            );
        __invept( INV_ALL_CONTEXTS, &ctx );
        break;

    default:
        DPRINT( "HyperBone: CPU %d: %s: Unsupported hypercall 0x%04X\n", CPU_IDX, __FUNCTION__, HypercallNumber );
        break;
    }

    VmxpAdvanceEIP( GuestState );
}

/// <summary>
/// CRx mov from/to
/// </summary>
/// <param name="GuestState">Guest VM state</param>
VOID VmExitCR( IN PGUEST_STATE GuestState )
{
    PMOV_CR_QUALIFICATION data = (PMOV_CR_QUALIFICATION)&GuestState->ExitQualification;
    PULONG64 regPtr = (PULONG64)&GuestState->GpRegs->Rax + data->Fields.Register;
    VPID_CTX ctx = { 0 };

    switch (data->Fields.AccessType)
    {
    case TYPE_MOV_TO_CR:
    {
        switch (data->Fields.ControlRegister)
        {
        case 0:
            __vmx_vmwrite( GUEST_CR0, *regPtr );
            __vmx_vmwrite( CR0_READ_SHADOW, *regPtr );
            break;
        case 3:
            __vmx_vmwrite( GUEST_CR3, *regPtr );
            if (g_Data->Features.VPID)
                __invvpid( INV_ALL_CONTEXTS, &ctx );
            break;
        case 4:
            __vmx_vmwrite( GUEST_CR4, *regPtr );
            __vmx_vmwrite( CR4_READ_SHADOW, *regPtr );
            break;
        default:
            DPRINT( "HyperBone: CPU %d: %s: Unsupported register %d\n", CPU_IDX, __FUNCTION__, data->Fields.ControlRegister );
            ASSERT( FALSE );
            break;
        }
    }
    break;

    case TYPE_MOV_FROM_CR:
    {
        switch (data->Fields.ControlRegister)
        {
        case 0:
            __vmx_vmread( GUEST_CR0, regPtr );
            break;
        case 3:
            __vmx_vmread( GUEST_CR3, regPtr );
            break;
        case 4:
            __vmx_vmread( GUEST_CR4, regPtr );
            break;
        default:
            DPRINT( "HyperBone: CPU %d: %s: Unsupported register %d\n", CPU_IDX, __FUNCTION__, data->Fields.ControlRegister );
            ASSERT( FALSE );
            break;
        }
    }
    break;

    default:
        DPRINT( "HyperBone: CPU %d: %s: Unsupported operation %d\n", CPU_IDX, __FUNCTION__, data->Fields.AccessType );
        ASSERT( FALSE );
        break;
    }

    VmxpAdvanceEIP( GuestState );
}


/// <summary>
/// RDMSR handler
/// </summary>
/// <param name="GuestState">Guest VM state</param>
VOID VmExitMSRRead( IN PGUEST_STATE GuestState )
{
    LARGE_INTEGER MsrValue = { 0 };
    ULONG32 ecx = (ULONG32)GuestState->GpRegs->Rcx;

    switch (ecx)
    {
    case MSR_LSTAR:
        MsrValue.QuadPart = GuestState->Vcpu->OriginalLSTAR != 0 ? GuestState->Vcpu->OriginalLSTAR : __readmsr( MSR_LSTAR );
        //DPRINT( "HyperBone: CPU %d: %s: rdmsr MSR_LSTAR, value 0x%p\n", CPU_IDX, __FUNCTION__, MsrValue.QuadPart );
        break;
    case MSR_GS_BASE:
        MsrValue.QuadPart = VmcsRead( GUEST_GS_BASE );
        break;
    case MSR_FS_BASE:
        MsrValue.QuadPart = VmcsRead( GUEST_FS_BASE );
        break;
    case MSR_IA32_DEBUGCTL:
        MsrValue.QuadPart = VmcsRead( GUEST_IA32_DEBUGCTL );
        break;

        // Report VMX as locked
    case MSR_IA32_FEATURE_CONTROL:
        MsrValue.QuadPart = __readmsr( ecx );
        PIA32_FEATURE_CONTROL_MSR pMSR = (PIA32_FEATURE_CONTROL_MSR)&MsrValue.QuadPart;
        pMSR->Fields.EnableVmxon = FALSE;
        pMSR->Fields.Lock = TRUE;
        break;

        // Virtualize VMX register access
    case MSR_IA32_VMX_BASIC:
    case MSR_IA32_VMX_PINBASED_CTLS:
    case MSR_IA32_VMX_PROCBASED_CTLS:
    case MSR_IA32_VMX_EXIT_CTLS:
    case MSR_IA32_VMX_ENTRY_CTLS:
    case MSR_IA32_VMX_MISC:
    case MSR_IA32_VMX_CR0_FIXED0:
    case MSR_IA32_VMX_CR0_FIXED1:
    case MSR_IA32_VMX_CR4_FIXED0:
    case MSR_IA32_VMX_CR4_FIXED1:
    case MSR_IA32_VMX_VMCS_ENUM:
    case MSR_IA32_VMX_PROCBASED_CTLS2:
    case MSR_IA32_VMX_EPT_VPID_CAP:
    case MSR_IA32_VMX_TRUE_PINBASED_CTLS:
    case MSR_IA32_VMX_TRUE_PROCBASED_CTLS:
    case MSR_IA32_VMX_TRUE_EXIT_CTLS:
    case MSR_IA32_VMX_TRUE_ENTRY_CTLS:
    case MSR_IA32_VMX_VMFUNC:
        MsrValue.QuadPart = GuestState->Vcpu->MsrData[VMX_MSR( ecx )].QuadPart;
        break;

    default:
        MsrValue.QuadPart = __readmsr( ecx );
    }

    GuestState->GpRegs->Rax = MsrValue.LowPart;
    GuestState->GpRegs->Rdx = MsrValue.HighPart;

    VmxpAdvanceEIP( GuestState );
}

/// <summary>
/// WRMSR handler
/// </summary>
/// <param name="GuestState">Guest VM state</param>
VOID VmExitMSRWrite( IN PGUEST_STATE GuestState )
{
    LARGE_INTEGER MsrValue = { 0 };
    ULONG32 ecx = (ULONG32)GuestState->GpRegs->Rcx;

    MsrValue.LowPart = (ULONG32)GuestState->GpRegs->Rax;
    MsrValue.HighPart = (ULONG32)GuestState->GpRegs->Rdx;

    switch (ecx)
    {
    case MSR_LSTAR:
        //DPRINT( "HyperBone: CPU %d: %s: wrmsr MSR_LSTAR, new value 0x%p\n", CPU_IDX, __FUNCTION__, MsrValue.QuadPart );
        // Ignore write if hooked
        if(GuestState->Vcpu->OriginalLSTAR == 0)
            __writemsr( MSR_LSTAR, MsrValue.QuadPart );
        break;
    case MSR_GS_BASE:
        __vmx_vmwrite( GUEST_GS_BASE, MsrValue.QuadPart );
        break;
    case MSR_FS_BASE:
        __vmx_vmwrite( GUEST_FS_BASE, MsrValue.QuadPart );
        break;
    case MSR_IA32_DEBUGCTL:
        __vmx_vmwrite( GUEST_IA32_DEBUGCTL, MsrValue.QuadPart );
        __writemsr( MSR_IA32_DEBUGCTL, MsrValue.QuadPart );
        break;

        // Virtualize VMX register access
    case MSR_IA32_VMX_BASIC:
    case MSR_IA32_VMX_PINBASED_CTLS:
    case MSR_IA32_VMX_PROCBASED_CTLS:
    case MSR_IA32_VMX_EXIT_CTLS:
    case MSR_IA32_VMX_ENTRY_CTLS:
    case MSR_IA32_VMX_MISC:
    case MSR_IA32_VMX_CR0_FIXED0:
    case MSR_IA32_VMX_CR0_FIXED1:
    case MSR_IA32_VMX_CR4_FIXED0:
    case MSR_IA32_VMX_CR4_FIXED1:
    case MSR_IA32_VMX_VMCS_ENUM:
    case MSR_IA32_VMX_PROCBASED_CTLS2:
    case MSR_IA32_VMX_EPT_VPID_CAP:
    case MSR_IA32_VMX_TRUE_PINBASED_CTLS:
    case MSR_IA32_VMX_TRUE_PROCBASED_CTLS:
    case MSR_IA32_VMX_TRUE_EXIT_CTLS:
    case MSR_IA32_VMX_TRUE_ENTRY_CTLS:
    case MSR_IA32_VMX_VMFUNC:
        break;

    default:
        __writemsr( ecx, MsrValue.QuadPart );
    }

    VmxpAdvanceEIP( GuestState );
}

/// <summary>
/// Handle exceptions and interrupts
/// </summary>
/// <param name="GuestState">Guest VM state</param>
VOID VmExitEvent( IN PGUEST_STATE GuestState )
{
    INTERRUPT_INFO_FIELD Event = { 0 };
    ULONG64 ErrorCode = 0;
    ULONG InstructionLength = (ULONG)VmcsRead( VM_EXIT_INSTRUCTION_LEN );

    Event.All = (ULONG32)VmcsRead( VM_EXIT_INTR_INFO );
    ErrorCode = VmcsRead( VM_EXIT_INTR_ERROR_CODE );
    if (Event.Fields.ErrorCodeValid)
        __vmx_vmwrite( VM_ENTRY_EXCEPTION_ERROR_CODE, ErrorCode );

    switch (Event.Fields.Type)
    {
    case INTERRUPT_NMI:
        DPRINT( "HyperBone: CPU %d: %s: HandleNmi()\n", CPU_IDX, __FUNCTION__ );
        VmxInjectEvent( INTERRUPT_NMI, VECTOR_NMI_INTERRUPT, 0 );
        ASSERT( FALSE );
        break;

    case INTERRUPT_HARDWARE_EXCEPTION:
        DPRINT( "HyperBone: CPU %d: %s: Hardware Exception (vector = 0x%x)\n", CPU_IDX, __FUNCTION__, Event.Fields.Vector );
        VmxInjectEvent( Event.Fields.Type, Event.Fields.Vector, InstructionLength );
        break;

    case INTERRUPT_SOFTWARE_EXCEPTION:
        switch (Event.Fields.Vector)
        {
        case VECTOR_BREAKPOINT_EXCEPTION:
            DPRINT( "HyperBone: CPU %d: %s: int3 EIP = 0x%p\n", CPU_IDX, __FUNCTION__, GuestState->GuestRip );
            VmxInjectEvent( INTERRUPT_SOFTWARE_EXCEPTION, VECTOR_BREAKPOINT_EXCEPTION, InstructionLength );
            break;

        default:
            DPRINT( "HyperBone: CPU %d: %s: Software Exception (vector = 0x%X)\n", CPU_IDX, __FUNCTION__, Event.Fields.Vector );
            VmxInjectEvent( Event.Fields.Type, Event.Fields.Vector, InstructionLength );
            break;
        }
        break;

    default:
        DPRINT( "HyperBone: CPU %d: %s: Unhandled event type %d\n", CPU_IDX, __FUNCTION__, Event.Fields.Type );
        VmxInjectEvent( Event.Fields.Type, Event.Fields.Vector, InstructionLength );
        break;
    }
}

/// <summary>
/// Handle MTF exiting
/// </summary>
/// <param name="GuestState">Guest VM state</param>
VOID VmExitMTF( IN PGUEST_STATE GuestState )
{
    //DPRINT( "HyperBone: CPU %d: %s: MTF exit, EIP 0x%p\n", CPU_IDX, __FUNCTION__, GuestState->GuestRip );
    if (GuestState->Vcpu->HookDispatch.pEntry != NULL)
    {
        PVCPU Vcpu = GuestState->Vcpu;
        PEPT_DATA pEPT = &Vcpu->EPT;
        PPAGE_HOOK_ENTRY pHook = Vcpu->HookDispatch.pEntry;

        // REP-prefixed instructions
        if (Vcpu->HookDispatch.Rip == GuestState->GuestRip)
            return;

        // Update EPT PTE access
        EptUpdateTableRecursive(
            pEPT, pEPT->PML4Ptr, EPT_TOP_LEVEL, 
            pHook->DataPagePFN, 
            EPT_ACCESS_EXEC, 
            pHook->CodePagePFN, 1 
            );

        // Rely on page cache if split method is used
        /*EPT_CTX ctx = { 0 };
        __invept( INV_ALL_CONTEXTS, &ctx );*/

        Vcpu->HookDispatch.pEntry = NULL;
        Vcpu->HookDispatch.Rip = 0;
        ToggleMTF( FALSE );
    }
}

/// <summary>
/// VMLAUNCH failed
/// </summary>
/// <param name="GuestState">Guest VM state</param>
VOID VmExitStartFailed( IN PGUEST_STATE GuestState )
{
    DPRINT(
        "HyperBone: CPU %d: %s: Failed to enter VM, reason %d, code %d\n",
        CPU_IDX, __FUNCTION__, 
        GuestState->ExitReason, GuestState->ExitQualification 
        );

    KeBugCheckEx( HYPERVISOR_ERROR, BUG_CHECK_INVALID_VM, GuestState->ExitReason, GuestState->ExitQualification, 0 );
}

/// <summary>
/// Triple fault handler
/// </summary>
/// <param name="GuestState">Guest VM state</param>
VOID VmExitTripleFault( IN PGUEST_STATE GuestState )
{
    DPRINT(
        "HyperBone: CPU %d: %s: Triple fault at IP 0x%p, stack 0x%p, linear 0x%p, physical 0x%p\n",
        CPU_IDX, __FUNCTION__, 
        GuestState->GuestRip, GuestState->GuestRsp, GuestState->LinearAddress, GuestState->PhysicalAddress.QuadPart
        );

    KeBugCheckEx( HYPERVISOR_ERROR, BUG_CHECK_TRIPLE_FAULT, GuestState->GuestRip, GuestState->GuestRsp, GuestState->LinearAddress );
}

