/*++

Copyright (c) Alex Ionescu.  All rights reserved.

Module Name:

    VMX.c

Abstract:

    This module implements Intel VMX (Vanderpool/VT-x)-specific routines.

Author:

    Alex Ionescu (@aionescu) 16-Mar-2016 - Initial version

Environment:

    Kernel mode only, IRQL DISPATCH_LEVEL.

--*/

#include "VMX.h"
#include "EPT.h"
#include "../../Util/Utils.h"
#include "VmxEvent.h"

VOID VmxSubvertCPU( IN PVCPU Vcpu );
BOOLEAN VmxEnterRoot( IN PVCPU VpData );
VOID VmxSetupVMCS( IN PVCPU VpData );


/// <summary>
/// Check if VT-x is supported
/// </summary>
/// <returns>TRUE if supported</returns>
BOOLEAN VmxHardSupported()
{
    CPUID data = { 0 };

    // VMX bit
    __cpuid( (int*)&data, 1 );
    if ((data.ecx & (1 << 5)) == 0)
        return FALSE;

    IA32_FEATURE_CONTROL_MSR Control = { 0 };
    Control.All = __readmsr( MSR_IA32_FEATURE_CONTROL );

    // BIOS lock check
    if (Control.Fields.Lock == 0)
    {
        Control.Fields.Lock = TRUE;
        Control.Fields.EnableVmxon = TRUE;
        __writemsr( MSR_IA32_FEATURE_CONTROL, Control.All );
    }
    else if (Control.Fields.EnableVmxon == FALSE)
    {
        DPRINT( "HyperBone: CPU %d: %s: VMX locked off in BIOS\n", CPU_IDX, __FUNCTION__ );
        return FALSE;
    }

    return TRUE;
}

/// <summary>
/// Check various VMX features: EPT, VPID, VMFUNC, etc.
/// </summary>
VOID VmxCheckFeatures()
{
    IA32_VMX_BASIC_MSR basic = { 0 };
    IA32_VMX_PROCBASED_CTLS_MSR ctl = { 0 };
    IA32_VMX_PROCBASED_CTLS2_MSR ctl2 = { 0 };
    IA32_VMX_EPT_VPID_CAP_MSR vpidcap = { 0 };

    // True MSRs
    basic.All = __readmsr( MSR_IA32_VMX_BASIC );
    g_Data->Features.TrueMSRs = basic.Fields.VmxCapabilityHint;

    // Secondary control
    ctl.All = __readmsr( MSR_IA32_VMX_PROCBASED_CTLS );
    g_Data->Features.SecondaryControls = ctl.Fields.ActivateSecondaryControl;

    if (ctl.Fields.ActivateSecondaryControl)
    {
        // EPT, VPID, VMFUNC
        ctl2.All = __readmsr( MSR_IA32_VMX_PROCBASED_CTLS2 );
        g_Data->Features.EPT  = ctl2.Fields.EnableEPT;
        g_Data->Features.VPID = ctl2.Fields.EnableVPID;
        g_Data->Features.VMFUNC = ctl2.Fields.EnableVMFunctions;

        if (ctl2.Fields.EnableEPT != 0)
        {
            // Execute only
            vpidcap.All = __readmsr( MSR_IA32_VMX_EPT_VPID_CAP );
            g_Data->Features.ExecOnlyEPT = vpidcap.Fields.ExecuteOnly;
            g_Data->Features.InvSingleAddress = vpidcap.Fields.IndividualAddressInvVpid;

            if (vpidcap.Fields.ExecuteOnly == 0)
                DPRINT( "HyperBone: CPU %d: %s: No execute-only EPT translation support\n", CPU_IDX, __FUNCTION__ );
        }
        else
            DPRINT( "HyperBone: CPU %d: %s: No EPT/VPID support\n", CPU_IDX, __FUNCTION__ );
    }
    else
        DPRINT( "HyperBone: CPU %d: %s: No secondary contol support\n", CPU_IDX, __FUNCTION__ );
}

/// <summary>
/// Inject interrupt or exception into guest
/// </summary>
/// <param name="InterruptType">INterrupt type</param>
/// <param name="Vector">IDT index</param>
/// <param name="WriteLength">Intruction length skip</param>
VOID VmxInjectEvent( INTERRUPT_TYPE InterruptType, VECTOR_EXCEPTION Vector, ULONG WriteLength )
{   
    INTERRUPT_INJECT_INFO_FIELD InjectEvent = { 0 };

    InjectEvent.Fields.Vector = Vector;
    InjectEvent.Fields.Type = InterruptType;
    InjectEvent.Fields.DeliverErrorCode = 0;
    InjectEvent.Fields.Valid = 1;

    __vmx_vmwrite( VM_ENTRY_INTR_INFO_FIELD, InjectEvent.All );
    if (WriteLength > 0)
        __vmx_vmwrite( VM_ENTRY_INSTRUCTION_LEN, WriteLength );
}

/// <summary>
/// Virtualize LP
/// </summary>
/// <param name="Vcpu">Virtual CPU data</param>
/// <param name="SystemDirectoryTableBase">Kernel CR3</param>
VOID VmxInitializeCPU( IN PVCPU Vcpu, IN ULONG64 SystemDirectoryTableBase )
{
    // Store the hibernation state of the processor, which contains all the
    // special registers and MSRs which are what the VMCS will need as part
    // of its setup. This avoids using assembly sequences and manually reading
    // this data.
    KeSaveStateForHibernate( &Vcpu->HostState );

    // Then, capture the entire register state. We will need this, as once we
    // launch the VM, it will begin execution at the defined guest instruction
    // pointer, which is being captured as part of this call. In other words,
    // we will return right where we were, but with all our registers corrupted
    // by the VMCS/VMX initialization code (as guest state does not include
    // register state). By saving the context here, which includes all general
    // purpose registers, we guarantee that we return with all of our starting
    // register values as well!
    RtlCaptureContext( &Vcpu->HostState.ContextFrame );

    // As per the above, we might be here because the VM has actually launched.
    // We can check this by verifying the value of the VmxEnabled field, which
    // is set to 1 right before VMXLAUNCH is performed. We do not use the Data
    // parameter or any other local register in this function, and in fact have
    // defined VmxEnabled as volatile, because as per the above, our register
    // state is currently dirty due to the VMCALL itself. By using the global
    // variable combined with an API call, we also make sure that the compiler
    // will not optimize this access in any way, even on LTGC/Ox builds.
    if (g_Data->cpu_data[CPU_IDX].VmxState == VMX_STATE_TRANSITION)
    {
        // We now indicate that the VM has launched, and that we are about to
        // restore the GPRs back to their original values. This will have the
        // effect of putting us yet *AGAIN* at the previous line of code, but
        // this time the value of VmxEnabled will be two, bypassing the if and
        // else if checks.
        g_Data->cpu_data[CPU_IDX].VmxState = VMX_STATE_ON;

        // And finally, restore the context, so that all register and stack
        // state is finally restored. Note that by continuing to reference the
        // per-VP data this way, the compiler will continue to generate non-
        // optimized accesses, guaranteeing that no previous register state
        // will be used.
        VmRestoreContext( &g_Data->cpu_data[CPU_IDX].HostState.ContextFrame );
    }
    // If we are in this branch comparison, it means that we have not yet
    // attempted to launch the VM, nor that we have launched it. In other
    // words, this is the first time in VmxInitializeCPU. Because of this,
    // we are free to use all register state, as it is ours to use.
    else if (g_Data->cpu_data[CPU_IDX].VmxState == VMX_STATE_OFF)
    {
        // First, capture the value of the PML4 for the SYSTEM process, so that
        // all virtual processors, regardless of which process the current LP
        // has interrupted, can share the correct kernel address space.
        Vcpu->SystemDirectoryTableBase = SystemDirectoryTableBase;

        // Then, attempt to initialize VMX on this processor
        VmxSubvertCPU( Vcpu );
    }
}

/// <summary>
/// Revert CPU to non-root mode
/// </summary>
/// <param name="Vcpu">Virtual CPU data</param>
VOID VmxShutdown( IN PVCPU Vcpu )
{
    //DPRINT( "HyperBone: CPU %d: %s: CR3 load count %d\n", CPU_IDX, __FUNCTION__, Vcpu->Cr3Loads );

    __vmx_vmcall( HYPERCALL_UNLOAD, 0, 0, 0 );
    VmxVMCleanup( KGDT64_R3_DATA | RPL_MASK, KGDT64_R3_CMTEB | RPL_MASK );

    EptFreeIdentityMap( &Vcpu->EPT );

    if (Vcpu->VMXON)
        MmFreeContiguousMemory( Vcpu->VMXON );
    if (Vcpu->VMCS)
        MmFreeContiguousMemory( Vcpu->VMCS );
    if (Vcpu->VMMStack)
        MmFreeContiguousMemory( Vcpu->VMMStack );

    Vcpu->VMXON = NULL;
    Vcpu->VMCS = NULL;
    Vcpu->VMMStack = NULL;
}

/// <summary>
/// Execute VMLAUNCH
/// </summary>
/// <param name="Vcpu">Virtyal CPU data</param>
VOID VmxSubvertCPU( IN PVCPU Vcpu )
{
    PHYSICAL_ADDRESS phys = { 0 };
    phys.QuadPart = MAXULONG64;

    //
    // Initialize all the VMX-related MSRs by reading their value
    //
    for (ULONG i = 0; i <= VMX_MSR( MSR_IA32_VMX_VMCS_ENUM ); i++)
        Vcpu->MsrData[i].QuadPart = __readmsr( MSR_IA32_VMX_BASIC + i );

    // Secondary controls, if present
    if (g_Data->Features.SecondaryControls)
        Vcpu->MsrData[VMX_MSR( MSR_IA32_VMX_PROCBASED_CTLS2 )].QuadPart = __readmsr( MSR_IA32_VMX_PROCBASED_CTLS2 );

    // True MSRs, if present
    if (g_Data->Features.TrueMSRs)
        for (ULONG i = VMX_MSR( MSR_IA32_VMX_TRUE_PINBASED_CTLS ); i <= VMX_MSR( MSR_IA32_VMX_TRUE_ENTRY_CTLS ); i++)
            Vcpu->MsrData[i].QuadPart = __readmsr( MSR_IA32_VMX_BASIC + i );

    // VMFUNC, if present
    if(g_Data->Features.VMFUNC)
        Vcpu->MsrData[VMX_MSR( MSR_IA32_VMX_VMFUNC )].QuadPart = __readmsr( MSR_IA32_VMX_VMFUNC );

    Vcpu->VMXON    = MmAllocateContiguousMemory( sizeof( VMX_VMCS ), phys );
    Vcpu->VMCS     = MmAllocateContiguousMemory( sizeof( VMX_VMCS ), phys );
    Vcpu->VMMStack = MmAllocateContiguousMemory( KERNEL_STACK_SIZE,  phys );

    if (!Vcpu->VMXON || !Vcpu->VMCS || !Vcpu->VMMStack)
    {
        DPRINT( "HyperBone: CPU %d: %s: Failed to allocate memory\n", CPU_IDX, __FUNCTION__ );
        goto failed;
    }

    UtilProtectNonpagedMemory( Vcpu->VMXON,    sizeof( VMX_VMCS ), PAGE_READWRITE );
    UtilProtectNonpagedMemory( Vcpu->VMCS,     sizeof( VMX_VMCS ), PAGE_READWRITE );
    UtilProtectNonpagedMemory( Vcpu->VMMStack, KERNEL_STACK_SIZE,  PAGE_READWRITE );

    RtlZeroMemory( Vcpu->VMXON,    sizeof( VMX_VMCS ) );
    RtlZeroMemory( Vcpu->VMCS,     sizeof( VMX_VMCS ) );
    RtlZeroMemory( Vcpu->VMMStack, KERNEL_STACK_SIZE );

    // Attempt to enter VMX root mode on this processor.
    if (VmxEnterRoot( Vcpu ))
    {
        // Initialize the VMCS, both guest and host state.
        VmxSetupVMCS( Vcpu );

        // Setup EPT
        if(g_Data->Features.EPT)
        {
            if (!NT_SUCCESS( EptBuildIdentityMap( &Vcpu->EPT ) ))
            {
                DPRINT( "HyperBone: CPU %d: %s: Failed to build EPT identity map\n", CPU_IDX, __FUNCTION__ );
                goto failedvmxoff;
            }

            EptEnable( Vcpu->EPT.PML4Ptr );
        }

        // Record that VMX is now enabled
        Vcpu->VmxState = VMX_STATE_TRANSITION;

        // Setup various VMCS fields by VmxSetupVmcs. This will cause the
        // processor to jump to the return address of RtlCaptureContext in
        // VmxInitializeCPU, which called us.
        InterlockedIncrement( &g_Data->vcpus );
        int res = __vmx_vmlaunch();
        InterlockedDecrement( &g_Data->vcpus );

        // If we got here, either VMCS setup failed in some way, or the launch
        // did not proceed as planned. Because VmxEnabled is not set to 1, this
        // will correctly register as a failure.
        Vcpu->VmxState = VMX_STATE_OFF;

        DPRINT( "HyperBone: CPU %d: %s: __vmx_vmlaunch failed with result %d\n", CPU_IDX, __FUNCTION__, res );

failedvmxoff:
        __vmx_off();
    }

failed:;
    if (Vcpu->VMXON)
        MmFreeContiguousMemory( Vcpu->VMXON );
    if (Vcpu->VMCS)
        MmFreeContiguousMemory( Vcpu->VMCS );
    if (Vcpu->VMMStack)
        MmFreeContiguousMemory( Vcpu->VMMStack );

    Vcpu->VMXON    = NULL;
    Vcpu->VMCS     = NULL;
    Vcpu->VMMStack = NULL;
}

/// <summary>
/// Fill segment data
/// </summary>
/// <param name="GdtBase">GDTR base</param>
/// <param name="Selector">Segment selector value</param>
/// <param name="VmxGdtEntry">Resulting entry</param>
VOID VmxpConvertGdtEntry( IN PVOID GdtBase, IN USHORT Selector, OUT PVMX_GDTENTRY64 VmxGdtEntry )
{
    PKGDTENTRY64 gdtEntry = NULL;

    // Read the GDT entry at the given selector, masking out the RPL bits. x64
    // Windows does not use an LDT for these selectors in kernel, so the TI bit
    // should never be set.
    NT_ASSERT( (Selector & SELECTOR_TABLE_INDEX) == 0 );
    gdtEntry = (PKGDTENTRY64)((ULONG_PTR)GdtBase + (Selector & ~RPL_MASK));

    // Write the selector directly 
    VmxGdtEntry->Selector = Selector;

    // Use the LSL intrinsic to read the segment limit
    VmxGdtEntry->Limit = __segmentlimit( Selector );

    // Build the full 64-bit effective address, keeping in mind that only when
    // the System bit is unset, should this be done.
    //
    // NOTE: The Windows definition of KGDTENTRY64 is WRONG. The "System" field
    // is incorrectly defined at the position of where the AVL bit should be.
    // The actual location of the SYSTEM bit is encoded as the highest bit in
    // the "Type" field.
    VmxGdtEntry->Base = ((gdtEntry->Bytes.BaseHigh << 24) | (gdtEntry->Bytes.BaseMiddle << 16) | (gdtEntry->BaseLow)) & MAXULONG;
    VmxGdtEntry->Base |= ((gdtEntry->Bits.Type & 0x10) == 0) ? ((ULONG_PTR)gdtEntry->BaseUpper << 32) : 0;

    // Load the access rights
    VmxGdtEntry->AccessRights = 0;
    VmxGdtEntry->Bytes.Flags1 = gdtEntry->Bytes.Flags1;
    VmxGdtEntry->Bytes.Flags2 = gdtEntry->Bytes.Flags2;

    // Finally, handle the VMX-specific bits
    VmxGdtEntry->Bits.Reserved = 0;
    VmxGdtEntry->Bits.Unusable = !gdtEntry->Bits.Present;
}

/// <summary>
/// Adjust VMX control accordingly to MSR
/// </summary>
/// <param name="ControlValue">MSR value to consult</param>
/// <param name="DesiredValue">Target control value</param>
/// <returns>Adjusted value</returns>
ULONG VmxpAdjustMsr( IN LARGE_INTEGER ControlValue, ULONG DesiredValue )
{
    // VMX feature/capability MSRs encode the "must be 0" bits in the high word
    // of their value, and the "must be 1" bits in the low word of their value.
    // Adjust any requested capability/feature based on these requirements.
    DesiredValue &= ControlValue.HighPart;
    DesiredValue |= ControlValue.LowPart;
    return DesiredValue;
}

/// <summary>
/// Switch CPU to root mode
/// </summary>
/// <param name="Vcpu">Virtual CPU data</param>
/// <returns>TRUE on success</returns>
BOOLEAN VmxEnterRoot( IN PVCPU Vcpu )
{
    PKSPECIAL_REGISTERS Registers = &Vcpu->HostState.SpecialRegisters;
    PIA32_VMX_BASIC_MSR pBasic = (PIA32_VMX_BASIC_MSR)&Vcpu->MsrData[VMX_MSR( MSR_IA32_VMX_BASIC )];

    // Ensure the the VMCS can fit into a single page
    if (pBasic->Fields.RegionSize > PAGE_SIZE)
    {
        DPRINT( "HyperBone: CPU %d: %s: VMCS region doesn't fit into one page\n", CPU_IDX, __FUNCTION__ );
        return FALSE;
    }

    // Ensure that the VMCS is supported in writeback memory
    if (pBasic->Fields.MemoryType != VMX_MEM_TYPE_WRITEBACK)
    {
        DPRINT( "HyperBone: CPU %d: %s: Unsupported memory type\n", CPU_IDX, __FUNCTION__ );
        return FALSE;
    }

    // Ensure that true MSRs can be used for capabilities
    if (pBasic->Fields.VmxCapabilityHint == 0)
    {
        DPRINT( "HyperBone: CPU %d: %s: No true MSR support\n", CPU_IDX, __FUNCTION__ );
        return FALSE;
    }

    // Capture the revision ID for the VMXON and VMCS region
    Vcpu->VMXON->RevisionId = pBasic->Fields.RevisionIdentifier;
    Vcpu->VMCS->RevisionId  = pBasic->Fields.RevisionIdentifier;

    // Update CR0 with the must-be-zero and must-be-one requirements
    Registers->Cr0 &= Vcpu->MsrData[VMX_MSR( MSR_IA32_VMX_CR0_FIXED1 )].LowPart;
    Registers->Cr0 |= Vcpu->MsrData[VMX_MSR( MSR_IA32_VMX_CR0_FIXED0 )].LowPart;

    // Do the same for CR4
    Registers->Cr4 &= Vcpu->MsrData[VMX_MSR( MSR_IA32_VMX_CR4_FIXED1 )].LowPart;
    Registers->Cr4 |= Vcpu->MsrData[VMX_MSR( MSR_IA32_VMX_CR4_FIXED0 )].LowPart;

    // Update host CR0 and CR4 based on the requirements above
    __writecr0( Registers->Cr0 );
    __writecr4( Registers->Cr4 );

    // Enable VMX Root Mode
    PHYSICAL_ADDRESS phys = MmGetPhysicalAddress( Vcpu->VMXON );
    int res = __vmx_on( (PULONG64)&phys );
    if (res)
    {
        DPRINT( "HyperBone: CPU %d: %s: __vmx_on failed with status %d\n", CPU_IDX, __FUNCTION__, res );
        return FALSE;
    }

    // Clear the state of the VMCS, setting it to Inactive
    phys = MmGetPhysicalAddress( Vcpu->VMCS );
    if (__vmx_vmclear( (PULONG64)&phys ))
    {
        DPRINT( "HyperBone: CPU %d: %s: __vmx_vmclear failed\n", CPU_IDX, __FUNCTION__ );
        return FALSE;
    }

    // Load the VMCS, setting its state to Active
    if (__vmx_vmptrld( (PULONG64)&phys ))
    {
        DPRINT( "HyperBone: CPU %d: %s: __vmx_vmptrld failed\n", CPU_IDX, __FUNCTION__ );
        return FALSE;
    }

    // VMX Root Mode is enabled, with an active VMCS.
    return TRUE;
}

/// <summary>
/// Setup VMCS fields
/// </summary>
/// <param name="VpData">Virtual CPU data</param>
VOID VmxSetupVMCS( IN PVCPU VpData )
{
    PKPROCESSOR_STATE state = &VpData->HostState;
    VMX_GDTENTRY64 vmxGdtEntry = { 0 };
    VMX_VM_ENTER_CONTROLS vmEnterCtlRequested = { 0 };
    VMX_VM_EXIT_CONTROLS vmExitCtlRequested = { 0 };
    VMX_PIN_BASED_CONTROLS vmPinCtlRequested = { 0 };
    VMX_CPU_BASED_CONTROLS vmCpuCtlRequested = { 0 };
    VMX_SECONDARY_CPU_BASED_CONTROLS vmCpuCtl2Requested = { 0 };

    // As we exit back into the guest, make sure to exist in x64 mode as well.
    vmEnterCtlRequested.Fields.IA32eModeGuest = TRUE;

    // If any interrupts were pending upon entering the hypervisor, acknowledge
    // them when we're done. And make sure to enter us in x64 mode at all times
    vmExitCtlRequested.Fields.AcknowledgeInterruptOnExit = TRUE;
    vmExitCtlRequested.Fields.HostAddressSpaceSize = TRUE;

    // In order for our choice of supporting RDTSCP and XSAVE/RESTORES above to
    // actually mean something, we have to request secondary controls. We also
    // want to activate the MSR bitmap in order to keep them from being caught.
    vmCpuCtlRequested.Fields.UseMSRBitmaps = TRUE;
    vmCpuCtlRequested.Fields.ActivateSecondaryControl = TRUE;
    //vmCpuCtlRequested.Fields.UseTSCOffseting = TRUE;
    //vmCpuCtlRequested.Fields.RDTSCExiting = TRUE;

    // VPID caches must be invalidated on CR3 change
    if(g_Data->Features.VPID)
        vmCpuCtlRequested.Fields.CR3LoadExiting = TRUE;

    // Enable support for RDTSCP and XSAVES/XRESTORES in the guest. Windows 10
    // makes use of both of these instructions if the CPU supports it. By using
    // VmxpAdjustMsr, these options will be ignored if this processor does
    // not actually support the instructions to begin with.
    vmCpuCtl2Requested.Fields.EnableRDTSCP = TRUE;
    vmCpuCtl2Requested.Fields.EnableXSAVESXSTORS = TRUE;

    // Begin by setting the link pointer to the required value for 4KB VMCS.
    __vmx_vmwrite( VMCS_LINK_POINTER, MAXULONG64 );

    __vmx_vmwrite(
        PIN_BASED_VM_EXEC_CONTROL, 
        VmxpAdjustMsr( VpData->MsrData[VMX_MSR( MSR_IA32_VMX_TRUE_PINBASED_CTLS )], vmPinCtlRequested.All ) 
        );
    __vmx_vmwrite( 
        CPU_BASED_VM_EXEC_CONTROL, 
        VmxpAdjustMsr( VpData->MsrData[VMX_MSR( MSR_IA32_VMX_TRUE_PROCBASED_CTLS )], vmCpuCtlRequested.All ) 
        );
    __vmx_vmwrite( 
        SECONDARY_VM_EXEC_CONTROL, 
        VmxpAdjustMsr( VpData->MsrData[VMX_MSR( MSR_IA32_VMX_PROCBASED_CTLS2 )], vmCpuCtl2Requested.All ) 
        );
    __vmx_vmwrite(
        VM_EXIT_CONTROLS, 
        VmxpAdjustMsr( VpData->MsrData[VMX_MSR( MSR_IA32_VMX_TRUE_EXIT_CTLS )], vmExitCtlRequested.All ) 
        );
    __vmx_vmwrite( 
        VM_ENTRY_CONTROLS, 
        VmxpAdjustMsr( VpData->MsrData[VMX_MSR( MSR_IA32_VMX_TRUE_ENTRY_CTLS )], vmEnterCtlRequested.All ) 
        );

    // Load the MSR bitmap. Unlike other bitmaps, not having an MSR bitmap will
    // trap all MSRs, so have to allocate an empty one.
    PUCHAR bitMapReadLow = g_Data->MSRBitmap;       // 0x00000000 - 0x00001FFF
    PUCHAR bitMapReadHigh = bitMapReadLow + 1024;   // 0xC0000000 - 0xC0001FFF

    RTL_BITMAP bitMapReadLowHeader = { 0 };
    RTL_BITMAP bitMapReadHighHeader = { 0 };
    RtlInitializeBitMap( &bitMapReadLowHeader, (PULONG)bitMapReadLow, 1024 * 8 );
    RtlInitializeBitMap( &bitMapReadHighHeader, (PULONG)bitMapReadHigh, 1024 * 8 );

    RtlSetBit( &bitMapReadLowHeader, MSR_IA32_FEATURE_CONTROL );    // MSR_IA32_FEATURE_CONTROL
    RtlSetBit( &bitMapReadLowHeader,  MSR_IA32_DEBUGCTL );          // MSR_DEBUGCTL
    RtlSetBit( &bitMapReadHighHeader, MSR_LSTAR - 0xC0000000 );     // MSR_LSTAR

    // VMX MSRs
    for (ULONG i = MSR_IA32_VMX_BASIC; i <= MSR_IA32_VMX_VMFUNC; i++)
        RtlSetBit( &bitMapReadLowHeader, i );

    __vmx_vmwrite( MSR_BITMAP, MmGetPhysicalAddress( g_Data->MSRBitmap ).QuadPart );

    // Exception bitmap
    ULONG ExceptionBitmap = 0;
    //ExceptionBitmap |= 1 << VECTOR_DEBUG_EXCEPTION;
    ExceptionBitmap |= 1 << VECTOR_BREAKPOINT_EXCEPTION;

    __vmx_vmwrite( EXCEPTION_BITMAP, ExceptionBitmap );

    // CS (Ring 0 Code)
    VmxpConvertGdtEntry( state->SpecialRegisters.Gdtr.Base, state->ContextFrame.SegCs, &vmxGdtEntry );
    __vmx_vmwrite( GUEST_CS_SELECTOR, vmxGdtEntry.Selector );
    __vmx_vmwrite( GUEST_CS_LIMIT, vmxGdtEntry.Limit );
    __vmx_vmwrite( GUEST_CS_AR_BYTES, vmxGdtEntry.AccessRights );
    __vmx_vmwrite( GUEST_CS_BASE, vmxGdtEntry.Base );
    __vmx_vmwrite( HOST_CS_SELECTOR, state->ContextFrame.SegCs & ~RPL_MASK );

    // SS (Ring 0 Data)
    VmxpConvertGdtEntry( state->SpecialRegisters.Gdtr.Base, state->ContextFrame.SegSs, &vmxGdtEntry );
    __vmx_vmwrite( GUEST_SS_SELECTOR, vmxGdtEntry.Selector );
    __vmx_vmwrite( GUEST_SS_LIMIT, vmxGdtEntry.Limit );
    __vmx_vmwrite( GUEST_SS_AR_BYTES, vmxGdtEntry.AccessRights );
    __vmx_vmwrite( GUEST_SS_BASE, vmxGdtEntry.Base );
    __vmx_vmwrite( HOST_SS_SELECTOR, state->ContextFrame.SegSs & ~RPL_MASK );

    // DS (Ring 3 Data)
    VmxpConvertGdtEntry( state->SpecialRegisters.Gdtr.Base, state->ContextFrame.SegDs, &vmxGdtEntry );
    __vmx_vmwrite( GUEST_DS_SELECTOR, vmxGdtEntry.Selector );
    __vmx_vmwrite( GUEST_DS_LIMIT, vmxGdtEntry.Limit );
    __vmx_vmwrite( GUEST_DS_AR_BYTES, vmxGdtEntry.AccessRights );
    __vmx_vmwrite( GUEST_DS_BASE, vmxGdtEntry.Base );
    __vmx_vmwrite( HOST_DS_SELECTOR, state->ContextFrame.SegDs & ~RPL_MASK );

    // ES (Ring 3 Data)
    VmxpConvertGdtEntry( state->SpecialRegisters.Gdtr.Base, state->ContextFrame.SegEs, &vmxGdtEntry );
    __vmx_vmwrite( GUEST_ES_SELECTOR, vmxGdtEntry.Selector );
    __vmx_vmwrite( GUEST_ES_LIMIT, vmxGdtEntry.Limit );
    __vmx_vmwrite( GUEST_ES_AR_BYTES, vmxGdtEntry.AccessRights );
    __vmx_vmwrite( GUEST_ES_BASE, vmxGdtEntry.Base );
    __vmx_vmwrite( HOST_ES_SELECTOR, state->ContextFrame.SegEs & ~RPL_MASK );

    // FS (Ring 3 Compatibility-Mode TEB)
    VmxpConvertGdtEntry( state->SpecialRegisters.Gdtr.Base, state->ContextFrame.SegFs, &vmxGdtEntry );
    __vmx_vmwrite( GUEST_FS_SELECTOR, vmxGdtEntry.Selector );
    __vmx_vmwrite( GUEST_FS_LIMIT, vmxGdtEntry.Limit );
    __vmx_vmwrite( GUEST_FS_AR_BYTES, vmxGdtEntry.AccessRights );
    __vmx_vmwrite( GUEST_FS_BASE, vmxGdtEntry.Base );
    __vmx_vmwrite( HOST_FS_BASE, vmxGdtEntry.Base );
    __vmx_vmwrite( HOST_FS_SELECTOR, state->ContextFrame.SegFs & ~RPL_MASK );

    // GS (Ring 3 Data if in Compatibility-Mode, MSR-based in Long Mode)
    VmxpConvertGdtEntry( state->SpecialRegisters.Gdtr.Base, state->ContextFrame.SegGs, &vmxGdtEntry );
    __vmx_vmwrite( GUEST_GS_SELECTOR, vmxGdtEntry.Selector );
    __vmx_vmwrite( GUEST_GS_LIMIT, vmxGdtEntry.Limit );
    __vmx_vmwrite( GUEST_GS_AR_BYTES, vmxGdtEntry.AccessRights );
    __vmx_vmwrite( GUEST_GS_BASE, state->SpecialRegisters.MsrGsBase );
    __vmx_vmwrite( HOST_GS_BASE, state->SpecialRegisters.MsrGsBase );
    __vmx_vmwrite( HOST_GS_SELECTOR, state->ContextFrame.SegGs & ~RPL_MASK );

    // Task Register (Ring 0 TSS)
    VmxpConvertGdtEntry( state->SpecialRegisters.Gdtr.Base, state->SpecialRegisters.Tr, &vmxGdtEntry );
    __vmx_vmwrite( GUEST_TR_SELECTOR, vmxGdtEntry.Selector );
    __vmx_vmwrite( GUEST_TR_LIMIT, vmxGdtEntry.Limit );
    __vmx_vmwrite( GUEST_TR_AR_BYTES, vmxGdtEntry.AccessRights );
    __vmx_vmwrite( GUEST_TR_BASE, vmxGdtEntry.Base );
    __vmx_vmwrite( HOST_TR_BASE, vmxGdtEntry.Base );
    __vmx_vmwrite( HOST_TR_SELECTOR, state->SpecialRegisters.Tr & ~RPL_MASK );

    // LDT
    VmxpConvertGdtEntry( state->SpecialRegisters.Gdtr.Base, state->SpecialRegisters.Ldtr, &vmxGdtEntry );
    __vmx_vmwrite( GUEST_LDTR_SELECTOR, vmxGdtEntry.Selector );
    __vmx_vmwrite( GUEST_LDTR_LIMIT, vmxGdtEntry.Limit );
    __vmx_vmwrite( GUEST_LDTR_AR_BYTES, vmxGdtEntry.AccessRights );
    __vmx_vmwrite( GUEST_LDTR_BASE, vmxGdtEntry.Base );

    // GDT
    __vmx_vmwrite( GUEST_GDTR_BASE, (ULONG_PTR)state->SpecialRegisters.Gdtr.Base );
    __vmx_vmwrite( GUEST_GDTR_LIMIT, state->SpecialRegisters.Gdtr.Limit );
    __vmx_vmwrite( HOST_GDTR_BASE, (ULONG_PTR)state->SpecialRegisters.Gdtr.Base );

    // IDT
    __vmx_vmwrite( GUEST_IDTR_BASE, (ULONG_PTR)state->SpecialRegisters.Idtr.Base );
    __vmx_vmwrite( GUEST_IDTR_LIMIT, state->SpecialRegisters.Idtr.Limit );
    __vmx_vmwrite( HOST_IDTR_BASE, (ULONG_PTR)state->SpecialRegisters.Idtr.Base );

    // CR0
    __vmx_vmwrite( CR0_READ_SHADOW, state->SpecialRegisters.Cr0 );
    __vmx_vmwrite( HOST_CR0, state->SpecialRegisters.Cr0 );
    __vmx_vmwrite( GUEST_CR0, state->SpecialRegisters.Cr0 );

    // CR3 -- do not use the current process' address space for the host,
    // because we may be executing in an arbitrary user-mode process right now
    // as part of the DPC interrupt we execute in.
    __vmx_vmwrite( HOST_CR3, VpData->SystemDirectoryTableBase );
    __vmx_vmwrite( GUEST_CR3, state->SpecialRegisters.Cr3 );

    // CR4
    __vmx_vmwrite( HOST_CR4, state->SpecialRegisters.Cr4 );
    __vmx_vmwrite( GUEST_CR4, state->SpecialRegisters.Cr4 );
    __vmx_vmwrite( CR4_GUEST_HOST_MASK, 0x2000 );
    __vmx_vmwrite( CR4_READ_SHADOW, state->SpecialRegisters.Cr4 & ~0x2000 );

    // Debug MSR and DR7
    __vmx_vmwrite( GUEST_IA32_DEBUGCTL, state->SpecialRegisters.DebugControl );
    __vmx_vmwrite( GUEST_DR7, state->SpecialRegisters.KernelDr7 );

    // Finally, load the guest stack, instruction pointer, and rflags, which
    // corresponds exactly to the location where RtlCaptureContext will return
    // to inside of VmxInitializeCPU.
    __vmx_vmwrite( GUEST_RSP, state->ContextFrame.Rsp );
    __vmx_vmwrite( GUEST_RIP, state->ContextFrame.Rip );
    __vmx_vmwrite( GUEST_RFLAGS, state->ContextFrame.EFlags );

    // Load the hypervisor entrypoint and stack. We give ourselves a standard
    // size kernel stack (24KB) and bias for the context structure that the
    // hypervisor entrypoint will push on the stack, avoiding the need for RSP
    // modifying instructions in the entrypoint. Note that the CONTEXT pointer
    // and thus the stack itself, must be 16-byte aligned for ABI compatibility
    // with AMD64 -- specifically, XMM operations will fail otherwise, such as
    // the ones that RtlCaptureContext will perform.
    NT_ASSERT( (KERNEL_STACK_SIZE - sizeof( CONTEXT )) % 16 == 0 );
    __vmx_vmwrite( HOST_RSP, (ULONG_PTR)VpData->VMMStack + KERNEL_STACK_SIZE - sizeof( CONTEXT ) );
    __vmx_vmwrite( HOST_RIP, (ULONG_PTR)VmxVMEntry );
}

