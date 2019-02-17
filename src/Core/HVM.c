#include "HVM.h"
#include "../Arch/Intel/EPT.h"
#include "../Arch/Intel/VMX.h"
#include "../Util/Utils.h"

/// <summary>
/// Check if VT-x/AMD-V is supported
/// </summary>
/// <returns>TRUE if supported</returns>
BOOLEAN HvmIsHVSupported()
{
    CPU_VENDOR vendor = UtilCPUVendor();
    if (vendor == CPU_Intel)
        return VmxHardSupported();

    return TRUE;
}

/// <summary>
/// CPU virtualization features
/// </summary>
VOID HvmCheckFeatures()
{
    CPU_VENDOR vendor = UtilCPUVendor();
    if (vendor == CPU_Intel)
        VmxCheckFeatures();
}

//
// Vendor-specific calls
//
inline VOID IntelSubvertCPU( IN PVCPU Vcpu, IN PVOID SystemDirectoryTableBase )
{
    VmxInitializeCPU( Vcpu, (ULONG64)SystemDirectoryTableBase );
}

inline VOID IntelRestoreCPU( IN PVCPU Vcpu )
{
    // Prevent execution of VMCALL on non-vmx CPU
    if (Vcpu->VmxState > VMX_STATE_OFF)
        VmxShutdown( Vcpu );
}

inline VOID AMDSubvertCPU( IN PVCPU Vcpu, IN PVOID arg )
{
    UNREFERENCED_PARAMETER( Vcpu );
    UNREFERENCED_PARAMETER( arg );
    DPRINT( "HyperBone: CPU %d: %s: AMD-V not yet supported\n", CPU_IDX, __FUNCTION__ );
}

inline VOID AMDRestoreCPU( IN PVCPU Vcpu )
{
    UNREFERENCED_PARAMETER( Vcpu );
    DPRINT( "HyperBone: CPU %d: %s: AMD-V not yet supported\n", CPU_IDX, __FUNCTION__ );
}

VOID HvmpHVCallbackDPC( PRKDPC Dpc, PVOID Context, PVOID SystemArgument1, PVOID SystemArgument2 )
{
    UNREFERENCED_PARAMETER( Dpc );
    PVCPU pVCPU = &g_Data->cpu_data[CPU_IDX];

    // Check if we are loading, or unloading
    if (ARGUMENT_PRESENT( Context ))
    {
        // Initialize the virtual processor
        g_Data->CPUVendor == CPU_Intel ? IntelSubvertCPU( pVCPU, Context ) : AMDSubvertCPU( pVCPU, Context );
    }
    else
    {
        // Tear down the virtual processor
        g_Data->CPUVendor == CPU_Intel ? IntelRestoreCPU( pVCPU ) : AMDRestoreCPU( pVCPU );
    }

    // Wait for all DPCs to synchronize at this point
    KeSignalCallDpcSynchronize( SystemArgument2 );

    // Mark the DPC as being complete
    KeSignalCallDpcDone( SystemArgument1 );
}


/// <summary>
/// Virtualize each CPU
/// </summary>
/// <returns>Status code</returns>
NTSTATUS StartHV()
{
    // Unknown CPU
    if (g_Data->CPUVendor == CPU_Other)
        return STATUS_NOT_SUPPORTED;

    KeGenericCallDpc( HvmpHVCallbackDPC, (PVOID)__readcr3() );

    // Some CPU failed
    ULONG count = KeQueryActiveProcessorCountEx( ALL_PROCESSOR_GROUPS );
    if (count != (ULONG)g_Data->vcpus)
    {
        DPRINT( "HyperBone: CPU %d: %s: Some CPU failed to subvert\n", CPU_IDX, __FUNCTION__ );
        StopHV();
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

/// <summary>
/// Devirtualize each CPU
/// </summary>
/// <returns>Status code</returns>
NTSTATUS StopHV()
{
	// Unknown CPU
	if (g_Data->CPUVendor == CPU_Other)
		return STATUS_NOT_SUPPORTED;

	//KeGenericCallDpc( HvmpHVCallbackDPC, NULL ); there will be Dead Lock


	//unload from HyperPlatform and they are works
	ULONG number_of_processors = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
	for (ULONG processor_index = 0; processor_index < number_of_processors; processor_index++) {
		PROCESSOR_NUMBER processor_number;
		RtlZeroMemory(&processor_number, sizeof(PROCESSOR_NUMBER));
		NTSTATUS status = KeGetProcessorNumberFromIndex(processor_index, &processor_number);
		if (!NT_SUCCESS(status))
		{
			DbgBreakPoint();
		}

		// Switch the current processor
		GROUP_AFFINITY affinity;
		RtlZeroMemory(&affinity, sizeof(GROUP_AFFINITY));
		affinity.Group = processor_number.Group;
		affinity.Mask = 1ull << processor_number.Number;
		GROUP_AFFINITY previous_affinity;
		RtlZeroMemory(&affinity, sizeof(GROUP_AFFINITY));
		KeSetSystemGroupAffinityThread(&affinity, &previous_affinity);

		PVCPU pVCPU = &g_Data->cpu_data[processor_index];
		IntelRestoreCPU(pVCPU);//todo amd vmoff???黑人问号?

		KeRevertToUserGroupAffinityThread(&previous_affinity);
		if (!NT_SUCCESS(status))
		{
			DbgBreakPoint();
		}
	}

	return STATUS_SUCCESS;
}

