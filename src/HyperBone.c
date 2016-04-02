#include "Core/HVM.h"
#include "Include/CPU.h"
#include "Include/Common.h"
#include "Util/Utils.h"
#include "Test/Tests.h"

NTSTATUS DriverEntry( IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING registryPath );
VOID     HBUnload( IN PDRIVER_OBJECT DriverObject );

#pragma alloc_text(INIT, DriverEntry)

PGLOBAL_DATA g_Data = NULL;

/// <summary>
/// Allocate global data
/// </summary>
/// <returns>Allocated data or NULL</returns>
PGLOBAL_DATA AllocGlobalData()
{
    PHYSICAL_ADDRESS low = { 0 }, high = { 0 };
    high.QuadPart = MAXULONG64;

    ULONG cpu_count = KeQueryActiveProcessorCountEx( ALL_PROCESSOR_GROUPS );
    ULONG_PTR size = FIELD_OFFSET( GLOBAL_DATA, cpu_data ) + cpu_count * sizeof( VCPU );
    PGLOBAL_DATA pData = (PGLOBAL_DATA)ExAllocatePoolWithTag( NonPagedPoolNx, size, HB_POOL_TAG );
    if (pData == NULL)
        return NULL;

    RtlZeroMemory( pData, size );

    pData->MSRBitmap = ExAllocatePoolWithTag( NonPagedPoolNx, PAGE_SIZE, HB_POOL_TAG );
    if (pData->MSRBitmap == NULL)
    {
        ExFreePoolWithTag( pData, HB_POOL_TAG );
        return NULL;
    }

    RtlZeroMemory( pData->MSRBitmap, PAGE_SIZE );

    pData->CPUVendor = UtilCPUVendor();

    for (ULONG i = 0; i < cpu_count; i++)
    {
        PVCPU Vcpu = &pData->cpu_data[i];

        InitializeListHead( &Vcpu->EPT.PageList );

        for (ULONG j = 0; j < EPT_PREALLOC_PAGES; j++)
        {
            Vcpu->EPT.Pages[j] = MmAllocateContiguousMemorySpecifyCache( PAGE_SIZE, low, high, low, MmNonCached );
            if (Vcpu->EPT.Pages[j] != NULL)
            {
                UtilProtectNonpagedMemory( Vcpu->EPT.Pages[j], PAGE_SIZE, PAGE_READWRITE );
                RtlZeroMemory( Vcpu->EPT.Pages[j], PAGE_SIZE );
            }
        }
    }

    return pData;
}

/// <summary>
/// Free global data
/// </summary>
/// <param name="pData">Data pointer</param>
VOID FreeGlobalData( IN PGLOBAL_DATA pData )
{
    if (pData == NULL)
        return;

    ULONG cpu_count = KeQueryActiveProcessorCountEx( ALL_PROCESSOR_GROUPS );
    for (ULONG i = 0; i < cpu_count; i++)
    {
        PVCPU Vcpu = &pData->cpu_data[i];
        if (Vcpu->VMXON)
            MmFreeContiguousMemory( Vcpu->VMXON );
        if (Vcpu->VMCS)
            MmFreeContiguousMemory( Vcpu->VMCS );
        if (Vcpu->VMMStack)
            MmFreeContiguousMemory( Vcpu->VMMStack );

        for (ULONG j = 0; j < EPT_PREALLOC_PAGES; j++)
            if (Vcpu->EPT.Pages[j] != NULL)
                MmFreeContiguousMemory( Vcpu->EPT.Pages[j] );
    }

    if (pData->Memory)
        ExFreePoolWithTag( pData->Memory, HB_POOL_TAG );
    if (pData->MSRBitmap)
        ExFreePoolWithTag( pData->MSRBitmap, HB_POOL_TAG );

    ExFreePoolWithTag( pData, HB_POOL_TAG );
}

/*
*/
NTSTATUS DriverEntry( IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath )
{
    NTSTATUS status = STATUS_SUCCESS;
    UNREFERENCED_PARAMETER( RegistryPath );

    if (!HvmIsHVSupported())
    {
        DPRINT( "HyperBone: CPU %d: %s: VMX/AMD-V is not supported, aborting\n", CPU_IDX, __FUNCTION__ );
        return STATUS_HV_FEATURE_UNAVAILABLE;
    }

    if (UtilSSDTEntry( 0 ) == 0)
    {
        DPRINT( "HyperBone: CPU %d: %s: Failed to Get SSDT/Kernel base, can't continue\n", CPU_IDX, __FUNCTION__ );
        return STATUS_UNSUCCESSFUL;
    }

    g_Data = AllocGlobalData();
    if (g_Data == NULL)
    {
        DPRINT( "HyperBone: CPU %d: %s: Failed to allocate global data\n", CPU_IDX, __FUNCTION__ );
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (!NT_SUCCESS( UtilQueryPhysicalMemory() ))
    {
        DPRINT( "HyperBone: CPU %d: %s: Failed to query physical memory ranges\n", CPU_IDX, __FUNCTION__ );
        FreeGlobalData( g_Data );
        return STATUS_UNSUCCESSFUL;
    }

    DPRINT( "HyperBone: CPU %d: %s: Subverting started...\n", CPU_IDX, __FUNCTION__ );
    if (!NT_SUCCESS( StartHV() ))
    {
        DPRINT( "HyperBone: CPU %d: %s: StartHV() failed\n", CPU_IDX, __FUNCTION__ );
        FreeGlobalData( g_Data );
        return STATUS_UNSUCCESSFUL;
    }

    DPRINT( "HyperBone: CPU %d: %s: Subverting finished\n", CPU_IDX, __FUNCTION__ );

    TestStart( TRUE, TRUE, TRUE );
    DriverObject->DriverUnload = HBUnload;  
    return status;
}

/*
*/
VOID HBUnload( IN PDRIVER_OBJECT DriverObject )
{
    UNREFERENCED_PARAMETER( DriverObject );

    TestPrintResults();
    TestStop();

    NTSTATUS status = StopHV();
    DPRINT( "HyperBone: CPU %d: %s: Unload %s\n", CPU_IDX, __FUNCTION__, NT_SUCCESS( status ) ? "SUCCEDED" : "FAILED" );
    FreeGlobalData( g_Data );
}