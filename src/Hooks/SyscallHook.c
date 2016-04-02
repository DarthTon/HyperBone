#include "SyscallHook.h"
#include "../Include/CPU.h"
#include "../Arch/Intel/VMX.h"
#include "../Include/Common.h"
#include "../Util/Utils.h"
#include "../Include/Native.h"

#define MAX_SYSCALL_INDEX  0x1000

CHAR HookEnabled[MAX_SYSCALL_INDEX] = { 0 };
CHAR ArgTble[MAX_SYSCALL_INDEX]     = { 0 };
PVOID HookTable[MAX_SYSCALL_INDEX]  = { 0 };

ULONG64 KiSystemCall64Ptr   = 0;    // Original LSTAR value
ULONG64 KiServiceCopyEndPtr = 0;    // KiSystemServiceCopyEnd address

// Implemented in Syscall.asm
VOID SyscallEntryPoint();

/// <summary>
/// Per-CPU LSTAR hook/unhook routine
/// </summary>
/// <param name="Dpc">Unused</param>
/// <param name="Context">New LASTAR value if hooking, 0 if unhooking</param>
/// <param name="SystemArgument1">Unused</param>
/// <param name="SystemArgument2">Unused</param>
VOID SHpHookCallbackDPC( PRKDPC Dpc, PVOID Context, PVOID SystemArgument1, PVOID SystemArgument2 )
{
    UNREFERENCED_PARAMETER( Dpc );

    __vmx_vmcall( Context != NULL ? HYPERCALL_HOOK_LSTAR : HYPERCALL_UNHOOK_LSTAR, (ULONG64)Context, 0, 0 );
    KeSignalCallDpcSynchronize( SystemArgument2 );
    KeSignalCallDpcDone( SystemArgument1 );
}

/// <summary>
/// Perform LSTAR hooking
/// </summary>
/// <returns>Status code</returns>
NTSTATUS SHInitHook()
{
    NTSTATUS status = STATUS_SUCCESS;

    // No SSDT
    if (!UtilSSDTBase())
    {
        DPRINT( "HyperBone: CPU %d: %s: SSDT base not found\n", CPU_IDX, __FUNCTION__ );
        return STATUS_NOT_FOUND;
    }

    // KiSystemServiceCopyEnd
    // F7 05 ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? 0F 85 ? ? ? ? ? ? ? ? 41 FF D2
    if (KiServiceCopyEndPtr == 0)
    {
        CHAR pattern[] = "\xF7\x05\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\x0F\x85\xcc\xcc\xcc\xcc\x41\xFF\xD2";
        status = UtilScanSection( ".text", (PCUCHAR)pattern, 0xCC, sizeof( pattern ) - 1, (PVOID)&KiServiceCopyEndPtr );
        if (!NT_SUCCESS( status ))
        {
            DPRINT( "HyperBone: CPU %d: %s: KiSystemServiceCopyEnd not found\n", CPU_IDX, __FUNCTION__ );
            return status;
        }
    }

    // Hook LSTAR
    if (KiSystemCall64Ptr == 0)
    {
        KiSystemCall64Ptr = __readmsr( MSR_LSTAR );
        
        // Something isn't right
        if (KiSystemCall64Ptr == 0)
            return STATUS_UNSUCCESSFUL;

        KeGenericCallDpc( SHpHookCallbackDPC, (PVOID)(ULONG_PTR)SyscallEntryPoint );
        return STATUS_SUCCESS;
    }

    return STATUS_SUCCESS;
}

/// <summary>
/// Unhook LSTAR
/// </summary>
/// <returns>Status code</returns>
NTSTATUS SHDestroyHook()
{
    NTSTATUS status = STATUS_SUCCESS;
    if (KiSystemCall64Ptr != 0)
        KeGenericCallDpc( SHpHookCallbackDPC, NULL );

    if (NT_SUCCESS( status ))
        KiSystemCall64Ptr = 0;

    return status;
}

/// <summary>
/// Hook specific SSDT entry
/// </summary>
/// <param name="index">SSDT index</param>
/// <param name="hookPtr">Hook address</param>
/// <param name="argCount">Number of function arguments</param>
/// <returns>Status code</returns>
NTSTATUS SHHookSyscall( IN ULONG index, IN PVOID hookPtr, IN CHAR argCount )
{
    NTSTATUS status = STATUS_SUCCESS;
    if (index > MAX_SYSCALL_INDEX || hookPtr == NULL)
        return STATUS_INVALID_PARAMETER;

    KIRQL irql = KeGetCurrentIrql();
    if (irql < DISPATCH_LEVEL)
        irql = KeRaiseIrqlToDpcLevel();

    InterlockedExchange64( (PLONG64)&HookTable[index], (LONG64)hookPtr );
    InterlockedExchange8( &ArgTble[index], argCount );
    InterlockedExchange8( &HookEnabled[index], TRUE );

    if (KeGetCurrentIrql() > irql)
        KeLowerIrql( irql );

    return status;
}

/// <summary>
/// Restore original SSDT entry
/// </summary>
/// <param name="index">SSDT index</param>
/// <returns>Status code</returns>
NTSTATUS SHRestoreSyscall( IN ULONG index )
{
    if (index > MAX_SYSCALL_INDEX)
        return STATUS_INVALID_PARAMETER;

    KIRQL irql = KeGetCurrentIrql();
    if (irql < DISPATCH_LEVEL)
        irql = KeRaiseIrqlToDpcLevel();

    InterlockedExchange8( &HookEnabled[index], 0 );
    InterlockedExchange8( &ArgTble[index], 0 );
    InterlockedExchange64( (PLONG64)&HookTable[index], 0 );

    if( KeGetCurrentIrql() > irql )
        KeLowerIrql( irql );

    return STATUS_SUCCESS;
}

