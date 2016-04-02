#pragma once
#include <ntddk.h>

/// <summary>
/// Perform LSTAR hooking
/// </summary>
/// <returns>Status code</returns>
NTSTATUS SHInitHook();

/// <summary>
/// Hook specific SSDT entry
/// </summary>
/// <param name="index">SSDT index</param>
/// <param name="hookPtr">Hook address</param>
/// <param name="argCount">Number of function arguments</param>
/// <returns>Status code</returns>
NTSTATUS SHHookSyscall( IN ULONG index, IN PVOID hookPtr, IN CHAR argCount );

/// <summary>
/// Restore original SSDT entry
/// </summary>
/// <param name="index">SSDT index</param>
/// <returns>Status code</returns>
NTSTATUS SHRestoreSyscall( IN ULONG index );

/// <summary>
/// Unhook LSTAR
/// </summary>
/// <returns>Status code</returns>
NTSTATUS SHDestroyHook();
