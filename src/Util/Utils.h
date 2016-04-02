#pragma once
#include <ntddk.h>

/// <summary>
/// Get CPU vendor
/// </summary>
/// <returns>Intel or AMD. If failed - Other</returns>
enum _CPU_VENDOR UtilCPUVendor();

/// <summary>
/// Get ntoskrnl base address
/// </summary>
/// <param name="pSize">Size of module</param>
/// <returns>Found address, NULL if not found</returns>
PVOID UtilKernelBase( OUT PULONG pSize );

/// <summary>
/// Gets SSDT base - KiSystemServiceTable
/// </summary>
/// <returns>SSDT base, NULL if not found</returns>
struct _SYSTEM_SERVICE_DESCRIPTOR_TABLE* UtilSSDTBase();

/// <summary>
/// Gets the SSDT entry address by index.
/// </summary>
/// <param name="index">Service index</param>
/// <returns>Found service address, NULL if not found</returns>
PVOID UtilSSDTEntry( IN ULONG index );

/// <summary>
/// Gather info about used physical pages
/// </summary>
/// <returns>Status code</returns>
NTSTATUS UtilQueryPhysicalMemory();

/// <summary>
/// Change protection of nonpaged system address
/// </summary>
/// <param name="ptr">Address</param>
/// <param name="size">Size of region</param>
/// <param name="protection">New protection flags</param>
/// <returns>Status code</returns>
NTSTATUS UtilProtectNonpagedMemory( IN PVOID ptr, IN ULONG64 size, IN ULONG protection );

/// <summary>
/// Search for pattern
/// </summary>
/// <param name="pattern">Pattern to search for</param>
/// <param name="wildcard">Used wildcard</param>
/// <param name="len">Pattern length</param>
/// <param name="base">Base address for searching</param>
/// <param name="size">Address range to search in</param>
/// <param name="ppFound">Found location</param>
/// <returns>Status code</returns>
NTSTATUS UtilSearchPattern( IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, IN const VOID* base, IN ULONG_PTR size, OUT PVOID* ppFound );

/// <summary>
/// Find pattern in kernel PE section
/// </summary>
/// <param name="section">Section name</param>
/// <param name="pattern">Pattern data</param>
/// <param name="wildcard">Pattern wildcard symbol</param>
/// <param name="len">Pattern length</param>
/// <param name="ppFound">Found address</param>
/// <returns>Status code</returns>
NTSTATUS UtilScanSection( IN PCCHAR section, IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, OUT PVOID* ppFound );