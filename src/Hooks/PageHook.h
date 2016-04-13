#pragma once
#include <ntddk.h>

typedef enum _PAGE_TYPE
{
    DATA_PAGE = 0,
    CODE_PAGE = 1,
} PAGE_TYPE;

typedef struct _PAGE_HOOK_ENTRY
{
    LIST_ENTRY Link;
    PVOID OriginalPtr;      // Original function VA
    PVOID DataPageVA;       // Data page VA
    ULONG64 DataPagePFN;    // Data page PFN
    PVOID CodePageVA;       // Executable page VA
    ULONG64 CodePagePFN;    // Executable page PFN
    ULONG OriginalSize;     // Size of original data
    UCHAR OriginalData[80]; // Original bytes + jump
} PAGE_HOOK_ENTRY, *PPAGE_HOOK_ENTRY;

/// <summary>
/// Hook function
/// </summary>
/// <param name="pFunc">Function address</param>
/// <param name="pHook">Hook address</param>
/// /// <param name="Type">Hook type</param>
/// <returns>Status code</returns>
NTSTATUS PHHook( IN PVOID pFunc, IN PVOID pHook );

/// <summary>
/// Restore hooked function
/// </summary>
/// <param name="pFunc">Function address</param>
/// <returns>Status code</returns>
NTSTATUS PHRestore( IN PVOID pFunc );

/// <summary>
/// Get hook data by function pointer
/// </summary>
/// <param name="ptr">Function address</param>
/// <returns>Found entry or NULL</returns>
PPAGE_HOOK_ENTRY PHGetHookEntry( IN PVOID ptr );

/// <summary>
/// Get number of hooks in one page
/// </summary>
/// <param name="ptr">Function address</param>
/// <param name="Type">Page type</param>
/// <returns>Number of hooks</returns>
ULONG PHPageHookCount( IN PVOID ptr, IN PAGE_TYPE Type );

/// <summary>
/// Get hook data by page address
/// </summary>
/// <param name="ptr">Function pointer</param>
/// <param name="Type">Page type</param>
/// <returns>Found hook entry or NULL</returns>
PPAGE_HOOK_ENTRY PHGetHookEntryByPage( IN PVOID ptr, IN PAGE_TYPE Type );

/// <summary>
/// Get hook data by Physical page frame number
/// </summary>
/// <param name="pfn">PFN</param>
/// <param name="Type">Page type</param>
/// <returns>Found hook entry or NULL</returns>
PPAGE_HOOK_ENTRY PHGetHookEntryByPFN( IN ULONG64 pfn, IN PAGE_TYPE Type );