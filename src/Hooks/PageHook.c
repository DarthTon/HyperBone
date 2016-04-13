#include "PageHook.h"
#include "../Include/Common.h"
#include "../Arch/Intel/VMX.h"
#include "../Arch/Intel/EPT.h"
#include "../Util/LDasm.h"

LIST_ENTRY g_PageList = { 0 };

typedef struct _HOOK_CONTEXT
{
    BOOLEAN Hook;           // TRUE to hook page, FALSE to unhook
    ULONG64 DataPagePFN;    // Physical data page PFN
    ULONG64 CodePagePFN;    // Physical code page PFN
} HOOK_CONTEXT, *PHOOK_CONTEXT;

#pragma pack(push, 1)
typedef struct _JUMP_THUNK
{
    UCHAR PushOp;           // 0x68
    ULONG AddressLow;       // 
    ULONG MovOp;            // 0x042444C7
    ULONG AddressHigh;      // 
    UCHAR RetOp;            // 0xC3
} JUMP_THUNK, *PJUMP_THUNK;
#pragma pack(pop)

/// <summary>
/// Construct jump 
/// </summary>
/// <param name="pThunk">Data to initialize</param>
/// <param name="To">Address of jump</param>
VOID PHpInitJumpThunk( IN OUT PJUMP_THUNK pThunk, IN ULONG64 To )
{
    PULARGE_INTEGER liTo = (PULARGE_INTEGER)&To;

    pThunk->PushOp = 0x68;
    pThunk->AddressLow = liTo->LowPart;
    pThunk->MovOp = 0x042444C7;
    pThunk->AddressHigh = liTo->HighPart;
    pThunk->RetOp = 0xC3;
}

/// <summary>
/// Per-CPU page hook/unhook routine
/// </summary>
/// <param name="Dpc">Unused</param>
/// <param name="Context">Valid PHOOK_CONTEXT</param>
/// <param name="SystemArgument1">Unused</param>
/// <param name="SystemArgument2">Unused</param>
VOID PHpHookCallbackDPC( IN PRKDPC Dpc, IN PVOID Context, IN PVOID SystemArgument1, IN PVOID SystemArgument2 )
{
    UNREFERENCED_PARAMETER( Dpc );
    PHOOK_CONTEXT pCTX = (PHOOK_CONTEXT)Context;

    if (pCTX != NULL)
        __vmx_vmcall( pCTX->Hook ? HYPERCALL_HOOK_PAGE : HYPERCALL_UNHOOK_PAGE, pCTX->DataPagePFN, pCTX->CodePagePFN, 0 );

    KeSignalCallDpcSynchronize( SystemArgument2 );
    KeSignalCallDpcDone( SystemArgument1 );
}

/// <summary>
/// Copy original bytes using LDASM
/// </summary>
/// <param name="pFunc">Original function ptr</param>
/// <param name="OriginalStore">Buffer to store bytes</param>
/// <param name="pSize">Lenght of copied data</param>
/// <returns>Status code</returns>
NTSTATUS PHpCopyCode( IN PVOID pFunc, OUT PUCHAR OriginalStore, OUT PULONG pSize )
{
    // Store original bytes
    PUCHAR src = pFunc;
    PUCHAR old = OriginalStore;
    ULONG all_len = 0;
    ldasm_data ld = { 0 };

    do
    {
        ULONG len = ldasm( src, &ld, TRUE );

        // Determine code end
        if (ld.flags & F_INVALID
            || (len == 1 && (src[ld.opcd_offset] == 0xCC || src[ld.opcd_offset] == 0xC3))
            || (len == 3 && src[ld.opcd_offset] == 0xC2)
            || len + all_len > 128)
        {
            break;
        }

        // move instruction 
        memcpy( old, src, len );

        // if instruction has relative offset, calculate new offset 
        if (ld.flags & F_RELATIVE)
        {
            LONG diff = 0;
            const uintptr_t ofst = (ld.disp_offset != 0 ? ld.disp_offset : ld.imm_offset);
            const uintptr_t sz = ld.disp_size != 0 ? ld.disp_size : ld.imm_size;

            memcpy( &diff, src + ofst, sz );
            // exit if jump is greater then 2GB
            if (_abs64( src + len + diff - old ) > INT_MAX)
            {
                break;
            }
            else
            {
                diff += (LONG)(src - old);
                memcpy( old + ofst, &diff, sz );
            }
        }

        src += len;
        old += len;
        all_len += len;

    } while (all_len < sizeof( JUMP_THUNK ));

    // Failed to copy old code, use backup plan
    if (all_len < sizeof( JUMP_THUNK ))
    {
        return STATUS_UNSUCCESSFUL;
    }
    else
    {
        PHpInitJumpThunk( (PJUMP_THUNK)old, (ULONG64)src );
        *pSize = all_len;
    }

    return STATUS_SUCCESS;
}

/// <summary>
/// Hook function
/// </summary>
/// <param name="pFunc">Function address</param>
/// <param name="pHook">Hook address</param>
/// /// <param name="Type">Hook type</param>
/// <returns>Status code</returns>
NTSTATUS PHHook( IN PVOID pFunc, IN PVOID pHook )
{
    PUCHAR CodePage = NULL;
    BOOLEAN Newpage = FALSE;
    PHYSICAL_ADDRESS phys = { 0 };
    phys.QuadPart = MAXULONG64;

    // No CPU support
    if (!g_Data->Features.EPT || !g_Data->Features.ExecOnlyEPT)
        return STATUS_NOT_SUPPORTED;

    // Check if page is already hooked
    PPAGE_HOOK_ENTRY pEntry = PHGetHookEntryByPage( pFunc, DATA_PAGE );
    if (pEntry != NULL)
    {
        CodePage = pEntry->CodePageVA;
    }
    else
    {
        CodePage = MmAllocateContiguousMemory( PAGE_SIZE, phys );
        Newpage = TRUE;
    }

    if (CodePage == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    PPAGE_HOOK_ENTRY pHookEntry = ExAllocatePoolWithTag( NonPagedPool, sizeof( PAGE_HOOK_ENTRY ), HB_POOL_TAG );
    if (pHookEntry == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    RtlZeroMemory( pHookEntry, sizeof( PAGE_HOOK_ENTRY ) );
    RtlCopyMemory( CodePage, PAGE_ALIGN( pFunc ), PAGE_SIZE );
    
    // Copy original code
    NTSTATUS status = PHpCopyCode( pFunc, pHookEntry->OriginalData, &pHookEntry->OriginalSize );
    if (!NT_SUCCESS( status ))
    {
        ExFreePoolWithTag( pHookEntry, HB_POOL_TAG );
        return status;
    }

    ULONG_PTR page_offset = (ULONG_PTR)pFunc - (ULONG_PTR)PAGE_ALIGN( pFunc );

    // TODO: atomic memory patching, i.e. with other CPUs spinlocked
    JUMP_THUNK thunk = { 0 };
    PHpInitJumpThunk( &thunk, (ULONG64)pHook );
    memcpy( CodePage + page_offset, &thunk, sizeof( thunk ) );

    pHookEntry->OriginalPtr = pFunc;
    pHookEntry->DataPageVA = PAGE_ALIGN( pFunc );
    pHookEntry->DataPagePFN = PFN( MmGetPhysicalAddress( pFunc ).QuadPart );
    pHookEntry->CodePageVA = CodePage;
    pHookEntry->CodePagePFN = PFN( MmGetPhysicalAddress( CodePage ).QuadPart );

    // Add to list
    if (g_PageList.Flink == NULL)
        InitializeListHead( &g_PageList );
    InsertTailList( &g_PageList, &pHookEntry->Link );

    // Create EPT page translation
    if (Newpage)
    {
        HOOK_CONTEXT ctx = { 0 };
        ctx.Hook = TRUE;
        ctx.DataPagePFN = pHookEntry->DataPagePFN;
        ctx.CodePagePFN = pHookEntry->CodePagePFN;

        KeGenericCallDpc( PHpHookCallbackDPC, &ctx );
    }

    return STATUS_SUCCESS;
}

/// <summary>
/// Restore hooked function
/// </summary>
/// <param name="pFunc">Function address</param>
/// <returns>Status code</returns>
NTSTATUS PHRestore( IN PVOID pFunc )
{
    // No CPU support
    if (!g_Data->Features.ExecOnlyEPT)
        return STATUS_NOT_SUPPORTED;

    PPAGE_HOOK_ENTRY pHookEntry = PHGetHookEntry( pFunc );
    if (pHookEntry == NULL)
        return STATUS_NOT_FOUND;

    // Restore original bytes
    if (PHPageHookCount( pFunc, DATA_PAGE ) > 1)
    {
        // TODO: atomic memory patching, i.e. with other CPUs spinlocked
        ULONG_PTR page_offset = (ULONG_PTR)pFunc - (ULONG_PTR)PAGE_ALIGN( pFunc );
        memcpy( (PUCHAR)pHookEntry->CodePageVA + page_offset, pHookEntry->OriginalData, pHookEntry->OriginalSize );
    }
    // Swap pages
    else
    {
        HOOK_CONTEXT ctx = { 0 };
        ctx.Hook = FALSE;
        ctx.DataPagePFN = pHookEntry->DataPagePFN;
        ctx.CodePagePFN = pHookEntry->CodePagePFN;;

        KeGenericCallDpc( PHpHookCallbackDPC, &ctx );
    }

    MmFreeContiguousMemory( pHookEntry->CodePageVA );
    RemoveEntryList( &pHookEntry->Link );
    ExFreePoolWithTag( pHookEntry, HB_POOL_TAG );
    
    return STATUS_SUCCESS;
}

/// <summary>
/// Get hook data by function pointer
/// </summary>
/// <param name="ptr">Function address</param>
/// <returns>Found entry or NULL</returns>
PPAGE_HOOK_ENTRY PHGetHookEntry( IN PVOID ptr )
{
    if (g_PageList.Flink == NULL || IsListEmpty( &g_PageList ))
        return NULL;

    for (PLIST_ENTRY pListEntry = g_PageList.Flink; pListEntry != &g_PageList; pListEntry = pListEntry->Flink)
    {
        PPAGE_HOOK_ENTRY pEntry = CONTAINING_RECORD( pListEntry, PAGE_HOOK_ENTRY, Link );
        if (pEntry->OriginalPtr == ptr)
            return pEntry;
    }

    return NULL;
}

/// <summary>
/// Get number of hooks in one page
/// </summary>
/// <param name="ptr">Function address</param>
/// <param name="Type">Page type</param>
/// <returns>Number of hooks</returns>
ULONG PHPageHookCount( IN PVOID ptr, IN PAGE_TYPE Type )
{
    ULONG count = 0;
    if (g_PageList.Flink == NULL || IsListEmpty( &g_PageList ))
        return count;

    PVOID page = PAGE_ALIGN( ptr );
    for (PLIST_ENTRY pListEntry = g_PageList.Flink; pListEntry != &g_PageList; pListEntry = pListEntry->Flink)
    {
        PPAGE_HOOK_ENTRY pEntry = CONTAINING_RECORD( pListEntry, PAGE_HOOK_ENTRY, Link );
        if ((Type == DATA_PAGE && pEntry->DataPageVA == page) || (Type == CODE_PAGE && pEntry->CodePageVA == page))
            count++;
    }

    return count;
}

/// <summary>
/// Get hook data by page address
/// </summary>
/// <param name="ptr">Function pointer</param>
/// <param name="Type">Page type</param>
/// <returns>Found hook entry or NULL</returns>
PPAGE_HOOK_ENTRY PHGetHookEntryByPage( IN PVOID ptr, IN PAGE_TYPE Type )
{
    if (g_PageList.Flink == NULL || IsListEmpty( &g_PageList ))
        return NULL;

    PVOID page = PAGE_ALIGN( ptr );
    for (PLIST_ENTRY pListEntry = g_PageList.Flink; pListEntry != &g_PageList; pListEntry = pListEntry->Flink)
    {
        PPAGE_HOOK_ENTRY pEntry = CONTAINING_RECORD( pListEntry, PAGE_HOOK_ENTRY, Link );
        if ((Type == DATA_PAGE && pEntry->DataPageVA == page) || (Type == CODE_PAGE && pEntry->CodePageVA == page))
            return pEntry;
    }

    return NULL;
}

/// <summary>
/// Get hook data by Physical page frame number
/// </summary>
/// <param name="pfn">PFN</param>
/// <param name="Type">Page type</param>
/// <returns>Found hook entry or NULL</returns>
PPAGE_HOOK_ENTRY PHGetHookEntryByPFN( IN ULONG64 pfn, IN PAGE_TYPE Type )
{
    if (g_PageList.Flink == NULL || IsListEmpty( &g_PageList ))
        return NULL;

    for (PLIST_ENTRY pListEntry = g_PageList.Flink; pListEntry != &g_PageList; pListEntry = pListEntry->Flink)
    {
        PPAGE_HOOK_ENTRY pEntry = CONTAINING_RECORD( pListEntry, PAGE_HOOK_ENTRY, Link );
        if ((Type == DATA_PAGE && pEntry->DataPagePFN == pfn) || (Type == CODE_PAGE && pEntry->CodePagePFN == pfn))
            return pEntry;
    }

    return NULL;
}

