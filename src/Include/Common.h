#pragma once
#include "Native.h"
#include <ntddk.h>

#define DPRINT(format, ...)         DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, format, __VA_ARGS__)
//#define DPRINT(format, ...)        
#define HB_POOL_TAG                '0mVZ'

#define NBP_MAGIC                   ((ULONG32)'!LTI')
#define HYPERCALL_UNLOAD            0x1
#define HYPERCALL_HOOK_LSTAR        0x2
#define HYPERCALL_UNHOOK_LSTAR      0x3
#define HYPERCALL_HOOK_PAGE         0x4
#define HYPERCALL_UNHOOK_PAGE       0x5

#define MAX_CPU_PER_GROUP           64

#define BUG_CHECK_UNSPECIFIED       0
#define BUG_CHECK_INVALID_VM        1
#define BUG_CHECK_TRIPLE_FAULT      2
#define BUG_CHECK_EPT_MISCONFIG     3
#define BUG_CHECK_EPT_VIOLATION     4
#define BUG_CHECK_EPT_NO_PAGES      5

#define CPU_IDX                     (KeGetCurrentProcessorNumberEx( NULL ))
#define PFN(addr)                   (ULONG64)((addr) >> PAGE_SHIFT)
#define SSDTIndex(ptr)              *(PULONG)((ULONG_PTR)ptr + 0x15)

#define PAGES_PER_ENTRY             ((PAGE_SIZE - sizeof( LIST_ENTRY ) - sizeof( ULONG64 )) / sizeof( union _EPT_MMPTE* ))
#define EPT_PREALLOC_PAGES          512

/// <summary>
/// CPU vendor
/// </summary>
typedef enum _CPU_VENDOR
{
    CPU_Other = 0,
    CPU_Intel,
    CPU_AMD
} CPU_VENDOR;

/// <summary>
/// Virtual CPU state
/// </summary>
typedef enum _VCPU_VMX_STATE
{
    VMX_STATE_OFF        = 0,   // No virtualization
    VMX_STATE_TRANSITION = 1,   // Virtualized, context not yet restored
    VMX_STATE_ON         = 2    // Virtualized, running guest
} VCPU_VMX_STATE;

#pragma warning(disable: 4214)

/// <summary>
/// VMXON and VMCS regions
/// </summary>
typedef struct _VMX_VMCS
{
    ULONG RevisionId;
    ULONG AbortIndicator;
    UCHAR Data[PAGE_SIZE - 2 * sizeof( ULONG )];
} VMX_VMCS, *PVMX_VMCS;

/// <summary>
/// EPT pages storage
/// </summary>
typedef struct _EPT_PAGES_ENTRY
{
    LIST_ENTRY link;
    ULONG64 count;
    union _EPT_MMPTE* pages[PAGES_PER_ENTRY];
} EPT_PAGES_ENTRY, *PEPT_PAGES_ENTRY;

typedef struct _VMX_FEATURES
{
    ULONG64 SecondaryControls : 1;  // Secondary controls are enabled
    ULONG64 TrueMSRs : 1;           // True VMX MSR values are supported
    ULONG64 EPT : 1;                // EPT supported by CPU
    ULONG64 VPID : 1;               // VPID supported by CPU
    ULONG64 ExecOnlyEPT : 1;        // EPT translation with execute-only access is supported
    ULONG64 InvSingleAddress : 1;   // IVVPID for single address
    ULONG64 VMFUNC : 1;             // VMFUNC is supported
} VMX_FEATURES, *PVMX_FEATURES;

/// <summary>
/// VCPU EPT info
/// </summary>
typedef struct _EPT_DATA
{
    union _EPT_MMPTE* PML4Ptr;                      // EPT PML4 pointer
    LIST_ENTRY PageList;                            // EPT_PAGES_ENTRY list
    union _EPT_MMPTE* Pages[EPT_PREALLOC_PAGES];    // Array of preallocated pages
    ULONG Preallocations;                           // Number of used preallocated pages
    ULONG TotalPages;                               // Total number of EPT pages
} EPT_DATA, *PEPT_DATA;

/// <summary>
/// Page hook trace state
/// </summary>
typedef struct _PAGE_HOOK_STATE
{
    struct _PAGE_HOOK_ENTRY* pEntry;
    ULONG64 Rip;
} PAGE_HOOK_STATE, *PPAGE_HOOK_STATE;

/// <summary>
/// Virtual CPU stuff
/// </summary>
typedef struct _VCPU
{
    KPROCESSOR_STATE HostState;             // Host CPU state before virtualization
    volatile VCPU_VMX_STATE VmxState;       // CPU virtualization state
    ULONG64 SystemDirectoryTableBase;       // Kernel CR3
    LARGE_INTEGER MsrData[18];              // VMX-specific MSR data
    PVMX_VMCS VMXON;                        // VMXON region
    PVMX_VMCS VMCS;                         // VMCS region
    PVOID VMMStack;                         // Host VMM stack memory
    EPT_DATA EPT;                           // EPT mapping data
    ULONG64 OriginalLSTAR;                  // LSTAR MSR value
    ULONG64 TscOffset;                      // TSC VMM offset value
    PAGE_HOOK_STATE HookDispatch;           // Page hooking trace state
} VCPU, *PVCPU;

/// <summary>
/// Global data
/// </summary>
typedef struct _GLOBAL_DATA
{
    CPU_VENDOR CPUVendor;                   // Intel or AMD
    VMX_FEATURES Features;                  // VMX CPU features
    PPHYSICAL_MEMORY_DESCRIPTOR Memory;     // Used PFN regions
    PUCHAR MSRBitmap;                       // MSR vmexit bitmap
    LONG vcpus;                             // Number of virtualized CPUs
    VCPU cpu_data[ANYSIZE_ARRAY];           // Per-CPU data
} GLOBAL_DATA, *PGLOBAL_DATA;

extern PGLOBAL_DATA g_Data;
#pragma warning(default: 4214)
