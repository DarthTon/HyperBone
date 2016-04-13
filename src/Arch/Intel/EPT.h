#pragma once
#define VM_VPID             1
#define EPT_TABLE_ORDER     9
#define EPT_TABLE_ENTRIES   512

/// <summary>
/// EPT page access
/// </summary>
typedef enum _EPT_ACCESS
{
    EPT_ACCESS_NONE  = 0,
    EPT_ACCESS_READ  = 1,
    EPT_ACCESS_WRITE = 2,
    EPT_ACCESS_EXEC  = 4,
    EPT_ACCESS_RW    = EPT_ACCESS_READ | EPT_ACCESS_WRITE,
    EPT_ACCESS_ALL   = EPT_ACCESS_READ | EPT_ACCESS_WRITE | EPT_ACCESS_EXEC
} EPT_ACCESS;


/// <summary>
/// ETP table level
/// </summary>
typedef enum _EPT_TABLE_LEVEL
{
    EPT_LEVEL_PTE   = 0,
    EPT_LEVEL_PDE   = 1,
    EPT_LEVEL_PDPTE = 2,
    EPT_LEVEL_PML4  = 3,
    EPT_TOP_LEVEL   = EPT_LEVEL_PML4
} EPT_TABLE_LEVEL;

#pragma warning(disable: 4214)
#pragma pack(push, 1)
/// <summary>
///  PEPT
/// </summary>
typedef union _EPT_TABLE_POINTER
{
    ULONG64 All;
    struct
    {
        ULONG64 MemoryType : 3;         // EPT Paging structure memory type (0 for UC)
        ULONG64 PageWalkLength : 3;     // Page-walk length
        ULONG64 reserved1 : 6;
        ULONG64 PhysAddr : 40;          // Physical address of the EPT PML4 table
        ULONG64 reserved2 : 12;
    } Fields;
} EPT_TABLE_POINTER, *PEPT_TABLE_POINTER;

/// <summary>
/// PML4, PDPTE, PDTE pointing to another table
/// </summary>
typedef union _EPT_MMPTE
{
    ULONG64 All;
    struct
    {
        ULONG64 Present : 1;    // If the region is present (read access)
        ULONG64 Write : 1;      // If the region is writable
        ULONG64 Execute : 1;    // If the region is executable
        ULONG64 reserved1 : 9;  // Reserved
        ULONG64 PhysAddr : 40;  // Physical address
        ULONG64 reserved2 : 12; // Reserved
    } Fields;
} EPT_PML4_ENTRY, EPT_MMPTE, *PEPT_PML4_ENTRY, *PEPT_MMPTE;

/// <summary>
/// 2 MB PDE entry
/// </summary>
typedef union _EPT_PDE_LARGE_ENTRY
{
    ULONG64 All;
    struct
    {
        ULONG64 Present : 1;        // If the 2 MB region is present (read access)
        ULONG64 Write : 1;          // If the 2 MB region is writable
        ULONG64 Execute : 1;        // If the 2 MB region is executable
        ULONG64 MemoryType : 3;     // EPT Memory type
        ULONG64 IgnorePat : 1;      // Flag for whether to ignore PAT
        ULONG64 Size : 1;           // Must be 1
        ULONG64 reserved1 : 13;     // Reserved
        ULONG64 PhysAddr : 40;      // Physical address
        ULONG64 reserved2 : 12;     // Reserved
    } Fields;
} EPT_PDE_LARGE_ENTRY, *PEPT_PDE_LARGE_ENTRY;

/// <summary>
/// PTE entry
/// </summary>
typedef union _EPT_PTE_ENTRY
{
    ULONG64 All;
    struct
    {
        ULONG64 Read : 1;           // Region is present (read access)
        ULONG64 Write : 1;          // Region is writable
        ULONG64 Execute : 1;        // Region is executable
        ULONG64 MemoryType : 3;     // EPT Memory type
        ULONG64 IgnorePat : 1;      // Flag for whether to ignore PAT
        ULONG64 reserved1 : 5;      // Reserved
        ULONG64 PhysAddr : 40;      // Physical address
        ULONG64 reserved2 : 12;     // Reserved
    } Fields;
} EPT_PTE_ENTRY, *PEPT_PTE_ENTRY;

/// <summary>
/// Guest physical to host physical address bits
/// </summary>
typedef union _GUEST_PHYSICAL
{
    ULONG64 All;
    struct
    {
        ULONG64 offset : 12;    // [0-11]
        ULONG64 pte : 9;        // [12-20]
        ULONG64 pde : 9;        // [21-29]
        ULONG64 pdpte : 9;      // [30-38]
        ULONG64 pml4 : 9;       // [39-47]
        ULONG64 reserved : 16;  // Reserved
    } Fields;
} GUEST_PHYSICAL, *PGUEST_PHYSICAL;

/// <summary>
/// Exit qualification for EPT violation
/// </summary>
typedef union _EPT_VIOLATION_DATA
{
    ULONG64 All;
    struct
    {
        ULONG64 Read : 1;           // Read access
        ULONG64 Write : 1;          // Write access
        ULONG64 Execute : 1;        // Execute access
        ULONG64 PTERead : 1;        // PTE entry has read access
        ULONG64 PTEWrite : 1;       // PTE entry has write access
        ULONG64 PTEExecute : 1;     // PTE entry has execute access
        ULONG64 Reserved1 : 1;      // 
        ULONG64 GuestLinear : 1;    // GUEST_LINEAR_ADDRESS field is valid
        ULONG64 FailType : 1;       // 
        ULONG64 Reserved2 : 3;      // 
        ULONG64 NMIBlock : 1;       // NMI unblocking due to IRET
        ULONG64 Reserved3 : 51;     // 
    } Fields;
} EPT_VIOLATION_DATA, *PEPT_VIOLATION_DATA;

struct _EPT_DATA;
#pragma pack(pop)
#pragma warning(default: 4214)

/// <summary>
/// Enable EPT for CPU
/// </summary>
/// <param name="PML4">PML4 pointer to use</param>
VOID EptEnable( IN PEPT_PML4_ENTRY PML4 );

/// <summary>
/// Disable EPT for CPU
/// </summary>
VOID EptDisable();

/// <summary>
/// Create Guest to Host page mappings
/// </summary>
/// <param name="pEPT">CPU EPT data</param>
/// <returns>Status code</returns>
NTSTATUS EptBuildIdentityMap( IN struct _EPT_DATA* pEPT );

/// <summary>
/// Release Guest to Host page mappings
/// </summary>
/// <param name="pEPT">CPU EPT data</param>
/// <returns>Status code</returns>
NTSTATUS EptFreeIdentityMap( IN struct _EPT_DATA* pEPT );

/// <summary>
/// Update EPT entry
/// </summary>
/// <param name="pEPTData">CPU EPT data</param>
/// <param name="pTable">EPT table</param>
/// <param name="level">EPT table level</param>
/// <param name="pfn">Page frame number to update</param>
/// <param name="access">New PFN access</param>
/// <param name="hostPFN">New hot PFN</param>
/// <param name="count">Number of entries to update</param>
/// <returns>Status code</returns>
NTSTATUS EptUpdateTableRecursive( 
    IN struct _EPT_DATA* pEPTData,
    IN PEPT_MMPTE pTable,
    IN EPT_TABLE_LEVEL level,
    IN ULONG64 pfn, 
    IN EPT_ACCESS access,
    IN ULONG64 hostPFN,
    IN ULONG count
    );

/// <summary>
/// Get EPT PTE entry for guest physical address
/// </summary>
/// <param name="PML4">PTE PML4 pointer</param>
/// <param name="phys">Guest physical address</param>
/// <param name="pEntry">Found entry or NULL</param>
/// <returns>Status code</returns>
NTSTATUS EptGetPTEForPhysical( IN PEPT_PML4_ENTRY PML4, IN PHYSICAL_ADDRESS phys, OUT PEPT_PTE_ENTRY* pEntry );