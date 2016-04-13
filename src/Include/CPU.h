#pragma once
#include <ntdef.h>

#define MSR_APIC_BASE                       0x01B
#define MSR_IA32_FEATURE_CONTROL            0x03A

#define MSR_IA32_VMX_BASIC                  0x480
#define MSR_IA32_VMX_PINBASED_CTLS          0x481
#define MSR_IA32_VMX_PROCBASED_CTLS         0x482
#define MSR_IA32_VMX_EXIT_CTLS              0x483
#define MSR_IA32_VMX_ENTRY_CTLS             0x484
#define MSR_IA32_VMX_MISC                   0x485
#define MSR_IA32_VMX_CR0_FIXED0             0x486
#define MSR_IA32_VMX_CR0_FIXED1             0x487
#define MSR_IA32_VMX_CR4_FIXED0             0x488
#define MSR_IA32_VMX_CR4_FIXED1             0x489
#define MSR_IA32_VMX_VMCS_ENUM              0x48A
#define MSR_IA32_VMX_PROCBASED_CTLS2        0x48B
#define MSR_IA32_VMX_EPT_VPID_CAP           0x48C
#define MSR_IA32_VMX_TRUE_PINBASED_CTLS     0x48D
#define MSR_IA32_VMX_TRUE_PROCBASED_CTLS    0x48E
#define MSR_IA32_VMX_TRUE_EXIT_CTLS         0x48F
#define MSR_IA32_VMX_TRUE_ENTRY_CTLS        0x490
#define MSR_IA32_VMX_VMFUNC                 0x491

#define MSR_IA32_SYSENTER_CS                0x174
#define MSR_IA32_SYSENTER_ESP               0x175
#define MSR_IA32_SYSENTER_EIP               0x176
#define MSR_IA32_DEBUGCTL                   0x1D9

#define MSR_LSTAR                           0xC0000082

#define MSR_FS_BASE                         0xC0000100
#define MSR_GS_BASE                         0xC0000101
#define MSR_SHADOW_GS_BASE                  0xC0000102        // SwapGS GS shadow


#pragma warning(disable: 4214 4201)
typedef struct _CPUID
{
    int eax;
    int ebx;
    int ecx;
    int edx;
} CPUID, *PCPUID;

// RFLAGS
typedef union _EFLAGS
{
    ULONG_PTR All;
    struct
    {
        ULONG CF : 1;           // [0] Carry flag
        ULONG Reserved1 : 1;    // [1] Always 1
        ULONG PF : 1;           // [2] Parity flag
        ULONG Reserved2 : 1;    // [3] Always 0
        ULONG AF : 1;           // [4] Borrow flag
        ULONG Reserved3 : 1;    // [5] Always 0
        ULONG ZF : 1;           // [6] Zero flag
        ULONG SF : 1;           // [7] Sign flag
        ULONG TF : 1;           // [8] Trap flag
        ULONG IF : 1;           // [9] Interrupt flag
        ULONG DF : 1;           // [10]
        ULONG OF : 1;           // [11]
        ULONG IOPL : 2;         // [12-13] I/O privilege level
        ULONG NT : 1;           // [14] Nested task flag
        ULONG Reserved4 : 1;    // [15] Always 0
        ULONG RF : 1;           // [16] Resume flag
        ULONG VM : 1;           // [17] Virtual 8086 mode
        ULONG AC : 1;           // [18] Alignment check
        ULONG VIF : 1;          // [19] Virtual interrupt flag
        ULONG VIP : 1;          // [20] Virtual interrupt pending
        ULONG ID : 1;           // [21] Identification flag
        ULONG Reserved5 : 10;   // [22-31] Always 0
    } Fields;
} EFLAGS, *PEFLAGS;

// CR0
typedef union _CR0_REG
{
    ULONG_PTR All;
    struct
    {
        ULONG PE : 1;           // [0] Protected Mode Enabled
        ULONG MP : 1;           // [1] Monitor Coprocessor FLAG
        ULONG EM : 1;           // [2] Emulate FLAG
        ULONG TS : 1;           // [3] Task Switched FLAG
        ULONG ET : 1;           // [4] Extension Type FLAG
        ULONG NE : 1;           // [5] Numeric Error
        ULONG Reserved1 : 10;   // [6-15]
        ULONG WP : 1;           // [16] Write Protect
        ULONG Reserved2 : 1;    // [17]
        ULONG AM : 1;           // [18] Alignment Mask
        ULONG Reserved3 : 10;   // [19-28]
        ULONG NW : 1;           // [29] Not Write-Through
        ULONG CD : 1;           // [30] Cache Disable
        ULONG PG : 1;           // [31] Paging Enabled
    } Fields;
} CR0_REG, *PCR0_REG;

// CR4
typedef union _CR4_REG
{
    ULONG_PTR All;
    struct
    {
        ULONG VME : 1;          // [0] Virtual Mode Extensions
        ULONG PVI : 1;          // [1] Protected-Mode Virtual Interrupts
        ULONG TSD : 1;          // [2] Time Stamp Disable
        ULONG DE : 1;           // [3] Debugging Extensions
        ULONG PSE : 1;          // [4] Page Size Extensions
        ULONG PAE : 1;          // [5] Physical Address Extension
        ULONG MCE : 1;          // [6] Machine-Check Enable
        ULONG PGE : 1;          // [7] Page Global Enable
        ULONG PCE : 1;          // [8] Performance-Monitoring Counter Enable
        ULONG OSFXSR : 1;       // [9] OS Support for FXSAVE/FXRSTOR
        ULONG OSXMMEXCPT : 1;   // [10] OS Support for Unmasked SIMD Exceptions
        ULONG Reserved1 : 2;    // [11-12]
        ULONG VMXE : 1;         // [13] Virtual Machine Extensions Enabled
        ULONG SMXE : 1;         // [14] SMX-Enable Bit
        ULONG Reserved2 : 2;    // [15-16]
        ULONG PCIDE : 1;        // [17] PCID Enable
        ULONG OSXSAVE : 1;      // [18] XSAVE and Processor Extended States-Enable
        ULONG Reserved3 : 1;    // [19]
        ULONG SMEP : 1;         // [20] Supervisor Mode Execution Protection Enable
        ULONG SMAP : 1;         // [21] Supervisor Mode Access Protection Enable
    } Fields;
} CR4_REG, *PCR4_REG;

typedef union _IA32_APIC_BASE
{
    ULONG64 All;
    struct
    {
        ULONG64 Reserved1 : 8;            // [0-7]
        ULONG64 Bootstrap_processor : 1;  // [8]
        ULONG64 Reserved2 : 1;            // [9]
        ULONG64 Enable_x2apic_mode : 1;   // [10]
        ULONG64 Enable_xapic_global : 1;  // [11]
        ULONG64 Apic_base : 24;           // [12-35]
    } Fields;
} IA32_APIC_BASE, *PIA32_APIC_BASE;

typedef union _IA32_VMX_BASIC_MSR
{
    ULONG64 All;
    struct
    {
        ULONG32 RevisionIdentifier : 31;   // [0-30]
        ULONG32 Reserved1 : 1;             // [31]
        ULONG32 RegionSize : 12;           // [32-43]
        ULONG32 RegionClear : 1;           // [44]
        ULONG32 Reserved2 : 3;             // [45-47]
        ULONG32 SupportedIA64 : 1;         // [48]
        ULONG32 SupportedDualMoniter : 1;  // [49]
        ULONG32 MemoryType : 4;            // [50-53]
        ULONG32 VmExitReport : 1;          // [54]
        ULONG32 VmxCapabilityHint : 1;     // [55]
        ULONG32 Reserved3 : 8;             // [56-63]
    } Fields;
} IA32_VMX_BASIC_MSR, *PIA32_VMX_BASIC_MSR;

typedef union _IA32_VMX_PROCBASED_CTLS_MSR
{
    ULONG64 All;
    struct
    {
        ULONG64 Reserved0 : 32;                // [0-31]
        ULONG64 Reserved1 : 2;                 // [32 + 0-1]
        ULONG64 InterruptWindowExiting : 1;    // [32 + 2]
        ULONG64 UseTSCOffseting : 1;           // [32 + 3]
        ULONG64 Reserved2 : 3;                 // [32 + 4-6]
        ULONG64 HLTExiting : 1;                // [32 + 7]
        ULONG64 Reserved3 : 1;                 // [32 + 8]
        ULONG64 INVLPGExiting : 1;             // [32 + 9]
        ULONG64 MWAITExiting : 1;              // [32 + 10]
        ULONG64 RDPMCExiting : 1;              // [32 + 11]
        ULONG64 RDTSCExiting : 1;              // [32 + 12]
        ULONG64 Reserved4 : 2;                 // [32 + 13-14]
        ULONG64 CR3LoadExiting : 1;            // [32 + 15]
        ULONG64 CR3StoreExiting : 1;           // [32 + 16]
        ULONG64 Reserved5 : 2;                 // [32 + 17-18]
        ULONG64 CR8LoadExiting : 1;            // [32 + 19]
        ULONG64 CR8StoreExiting : 1;           // [32 + 20]
        ULONG64 UseTPRShadowExiting : 1;       // [32 + 21]
        ULONG64 NMIWindowExiting : 1;          // [32 + 22]
        ULONG64 MovDRExiting : 1;              // [32 + 23]
        ULONG64 UnconditionalIOExiting : 1;    // [32 + 24]
        ULONG64 UseIOBitmaps : 1;              // [32 + 25]
        ULONG64 Reserved6 : 1;                 // [32 + 26]
        ULONG64 MonitorTrapFlag : 1;           // [32 + 27]
        ULONG64 UseMSRBitmaps : 1;             // [32 + 28]
        ULONG64 MONITORExiting : 1;            // [32 + 29]
        ULONG64 PAUSEExiting : 1;              // [32 + 30]
        ULONG64 ActivateSecondaryControl : 1;  // [32 + 31]  Does VMX_PROCBASED_CTLS2_MSR exist
    } Fields;
} IA32_VMX_PROCBASED_CTLS_MSR, *PIA32_VMX_PROCBASED_CTLS_MSR;

typedef union _IA32_VMX_PROCBASED_CTLS2_MSR
{
    ULONG64 All;
    struct
    {
        ULONG64 Reserved0 : 32;                 // [0-31]
        ULONG64 VirtualizeAPICAccesses : 1;     // [32 + 0]
        ULONG64 EnableEPT : 1;                  // [32 + 1]
        ULONG64 DescriptorTableExiting : 1;     // [32 + 2]
        ULONG64 EnableRDTSCP : 1;               // [32 + 3]
        ULONG64 VirtualizeX2APICMode : 1;       // [32 + 4]
        ULONG64 EnableVPID : 1;                 // [32 + 5]
        ULONG64 WBINVDExiting : 1;              // [32 + 6]
        ULONG64 UnrestrictedGuest : 1;          // [32 + 7]
        ULONG64 APICRegisterVirtualization : 1; // [32 + 8]
        ULONG64 VirtualInterruptDelivery : 1;   // [32 + 9]
        ULONG64 PAUSELoopExiting : 1;           // [32 + 10]
        ULONG64 RDRANDExiting : 1;              // [32 + 11]
        ULONG64 EnableINVPCID : 1;              // [32 + 12]
        ULONG64 EnableVMFunctions : 1;          // [32 + 13]
        ULONG64 VMCSShadowing : 1;              // [32 + 14]
        ULONG64 Reserved1 : 1;                  // [32 + 15]
        ULONG64 RDSEEDExiting : 1;              // [32 + 16]
        ULONG64 Reserved2 : 1;                  // [32 + 17]
        ULONG64 EPTViolation : 1;               // [32 + 18]
        ULONG64 Reserved3 : 1;                  // [32 + 19]
        ULONG64 EnableXSAVESXSTORS : 1;         // [32 + 20]
    } Fields;
} IA32_VMX_PROCBASED_CTLS2_MSR, *PIA32_VMX_PROCBASED_CTLS2_MSR;

typedef union _IA32_FEATURE_CONTROL_MSR
{
    ULONG64 All;
    struct
    {
        ULONG64 Lock : 1;                // [0]
        ULONG64 EnableSMX : 1;           // [1]
        ULONG64 EnableVmxon : 1;         // [2]
        ULONG64 Reserved2 : 5;           // [3-7]
        ULONG64 EnableLocalSENTER : 7;   // [8-14]
        ULONG64 EnableGlobalSENTER : 1;  // [15]
        ULONG64 Reserved3a : 16;         //
        ULONG64 Reserved3b : 32;         // [16-63]
    } Fields;
} IA32_FEATURE_CONTROL_MSR, *PIA32_FEATURE_CONTROL_MSR;

typedef union _IA32_VMX_EPT_VPID_CAP_MSR
{
    ULONG64 All;
    struct
    {
        ULONG64 ExecuteOnly : 1;                // Bit 0 defines if the EPT implementation supports execute-only translation
        ULONG64 Reserved1 : 31;                 // Undefined
        ULONG64 Reserved2 : 8;                  // Undefined
        ULONG64 IndividualAddressInvVpid : 1;   // Bit 40 defines if type 0 INVVPID instructions are supported
        ULONG64 Reserved3 : 23;
    } Fields;
} IA32_VMX_EPT_VPID_CAP_MSR, *PIA32_VMX_EPT_VPID_CAP_MSR;
#pragma warning(disable: 4214 4201)
