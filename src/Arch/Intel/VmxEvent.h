#pragma once
#include <ntdef.h>

typedef union _INTERRUPT_INFO_FIELD
{
    ULONG32 All;
    struct 
    {
        ULONG32 Vector : 8;
        ULONG32 Type : 3;
        ULONG32 ErrorCodeValid : 1;
        ULONG32 NMIUnblocking : 1;
        ULONG32 Reserved : 18;
        ULONG32 Valid : 1;
    } Fields;    
} INTERRUPT_INFO_FIELD, *PINTERRUPT_INFO_FIELD;

typedef union _INTERRUPT_INJECT_INFO_FIELD
{
    ULONG32 All;
    struct
    {
        ULONG32 Vector : 8;
        ULONG32 Type : 3;
        ULONG32 DeliverErrorCode : 1;
        ULONG32 Reserved : 19;
        ULONG32 Valid : 1;
    } Fields;
} INTERRUPT_INJECT_INFO_FIELD, *PINTERRUPT_INJECT_INFO_FIELD;

typedef enum _INTERRUPT_TYPE
{
    INTERRUPT_EXTERNAL             = 0,
    INTERRUPT_NMI                  = 2,
    INTERRUPT_HARDWARE_EXCEPTION   = 3,
    INTERRUPT_SOFTWARE             = 4,
    INTERRUPT_PRIVILIGED_EXCEPTION = 5,
    INTERRUPT_SOFTWARE_EXCEPTION   = 6,
    INTERRUPT_OTHER_EVENT          = 7
} INTERRUPT_TYPE;

typedef enum _VECTOR_EXCEPTION
{
    VECTOR_DIVIDE_ERROR_EXCEPTION          = 0,
    VECTOR_DEBUG_EXCEPTION                 = 1,
    VECTOR_NMI_INTERRUPT                   = 2,
    VECTOR_BREAKPOINT_EXCEPTION            = 3,
    VECTOR_OVERFLOW_EXCEPTION              = 4,
    VECTOR_BOUND_EXCEPTION                 = 5,
    VECTOR_INVALID_OPCODE_EXCEPTION        = 6,
    VECTOR_DEVICE_NOT_AVAILABLE_EXCEPTION  = 7,
    VECTOR_DOUBLE_FAULT_EXCEPTION          = 8,
    VECTOR_COPROCESSOR_SEGMENT_OVERRUN     = 9,
    VECTOR_INVALID_TSS_EXCEPTION           = 10,
    VECTOR_SEGMENT_NOT_PRESENT             = 11,
    VECTOR_STACK_FAULT_EXCEPTION           = 12,
    VECTOR_GENERAL_PROTECTION_EXCEPTION    = 13,
    VECTOR_PAGE_FAULT_EXCEPTION            = 14,
    VECTOR_X87_FLOATING_POINT_ERROR        = 16,
    VECTOR_ALIGNMENT_CHECK_EXCEPTION       = 17,
    VECTOR_MACHINE_CHECK_EXCEPTION         = 18,
    VECTOR_SIMD_FLOATING_POINT_EXCEPTION   = 19,
    VECTOR_VIRTUALIZATION_EXCEPTION        = 20
} VECTOR_EXCEPTION;

/// <summary>
/// Inject interrupt or exception into guest
/// </summary>
/// <param name="InterruptType">INterrupt type</param>
/// <param name="Vector">IDT index</param>
/// <param name="WriteLength">Intruction length skip</param>
VOID VmxInjectEvent( INTERRUPT_TYPE InterruptType, VECTOR_EXCEPTION Vector, ULONG WriteLength );