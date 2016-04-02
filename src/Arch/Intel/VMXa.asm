;++
;
; Copyright (c) Alex Ionescu.  All rights reserved.
;
; Module:
;
;    VMXa.asm
;
; Abstract:
;
;    This module implements AMD64-specific routines for the Simple Hyper Visor.
;
; Author:
;
;    Alex Ionescu (@aionescu) 16-Mar-2016 - Initial version
;
; Environment:
;
;    Kernel mode only.
;
;--
extern VmxpExitHandler:proc
extern RtlCaptureContext:proc

.CODE

VmxVMEntry PROC
    push    rcx                 ; save RCX, as we will need to orverride it
    lea     rcx, [rsp+8h]       ; store the context in the stack, bias for
                                ; the return address and the push we just did.
    call    RtlCaptureContext   ; save the current register state.
                                ; note that this is a specially written function
                                ; which has the following key characteristics:
                                ;   1) it does not taint the value of RCX
                                ;   2) it does not spill any registers, nor
                                ;      expect home space to be allocated for it

    jmp     VmxpExitHandler     ; jump to the C code handler. we assume that it
                                ; compiled with optimizations and does not use
                                ; home space, which is true of release builds.
VmxVMEntry ENDP

VmxVMCleanup PROC
    mov     ds, cx              ; set DS to parameter 1
    mov     es, cx              ; set ES to parameter 1
    mov     fs, dx              ; set FS to parameter 2
    ret                         ; return
VmxVMCleanup ENDP

VmxpResume PROC 
    vmresume
    ret
VmxpResume ENDP

__vmx_vmcall PROC
    vmcall
    ret
__vmx_vmcall ENDP

__invept PROC
    invept rcx, OWORD PTR [rdx]
    ret
__invept ENDP

__invvpid PROC
    invvpid rcx, OWORD PTR [rdx]
    ret
__invvpid ENDP

END