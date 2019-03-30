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

; Our own function to restore context from CONTEXT structure (alternative to a BSODing RtlRestoreContext() function; compatibility with original RtlCaptureContext() function).

VmRestoreContext PROC

	push rbp
	push rsi
	push rdi
	sub rsp, 30h
	mov rbp, rsp
	movaps  xmm0, xmmword ptr [rcx+1A0h]
	movaps  xmm1, xmmword ptr [rcx+1B0h]
	movaps  xmm2, xmmword ptr [rcx+1C0h]
	movaps  xmm3, xmmword ptr [rcx+1D0h]
	movaps  xmm4, xmmword ptr [rcx+1E0h]
	movaps  xmm5, xmmword ptr [rcx+1F0h]
	movaps  xmm6, xmmword ptr [rcx+200h]
	movaps  xmm7, xmmword ptr [rcx+210h]
	movaps  xmm8, xmmword ptr [rcx+220h]
	movaps  xmm9, xmmword ptr [rcx+230h]
	movaps  xmm10, xmmword ptr [rcx+240h]
	movaps  xmm11, xmmword ptr [rcx+250h]
	movaps  xmm12, xmmword ptr [rcx+260h]
	movaps  xmm13, xmmword ptr [rcx+270h]
	movaps  xmm14, xmmword ptr [rcx+280h]
	movaps  xmm15, xmmword ptr [rcx+290h]
	ldmxcsr dword ptr [rcx+34h]

	mov     ax, [rcx+42h]
	mov     [rsp+20h], ax
	mov     rax, [rcx+98h] ; RSP
	mov     [rsp+18h], rax
	mov     eax, [rcx+44h]
	mov     [rsp+10h], eax
	mov     ax, [rcx+38h]
	mov     [rsp+08h], ax
	mov     rax, [rcx+0F8h] ; RIP
	mov     [rsp+00h], rax ; set RIP as return address (for iretq instruction).

	mov     rax, [rcx+78h]
	mov     rdx, [rcx+88h]
	mov     r8, [rcx+0B8h]
	mov     r9, [rcx+0C0h]
	mov     r10, [rcx+0C8h]
	mov     r11, [rcx+0D0h]
	cli
	mov     rbx, [rcx+90h]
	mov     rsi, [rcx+0A8h]
	mov     rdi, [rcx+0B0h]
	mov     rbp, [rcx+0A0h]
	mov     r12, [rcx+0D8h]
	mov     r13, [rcx+0E0h]
	mov     r14, [rcx+0E8h]
	mov     r15, [rcx+0F0h]
	mov     rcx, [rcx+80h]
	iretq

VmRestoreContext ENDP

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
