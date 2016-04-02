#ifndef _LDASM_
#define _LDASM_

#include <ntdef.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define F_INVALID       0x01
#define F_PREFIX        0x02
#define F_REX           0x04
#define F_MODRM         0x08
#define F_SIB           0x10
#define F_DISP          0x20
#define F_IMM           0x40
#define F_RELATIVE      0x80

typedef struct _ldasm_data
{
    UCHAR  flags;
    UCHAR  rex;
    UCHAR  modrm;
    UCHAR  sib;
    UCHAR  opcd_offset;
    UCHAR  opcd_size;
    UCHAR  disp_offset;
    UCHAR  disp_size;
    UCHAR  imm_offset;
    UCHAR  imm_size;
} ldasm_data;

unsigned int  __fastcall ldasm( void *code, ldasm_data *ld, ULONG is64 );
unsigned long __fastcall SizeOfProc( void *Proc );
void*         __fastcall ResolveJmp( void *Proc );

#ifdef __cplusplus
}
#endif

#endif//_LDASM_