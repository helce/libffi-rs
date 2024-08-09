! Copyright (c) 2012-2024 AO MCST.
! Distributed under the terms of MIT License.

#define LIBFFI_ASM
#include <ffi.h>

#ifdef __ptr64__

#define CDISP movtd
#define LDD   ldd
#define LDB   ldb
#define STD   std
#define STB   stb
#define PTR_SIZE	8
#define LDP		ldd

#else /* __ptr64__ */

#define CDISP getpl
#define LDD   ldgdd
#define LDB   ldgdb
#define STD   stgdd
#define STB   stgdb
#define PTR_SIZE	4
#define LDP		ldgdw
#endif /* __ptr64__ */

        .ignore ld_st_style

.text

! The maximal size of a result returned on registers.
#define MAX_RES_REG_SIZE 64

! -----------------------------------------------------------------------------

        ! void ffi_call_asm
        !   (void (*fn)(void),
        !    void *stack_image,
        !    unsigned total_size,
        !    unsigned params_size,
        !    unsigned result_size,
	!    void *closure);

        .global ffi_call_asm
        .type   ffi_call_asm, @function
        .align  8
ffi_call_asm:

        ! %r0 = fn
        ! %r1 = stack_image
        ! %r2 = total_size
        ! %r3 = params_size
        ! %r4 = result_size
	! %r5 = closure

#define R_FN %r0
#define R_STACK_IMAGE %r1
#define R_TOTAL_SIZE %r2
#define R_PARAMS_SIZE %r3
#define R_RESULT_SIZE %r4
#define R_CLOSURE %r5
#define R_SP %r6
#define R_TMP1 %r7
#define R_TMP2 %r8

        setwd wsz = 0x9, nfx = 0x0
        setbn rsz = 0x3, rbs = 0x5, rcur = 0x0

        ! allocate memory for real parameters
        subs  0x0, R_TOTAL_SIZE, R_SP
        getsp R_SP, R_SP

        ! copy parameters from pointer R_STACK_IMAGE into real stack
        disp   %ctpr1, 1f
        addd   0x0, 0x0, R_TMP1 ! 64-bit addd to clear high part (important in 64-bit mode)
      1:
        cmplsb R_TMP1, R_PARAMS_SIZE, %pred0
        LDD    R_STACK_IMAGE, R_TMP1, R_TMP2 ? %pred0
        STD,sm R_SP, R_TMP1, R_TMP2 ? %pred0
        adds   R_TMP1, 0x8, R_TMP1
        ct     %ctpr1 ? %pred0

        ! copy parameters from real stack into registers
        cmplesb R_PARAMS_SIZE,  0x0, %pred0
        LDD     R_SP,  0x0, %b[0] ? ~%pred0
        cmplesb R_PARAMS_SIZE,  0x8, %pred0
        LDD     R_SP,  0x8, %b[1] ? ~%pred0
        cmplesb R_PARAMS_SIZE, 0x10, %pred0
        LDD     R_SP, 0x10, %b[2] ? ~%pred0
        cmplesb R_PARAMS_SIZE, 0x18, %pred0
        LDD     R_SP, 0x18, %b[3] ? ~%pred0
        cmplesb R_PARAMS_SIZE, 0x20, %pred0
        LDD     R_SP, 0x20, %b[4] ? ~%pred0
        cmplesb R_PARAMS_SIZE, 0x28, %pred0
        LDD     R_SP, 0x28, %b[5] ? ~%pred0
        cmplesb R_PARAMS_SIZE, 0x30, %pred0
        LDD     R_SP, 0x30, %b[6] ? ~%pred0
        cmplesb R_PARAMS_SIZE, 0x38, %pred0
        LDD     R_SP, 0x38, %b[7] ? ~%pred0

        ! FIXME
	! This wait looks seems to be unnecessary and looks like some historical
	! rudiment. It emerged simultaneously with the very first iterations of
	! elbrus-s without any meaningful explanation.
        wait  all_c = 0x1

        ! do call
        CDISP R_FN, %ctpr1
	addd	0x0, R_CLOSURE, %g12
        call  %ctpr1, wbs = 0x5

        ! check if the result is passed on stack
        disp   %ctpr1, 1f
        cmplesb R_RESULT_SIZE, MAX_RES_REG_SIZE, %pred0
        ct     %ctpr1 ? ~%pred0

        ! copy result from registers into real stack
        cmplesb R_RESULT_SIZE,  0x0, %pred0
        STD,sm  R_SP,  0x0, %b[0] ? ~%pred0
        cmplesb R_RESULT_SIZE,  0x8, %pred0
        STD,sm  R_SP,  0x8, %b[1] ? ~%pred0
        cmplesb R_RESULT_SIZE, 0x10, %pred0
        STD,sm  R_SP, 0x10, %b[2] ? ~%pred0
        cmplesb R_RESULT_SIZE, 0x18, %pred0
        STD,sm  R_SP, 0x18, %b[3] ? ~%pred0
        cmplesb R_RESULT_SIZE, 0x20, %pred0
        STD,sm  R_SP, 0x20, %b[4] ? ~%pred0
        cmplesb R_RESULT_SIZE, 0x28, %pred0
        STD,sm  R_SP, 0x28, %b[5] ? ~%pred0
        cmplesb R_RESULT_SIZE, 0x30, %pred0
        STD,sm  R_SP, 0x30, %b[6] ? ~%pred0
        cmplesb R_RESULT_SIZE, 0x38, %pred0
        STD,sm  R_SP, 0x38, %b[7] ? ~%pred0
      1:

        ! copy result from real stack to pointer R_STACK_IMAGE
        disp   %ctpr1, 1f
        addd   0x0, 0x0, R_TMP1 ! 64-bit "addd" to clear high part (important in 64-bit mode)
      1:
        cmplsb R_TMP1, R_RESULT_SIZE, %pred0
        LDD    R_SP, R_TMP1, R_TMP2 ? %pred0
        STD,sm R_STACK_IMAGE, R_TMP1, R_TMP2 ? %pred0
        adds   R_TMP1, 0x8, R_TMP1
        ct     %ctpr1 ? %pred0

        ! return
        return %ctpr3
        ct %ctpr3

#undef R_FN
#undef R_STACK_IMAGE
#undef R_TOTAL_SIZE
#undef R_PARAMS_SIZE
#undef R_RESULT_SIZE
#undef R_CLOSURE
#undef R_SP
#undef R_TMP1
#undef R_TMP2

        .size   ffi_call_asm, .- ffi_call_asm

! -----------------------------------------------------------------------------

#define R_CLOSURE %g12

#define R_FP %r8
#define R_SP %r9
#define R_TMP %r10
#define R_CIF %r11
#define R_FUN %r12
#define R_USER %r13
#define R_RES_BUFFER_SIZE %r14
#define R_INCOMING_REGS %r15

#define R_R0 %r0
#define R_R1 %r1

        .global ffi_go_closure_e2k
        .type   ffi_go_closure_e2k, @function
        .align  8
ffi_go_closure_e2k:
        ! Register window layout:
        ! - 8 registers for incoming parameters
        ! - 8 registers for R_FP, R_SP, R_TMP, R_CIF, R_FUN, R_USER, R_RES_BUFFER_SIZE, R_INCOMING_REGS
        ! - 8 registers for outgoing call's parameters
	! The number of registers could be reduced by 2: after all %r-registers
	! have been spilled on stack, they are no longer needed, which makes it
	! possible to use %r{0-7} as temporary registers. But that would
	! make the code less transparent.
        setwd   wsz = 0xc, nfx = 0x1
        setbn   rsz = 0x3, rbs = 0x8, rcur = 0x0

	disp	%ctpr1, 1f
	LDP	R_CLOSURE, PTR_SIZE, R_CIF
	LDP	R_CLOSURE, 2 * PTR_SIZE, R_FUN
	addd	0x0, R_CLOSURE, R_USER
	ct	%ctpr1


        .global ffi_closure_e2k
        .type   ffi_closure_e2k, @function
        .align  8
ffi_closure_e2k:

	! When the user calls a function via a closure, the trampoline within
	! the closure passes the execution here.
        ! %g12 = closure

	! See the above comment in ffi_go_closure_e2k on window register size.
        setwd   wsz = 0xc, nfx = 0x1
        setbn   rsz = 0x3, rbs = 0x8, rcur = 0x0

	LDP	R_CLOSURE, FFI_TRAMPOLINE_SIZE, R_CIF
	LDP	R_CLOSURE, FFI_TRAMPOLINE_SIZE + PTR_SIZE, R_FUN
	LDP	R_CLOSURE, FFI_TRAMPOLINE_SIZE + 2 * PTR_SIZE, R_USER

	! Allocate 16 bytes for calc_args_reg_size () and
	! calc_aligned_stack_result_size () who may wish to spill
	! their only CIF argument on stack.
     1:
	getsp	-0x10, R_SP
	! There's no point in postponing the calculation of %fp.
	addd	R_SP, 0x10, R_FP

	disp	%ctpr1, calc_args_reg_size
	addd	0x0, R_CIF, %b[0]
	call	%ctpr1, wbs = 0x8
	addd	0x0, %b[0], R_INCOMING_REGS

	disp	%ctpr1, calc_aligned_stack_result_size
	addd	0x0, R_CIF, %b[0]
	call	%ctpr1, wbs = 0x8
	addd	0x0, %b[0], R_RES_BUFFER_SIZE

        ! Stack layout (the alignment should be STACK_ALIGN=16):
        ! - space for temporary storage of the result (see comments
        !   in ffi_prep_closure_loc), aligned on 16
        ! - 40 bytes for 5 outgoing parameters (48 with 16-byte alignment in mind)
#define L_STACK 48
	! Account for 16 bytes allocated above for calc_args_reg_size () and
	! calc_aligned_stack_result_size ().
        addd    R_RES_BUFFER_SIZE, L_STACK - 0x10, R_TMP
        subd    0x0, R_TMP, R_TMP
        getsp   R_TMP, R_SP

	! All incoming register parameters are saved on stack. A a result,
	! one gets the memory area (pointed to by R_FP) containing all
	! incoming parameters. The outgoing result returned on stack is also
	! saved to this area. All required memory is allocated at the point
	! of closure call (via a function pointer).
        cmplesb R_INCOMING_REGS, 0x0, %pred0
        STD,sm  R_FP, 0x0,    %r0  ? ~%pred0
        cmplesb R_INCOMING_REGS, 0x1, %pred0
        STD,sm  R_FP, 0x8,    %r1  ? ~%pred0
        cmplesb R_INCOMING_REGS, 0x2, %pred0
        STD,sm  R_FP, 0x10,   %r2  ? ~%pred0
        cmplesb R_INCOMING_REGS, 0x3, %pred0
        STD,sm  R_FP, 0x18,   %r3  ? ~%pred0
        cmplesb R_INCOMING_REGS, 0x4, %pred0
        STD,sm  R_FP, 0x20,   %r4  ? ~%pred0
        cmplesb R_INCOMING_REGS, 0x5, %pred0
        STD,sm  R_FP, 0x28,   %r5  ? ~%pred0
        cmplesb R_INCOMING_REGS, 0x6, %pred0
        STD,sm  R_FP, 0x30,   %r6  ? ~%pred0
        cmplesb R_INCOMING_REGS, 0x7, %pred0
        STD,sm  R_FP, 0x38,   %r7  ? ~%pred0

	! The return value's buffer's address. It's used also after CALL,
	! which is why it should be stored on %r register (as there's no
	! guarantee that %g won't be clobbered by CALL).
        subd    R_FP, R_RES_BUFFER_SIZE, R_TMP

        addd    0x0, R_CIF, %b[0]
	addd    0x0, R_FUN, %b[1]
	addd	0x0, R_USER, %b[2]
        addd    0x0, R_TMP, %b[3]
	addd    0x0, R_FP, %b[4]
        disp    %ctpr1, ffi_closure_e2k_inner
        call    %ctpr1, wbs = 0x8

        ! Now %b[0] contains the actual (not aligned) size of a result

        disp    %ctpr1, 1f
        cmplesb %b[0], MAX_RES_REG_SIZE, %pred0
        ct      %ctpr1 ? ~%pred0

        ! The size of a result is less or equal than 64 bytes.
        ! Put it on %r-registers.
        cmplesb %b[0],  0x0,  %pred0
        LDD     R_TMP, 0x0,  %r0 ? ~%pred0
        cmplesb %b[0],  0x8,  %pred0
        LDD     R_TMP, 0x8,  %r1 ? ~%pred0
        cmplesb %b[0],  0x10, %pred0
        LDD     R_TMP, 0x10, %r2 ? ~%pred0
        cmplesb %b[0],  0x18, %pred0
        LDD     R_TMP, 0x18, %r3 ? ~%pred0
        cmplesb %b[0],  0x20, %pred0
        LDD     R_TMP, 0x20, %r4 ? ~%pred0
        cmplesb %b[0],  0x28, %pred0
        LDD     R_TMP, 0x28, %r5 ? ~%pred0
        cmplesb %b[0],  0x30, %pred0
        LDD     R_TMP, 0x30, %r6 ? ~%pred0
        cmplesb %b[0],  0x38, %pred0
        LDD     R_TMP, 0x38, %r7 ? ~%pred0

        return %ctpr3
        ct %ctpr3

     1:
        ! The size of a result is greater than 64 bytes. Put it on the caller's
        ! stack. The alignment may turn out to be arbitrary here in general,
	! therefore, copy it byte by byte.
        ! src_addr = R_TMP
        ! dst_addr = R_FP
        ! size = %b[0]
        ! %r0 - %r7 registers are no longer needed, reuse them for
        ! temporary values.
        disp   %ctpr1, 2f
        addd   0x0, 0x0, R_R0 ! 64-bit "addd" to clear high part (important in 64-bit mode)
     2:
        cmplsb R_R0, %b[0], %pred0
        LDB    R_TMP, R_R0, R_R1 ? %pred0
        STB,sm R_FP, R_R0, R_R1 ? %pred0
        adds   R_R0, 0x1, R_R0
        ct     %ctpr1 ? %pred0

        return %ctpr3
        ct %ctpr3

#undef R_FP
#undef R_SP
#undef R_TMP
#undef R_R0
#undef R_R1
#undef L_STACK

        .size   ffi_closure_e2k, .- ffi_closure_e2k
