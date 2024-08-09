/* -----------------------------------------------------------------------
   ffi.c - Copyright (c) 2012-2024 AO MCST.
   
   E2K Foreign Function Interface 

   Permission is hereby granted, free of charge, to any person obtaining
   a copy of this software and associated documentation files (the
   ``Software''), to deal in the Software without restriction, including
   without limitation the rights to use, copy, modify, merge, publish,
   distribute, sublicense, and/or sell copies of the Software, and to
   permit persons to whom the Software is furnished to do so, subject to
   the following conditions:

   The above copyright notice and this permission notice shall be included
   in all copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED ``AS IS'', WITHOUT WARRANTY OF ANY KIND,
   EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
   MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
   NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
   HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
   WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
   DEALINGS IN THE SOFTWARE.
   ----------------------------------------------------------------------- */

#if 0
#define DEBUG
#endif

#include <ffi.h>
#include <ffi_common.h>

#include <stdlib.h>

#ifdef DEBUG
#include <stdio.h>
#endif

/* Minimal stack alignment */
#define STACK_ALIGN 16

/* Parameter slot size */
#define SLOT_SIZE 8

/* The maximal number of slots employed in register transfers.  */
#define MAX_ARG_REG_SLOTS 8

/* The maximal size of the value, which can be returned on registers.  */
#define MAX_RES_REG_SIZE 64

#define MIN(x,y) (((x) < (y)) ? (x) : (y))
#define MAX(x,y) (((x) > (y)) ? (x) : (y))

/* ------------------------------------------------------------------------- */

static unsigned calc_arg_alignment(const ffi_type *arg_type)
{
  if (arg_type->size <= SLOT_SIZE)
    return SLOT_SIZE;
  else
    return SLOT_SIZE * 2;
}

/* Evaluate the size of stack required for incoming parameters.  */
static unsigned calc_args_stack_size(const ffi_cif *cif)
{
  unsigned n, pos;

  for (n = 0, pos = 0; n < cif->nargs; n++)
    {
      ffi_type *arg_type = cif->arg_types[n];

      pos = FFI_ALIGN(pos, calc_arg_alignment(arg_type));
      pos += arg_type->size;
    }
  pos = FFI_ALIGN(pos, STACK_ALIGN);

  return pos;
}

/* Evaluate the number of registers required for incoming parameters.  */
unsigned
calc_args_reg_size(const ffi_cif *cif)
{
  unsigned n, pos, nregs;

  nregs = 0;
  for (n = 0, pos = 0; n < cif->nargs; n++)
    {
      ffi_type *arg_type = cif->arg_types[n];

      /* Evaluate the position of the parameter's upper bound on stack by
       * analogy to calc_args_stack_size.  */
      pos = FFI_ALIGN(pos, calc_arg_alignment(arg_type));
      pos += arg_type->size;

      /* If the argument fits into the register area entirely, it will be
       * passed on registers. Otherwise, it will be transferred on stack
       * (thus, a few registers will remain unused).  */
      if (pos <= (SLOT_SIZE * MAX_ARG_REG_SLOTS))
        nregs = FFI_ALIGN(pos, SLOT_SIZE) / SLOT_SIZE;
      else
        break;
    }

  return nregs;
}

static unsigned calc_result_size(const ffi_type *type)
{
  /* man: rvalue must point to storage that is sizeof(ffi_arg) or larger
   * for non-floating point types */
  switch (type->type)
    {
    case FFI_TYPE_INT:
    case FFI_TYPE_UINT8:
    case FFI_TYPE_SINT8:
    case FFI_TYPE_UINT16:
    case FFI_TYPE_SINT16:
    case FFI_TYPE_UINT32:
    case FFI_TYPE_SINT32:
      return MAX(type->size, sizeof(ffi_arg));
    default:
      return type->size;
    }
}

static unsigned get_type_real_size(const ffi_type *type)
{
  if (type->type == FFI_TYPE_VOID)
    return 0;
  else
    return type->size;
}

unsigned
calc_aligned_stack_result_size (const ffi_cif *cif)
{
  return FFI_ALIGN (get_type_real_size (cif->rtype), STACK_ALIGN);
}

/* ------------------------------------------------------------------------- */

/* Perform machine dependent cif processing */
ffi_status ffi_prep_cif_machdep(ffi_cif *cif)
{
  /* It's a common practice to evaluate the size of stack for incoming
   * arguments here.  */
  cif->bytes = calc_args_stack_size(cif);
  return FFI_OK;
}

extern void ffi_call_asm (void (*fn)(void), void *stack_image,
                          unsigned total_size,
                          unsigned params_size, unsigned result_size,
			  void *closure);

static void
ffi_call_int (ffi_cif *cif, void (*fn) (void), void *rvalue, void **avalue,
	      void *closure)
{
  unsigned n, pos;
  char *stack_image;

  /* Size of the arguments */
  unsigned const params_size = cif->bytes;

  /* Size of the result */
  unsigned const result_size = calc_result_size(cif->rtype);

  /* Total size of the stack frame. The arguments and the result are passed
   * in the same stack area (outgoing parameters stack) */
  unsigned const total_size = FFI_ALIGN(MAX(params_size, result_size), STACK_ALIGN);

#ifdef DEBUG
  printf("ffi_call: result_size=%d, params_size=%d, total_size=%d\n",
         result_size, params_size, total_size);
#endif

  /* Allocate memory for stack image of parameters and results */
  stack_image = alloca(total_size);
  for (n = 0; n < total_size; n++)
    stack_image[n] = 0;

  /* Copy parameter values into stack image */
  for (n = 0, pos = 0; n < cif->nargs; n++)
    {
      ffi_type *arg_type = cif->arg_types[n];
      char *arg_image;

#ifdef DEBUG
#if 0
      printf("ffi_call: param %d: type=%d, size=%d\n",
             n, arg_type->type, (int)arg_type->size);
#endif
#endif

      /* Evaluate the lower border of the argument on stack.  */
      pos = FFI_ALIGN(pos, calc_arg_alignment(arg_type));

      /* Copy the binary contents of the argument to stack image.  */
      arg_image = stack_image + pos;
      memcpy(arg_image, avalue[n], arg_type->size);

      /* POS points to the argument's upper border (this is the value that the
       * next iteration of the loop will start with).  */
      pos += arg_type->size;

      /* do promotion */
      switch (arg_type->type)
        {
        case FFI_TYPE_SINT8:
          *((long long*) arg_image) = *((SINT8*)arg_image);
          break;
        case FFI_TYPE_UINT8:
          *((unsigned long long*) arg_image) = *((UINT8*)arg_image);
          break;
        case FFI_TYPE_SINT16:
          *((long long*) arg_image) = *((SINT16*)arg_image);
          break;
        case FFI_TYPE_UINT16:
          *((unsigned long long*) arg_image) = *((UINT16*)arg_image);
          break;
        case FFI_TYPE_SINT32:
          *((long long*) arg_image) = *((SINT32*)arg_image);
          break;
        case FFI_TYPE_UINT32:
          *((unsigned long long*) arg_image) = *((UINT32*)arg_image);
          break;
        }
    }
  pos = FFI_ALIGN(pos, STACK_ALIGN);
  FFI_ASSERT(pos == params_size);

#ifdef DEBUG
#if 0
  for (n = 0; n < params_size; n++)
    {
      printf("%02x ", (unsigned char)stack_image[n]);
      if ((n % 8) == 7)
        printf("\n");
    }
  printf("\n");
#endif
#endif

  /* Do call */
  ffi_call_asm (fn, stack_image, total_size, params_size, result_size,
		closure);

  /* Copy the result value from stack image */
  if (rvalue != NULL)
    memcpy(rvalue, stack_image, result_size);
}

void
ffi_call (ffi_cif *cif, void (*fn)(void), void *rvalue, void **avalue)
{
  ffi_call_int (cif, fn, rvalue, avalue, NULL);
}

/* ------------------------------------------------------------------------- */

extern void ffi_closure_e2k (void) FFI_HIDDEN;
extern void ffi_go_closure_e2k (void) FFI_HIDDEN;

ffi_status
ffi_prep_closure_loc (ffi_closure *closure,
		      ffi_cif *cif,
		      void (*fun)(ffi_cif*, void*, void**, void*),
		      void *user_data,
		      void *codeloc)
{
  /* Get pointer to the trampoine.  */
  unsigned int *tramp = (unsigned int *) &closure->tramp[0];

  /* The function that the trampoline will transfer execution to.  */
  unsigned long fn = (unsigned long) ffi_closure_e2k;

  /* The closure's value that will be passed to fn.  */
  unsigned long clx = (unsigned long) closure;

  /* If the return value's size is greater than 64 bytes, the space on stack
   * for it is allocated by the caller. Because of e2k ABI this area
   * intersects with the areas reserved for incoming arguments. Taking into
   * account that the interface of the user function called from under the
   * closure lets the user write out the result before the incoming arguments
   * are loaded, an intermediate buffer is required for the return value in
   * general. After the user function returns the result should be copied from
   * the intermediate buffer to the caller's stack frame.
   *
   * If the result's size is less than or equal to 64 bytes, no memory is
   * allocated for it at all. Therefore, the intermediate buffer is also
   * required for it. However, unlike the prior case, eventually it should
   * be copied on registers.
   *
   * Anyway, the buffer can be `alloca ()'ted only within ffi_closure_e2k ()
   * as this is the function that is capable of copying the result from the
   * intermediate buffer to registers (which are not accessible from anywhere
   * else). Note that the size should be aligned according to the alignment
   * of the stack.  */

  if (cif->abi != FFI_E2K)
    return FFI_BAD_ABI;

#ifdef DEBUG
  printf ("ffi_prep_closure_loc: res_buffer_size = %d\n", res_buffer_size);
  printf ("ffi_prep_closure_loc: incoming_regs = %d\n", incoming_regs);
  printf ("ffi_prep_closure_loc: fn=%lx\n", fn);
  printf ("ffi_prep_closure_loc: clx=%lx\n", clx);
#endif

  /* Matches FFI_TRAMPOLINE_SIZE.  */
#ifdef __ptr64__
  tramp[0]  = 0x0c000032;            /* HS    0c000032 : */
  tramp[1]  = 0x61c0dcd1;            /* ALS0  61c0dcd1  movtd,0 _f64,_lts0 <ffi_closure_e2k>, %ctpr1    */
  tramp[2]  = 0x11c0deec;            /* ALS1  11c0deec  addd,1 0x0, _f64,_lts2 <closure>, %dg12         */
  tramp[3]  = 0x00000000;            /*       00000000                                                  */
  tramp[4]  = (unsigned)(clx >> 32); /* LTS3  xxxxxxxx  <closure>.hi                                    */
  tramp[5] =  (unsigned)(clx);       /* LTS2  xxxxxxxx  <closure>.lo                                    */
  tramp[6]  = (unsigned)(fn >> 32);  /* LTS1  xxxxxxxx  <ffi_closure_e2k.hi>                            */
  tramp[7]  = (unsigned)(fn);        /* LTS0  xxxxxxxx  <ffi_closure_e2k.lo>                            */
  tramp[8] =  0x00001001;            /* HS    00001001 :                                                */
  tramp[9] =  0x80000420;            /* SS    80000420  ct %ctpr1                                       */
#else
  tramp[0]  = 0x0c000022;            /* HS    0c000022 : */
  tramp[1]  = 0x63f0d8d1;            /* ALS0  63f0d8d1  getpl,0 _f32s,_lts0 <ffi_closure_e2k>, %ctpr1   */
  tramp[2]  = 0x11c0d9ec;            /* ALS1  11c0d9ec  addd,1 0x0, _f32s,_lts1 <closure>, %dg12        */
  tramp[3]  = 0x00000000;            /* LTS2  00000000                                                  */
  tramp[4]  = (unsigned)(clx);       /* LTS1  xxxxxxxx  <closure>                                       */
  tramp[5]  = (unsigned)(fn);        /* LTS0  xxxxxxxx  <ffi_closure_e2k>                               */
  tramp[6] =  0x00001001;            /* HS    00001001 :                                                */
  tramp[7] =  0x80000420;            /* SS    80000420  ct %ctpr1                                       */
#endif

  closure->cif = cif;
  closure->fun = fun;
  closure->user_data = user_data;

  __builtin___clear_cache ((char *) tramp,
			   (char *) tramp + FFI_TRAMPOLINE_SIZE);

  return FFI_OK;
}

unsigned
ffi_closure_e2k_inner (ffi_cif *cif,
		       void (*fun)(ffi_cif*, void*, void**, void*),
		       void *user_data,
                       void *rvalue,
		       unsigned long stack_params)
{
  void **avalue = alloca(cif->nargs * sizeof(void *));
  unsigned n, pos;

  /* Grab the addresses of the arguments from the stack frame.  */
  for (n = 0, pos = 0; n < cif->nargs; n++)
    {
      ffi_type *arg_type = cif->arg_types[n];

      pos = FFI_ALIGN(pos, calc_arg_alignment(arg_type));
      avalue[n] = (void*)(stack_params + pos);
      pos += arg_type->size;
    }

#ifdef DEBUG
#if 0
  {
    unsigned long long *p = (unsigned long long*)stack_params;
    printf("rvalue = %p\n", rvalue);
    printf("%p: %016llx\n", p, p[0]);
    printf("%p: %016llx\n", p+1, p[1]);
    printf("%p: %016llx\n", p+2, p[2]);
    printf("%p: %016llx\n", p+3, p[3]);
    printf("%p: %016llx\n", p+4, p[4]);
    printf("%p: %016llx\n", p+5, p[5]);
  }
#endif
#endif

  /* Invoke the closure.  */
  fun (cif, rvalue, avalue, user_data);

  return get_type_real_size(cif->rtype);
}

/* ------------------------------------------------------------------------- */

void
ffi_call_go (ffi_cif *cif, void (*fn)(void), void *rvalue,
	     void **avalue, void *closure)
{
  ffi_call_int (cif, fn, rvalue, avalue, closure);
}

ffi_status
ffi_prep_go_closure (ffi_go_closure *closure, ffi_cif *cif,
		     void (*fun)(ffi_cif*, void*, void**, void*))
{
  if (cif->abi != FFI_E2K)
    return FFI_BAD_ABI;

  closure->tramp = ffi_go_closure_e2k;
  closure->cif = cif;
  closure->fun = fun;

  return FFI_OK;
}
