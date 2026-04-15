/* BPF shim: mpi-internal.h
 * Wraps the kernel's lib/mpi/mpi-internal.h but declares mpihelp_mul and
 * mpihelp_mul_karatsuba_case as static (via macro rename + internal_linkage
 * attribute) so the BPF backend accepts calls to these 6-argument functions.
 *
 * The BPF backend rejects calls to non-static functions with >5 arguments.
 * Making them static (or giving them internal_linkage) causes the backend to
 * inline them, bypassing the argument-count restriction.
 *
 * The include guard G10_MPI_INTERNAL_H matches the kernel header's guard so
 * this shim prevents re-inclusion when mpi-mul.c does #include "mpi-internal.h".
 */
#ifndef G10_MPI_INTERNAL_H
#define G10_MPI_INTERNAL_H

/* Include the real kernel mpi-internal.h content inline.
 * We replicate the content with the modifications needed:
 * mpihelp_mul and mpihelp_mul_karatsuba_case are declared with
 * __attribute__((internal_linkage)) so the BPF backend inlines them
 * (BPF rejects non-static function calls with >5 args). */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/mpi.h>
#include <linux/errno.h>

#define log_debug printk
#define log_bug printk
#define assert(x) \
	do { \
		if (!x) \
			log_bug("failed assertion\n"); \
	} while (0);

#ifndef KARATSUBA_THRESHOLD
#define KARATSUBA_THRESHOLD 16
#endif

#if KARATSUBA_THRESHOLD < 2
#undef KARATSUBA_THRESHOLD
#define KARATSUBA_THRESHOLD 2
#endif

typedef mpi_limb_t *mpi_ptr_t;	/* pointer to a limb */
typedef int mpi_size_t;		/* (must be a signed type) */

#define RESIZE_IF_NEEDED(a, b)			\
	do {					\
		if ((a)->alloced < (b))		\
			mpi_resize((a), (b));	\
	} while (0)

/* Copy N limbs from S to D.  */
#define MPN_COPY_INCR(d, s, n) \
	do {					\
		mpi_size_t _i;			\
		for (_i = 0; _i < (n); _i++)	\
			(d)[_i] = (s)[_i];	\
	} while (0)

#define MPN_COPY(d, s, n) MPN_COPY_INCR(d, s, n)

#define MPN_COPY_DECR(d, s, n) \
	do {					\
		mpi_size_t _i;			\
		for (_i = (n)-1; _i >= 0; _i--) \
			(d)[_i] = (s)[_i];	\
	} while (0)

/* Zero N limbs at D */
#define MPN_ZERO(d, n) \
	do {					\
		int  _i;			\
		for (_i = 0; _i < (n); _i++)	\
			(d)[_i] = 0;		\
	} while (0)

#define MPN_NORMALIZE(d, n)  \
	do {					\
		while ((n) > 0) {		\
			if ((d)[(n)-1])		\
				break;		\
			(n)--;			\
		}				\
	} while (0)

#define MPN_MUL_N_RECURSE(prodp, up, vp, size, tspace) \
	do {							\
		if ((size) < KARATSUBA_THRESHOLD)		\
			mul_n_basecase(prodp, up, vp, size);	\
		else						\
			mul_n(prodp, up, vp, size, tspace);	\
	} while (0);

#define UDIV_QRNND_PREINV(q, r, nh, nl, d, di)				\
	do {								\
		mpi_limb_t _ql __maybe_unused;				\
		mpi_limb_t _q, _r;					\
		mpi_limb_t _xh, _xl;					\
		umul_ppmm(_q, _ql, (nh), (di));				\
		_q += (nh);						\
		umul_ppmm(_xh, _xl, _q, (d));				\
		sub_ddmmss(_xh, _r, (nh), (nl), _xh, _xl);		\
		if (_xh) {						\
			sub_ddmmss(_xh, _r, _xh, _r, 0, (d));		\
			_q++;						\
			if (_xh) {					\
				sub_ddmmss(_xh, _r, _xh, _r, 0, (d));	\
				_q++;					\
			}						\
		}							\
		if (_r >= (d)) {					\
			_r -= (d);					\
			_q++;						\
		}							\
		(r) = _r;						\
		(q) = _q;						\
	} while (0)

/*-- mpiutil.c --*/
__attribute__((internal_linkage, always_inline))
mpi_ptr_t mpi_alloc_limb_space(unsigned nlimbs);
__attribute__((internal_linkage, always_inline))
void mpi_free_limb_space(mpi_ptr_t a);
__attribute__((internal_linkage, always_inline))
void mpi_assign_limb_space(MPI a, mpi_ptr_t ap, unsigned nlimbs);
static inline mpi_limb_t mpihelp_add_1(mpi_ptr_t res_ptr, mpi_ptr_t s1_ptr,
			 mpi_size_t s1_size, mpi_limb_t s2_limb);
mpi_limb_t mpihelp_add_n(mpi_ptr_t res_ptr, mpi_ptr_t s1_ptr,
			 mpi_ptr_t s2_ptr, mpi_size_t size);
static inline mpi_limb_t mpihelp_add(mpi_ptr_t res_ptr, mpi_ptr_t s1_ptr, mpi_size_t s1_size,
		       mpi_ptr_t s2_ptr, mpi_size_t s2_size);
static inline mpi_limb_t mpihelp_sub_1(mpi_ptr_t res_ptr, mpi_ptr_t s1_ptr,
			 mpi_size_t s1_size, mpi_limb_t s2_limb);
mpi_limb_t mpihelp_sub_n(mpi_ptr_t res_ptr, mpi_ptr_t s1_ptr,
			 mpi_ptr_t s2_ptr, mpi_size_t size);
static inline mpi_limb_t mpihelp_sub(mpi_ptr_t res_ptr, mpi_ptr_t s1_ptr, mpi_size_t s1_size,
		       mpi_ptr_t s2_ptr, mpi_size_t s2_size);

/*-- mpih-cmp.c --*/
int mpihelp_cmp(mpi_ptr_t op1_ptr, mpi_ptr_t op2_ptr, mpi_size_t size);

/*-- mpih-mul.c --*/
struct karatsuba_ctx {
	struct karatsuba_ctx *next;
	mpi_ptr_t tspace;
	mpi_size_t tspace_size;
	mpi_ptr_t tp;
	mpi_size_t tp_size;
};

/* All functions defined in mpih-mul.c and generic_mpih-mul1.c get
 * internal_linkage + always_inline so the BPF backend can DCE them when
 * unreachable and inline them when reachable. internal_linkage must appear
 * on the FIRST declaration (here), not just on the definition. */
__attribute__((internal_linkage, always_inline))
void mpihelp_release_karatsuba_ctx(struct karatsuba_ctx *ctx);
__attribute__((internal_linkage, always_inline))
mpi_limb_t mpihelp_addmul_1(mpi_ptr_t res_ptr, mpi_ptr_t s1_ptr,
			    mpi_size_t s1_size, mpi_limb_t s2_limb);
__attribute__((internal_linkage, always_inline))
mpi_limb_t mpihelp_submul_1(mpi_ptr_t res_ptr, mpi_ptr_t s1_ptr,
			    mpi_size_t s1_size, mpi_limb_t s2_limb);
/* mpihelp_mul has 6 args. BPF rejects non-static functions with >5 args.
 * Declare it with always_inline + internal_linkage so the BPF backend
 * inlines all calls to it and can DCE it when unreachable. */
__attribute__((internal_linkage, always_inline))
int mpihelp_mul(mpi_ptr_t prodp, mpi_ptr_t up, mpi_size_t usize,
		mpi_ptr_t vp, mpi_size_t vsize, mpi_limb_t *_result);
__attribute__((internal_linkage, always_inline))
void mpih_sqr_n_basecase(mpi_ptr_t prodp, mpi_ptr_t up, mpi_size_t size);
__attribute__((internal_linkage, always_inline))
void mpih_sqr_n(mpi_ptr_t prodp, mpi_ptr_t up, mpi_size_t size,
		mpi_ptr_t tspace);
__attribute__((internal_linkage, always_inline))
void mpihelp_mul_n(mpi_ptr_t prodp,
		mpi_ptr_t up, mpi_ptr_t vp, mpi_size_t size);
/* mpihelp_mul_karatsuba_case has 6 args. Same fix. */
__attribute__((internal_linkage, always_inline))
int mpihelp_mul_karatsuba_case(mpi_ptr_t prodp,
			       mpi_ptr_t up, mpi_size_t usize,
			       mpi_ptr_t vp, mpi_size_t vsize,
			       struct karatsuba_ctx *ctx);
/*-- generic_mpih-mul1.c --*/
__attribute__((internal_linkage, always_inline))
mpi_limb_t mpihelp_mul_1(mpi_ptr_t res_ptr, mpi_ptr_t s1_ptr,
			 mpi_size_t s1_size, mpi_limb_t s2_limb);

/*-- mpih-div.c --*/
mpi_limb_t mpihelp_mod_1(mpi_ptr_t dividend_ptr, mpi_size_t dividend_size,
			 mpi_limb_t divisor_limb);
mpi_limb_t mpihelp_divrem(mpi_ptr_t qp, mpi_size_t qextra_limbs,
			  mpi_ptr_t np, mpi_size_t nsize,
			  mpi_ptr_t dp, mpi_size_t dsize);
mpi_limb_t mpihelp_divmod_1(mpi_ptr_t quot_ptr,
			    mpi_ptr_t dividend_ptr, mpi_size_t dividend_size,
			    mpi_limb_t divisor_limb);

/*-- generic_mpih-[lr]shift.c --*/
mpi_limb_t mpihelp_lshift(mpi_ptr_t wp, mpi_ptr_t up, mpi_size_t usize,
			  unsigned cnt);
mpi_limb_t mpihelp_rshift(mpi_ptr_t wp, mpi_ptr_t up, mpi_size_t usize,
			  unsigned cnt);

/* Define stuff for longlong.h.  */
#define W_TYPE_SIZE BITS_PER_MPI_LIMB
typedef mpi_limb_t UWtype;
typedef unsigned int UHWtype;
#if defined(__GNUC__)
typedef unsigned int UQItype __attribute__ ((mode(QI)));
typedef int SItype __attribute__ ((mode(SI)));
typedef unsigned int USItype __attribute__ ((mode(SI)));
typedef int DItype __attribute__ ((mode(DI)));
typedef unsigned int UDItype __attribute__ ((mode(DI)));
#else
typedef unsigned char UQItype;
typedef long SItype;
typedef unsigned long USItype;
#endif

#ifdef __GNUC__
#include "mpi-inline.h"
#endif
#endif /* G10_MPI_INTERNAL_H */

/* Rename the 6-arg functions mpihelp_mul and mpihelp_mul_karatsuba_case to
 * __bpf_* names before including mpih-mul.c. This prevents the BPF backend
 * from emitting them as standalone functions (they're 6-arg and recursive).
 * Static inline stubs with the original names are provided in EXTRA_PRE_INCLUDE
 * so that mpi-mul.c uses the stubs instead of the renamed functions. */
#define mpihelp_mul_karatsuba_case __bpf_mpihelp_mul_karatsuba_case
#define mpihelp_mul __bpf_mpihelp_mul
/* Force always_inline on all functions defined in mpih-mul.c so the BPF
 * backend inlines them at all call sites (BPF rejects non-static >5-arg
 * function calls and function definitions with stack arguments). */
#pragma clang attribute push(__attribute__((always_inline, internal_linkage)), apply_to=function)
