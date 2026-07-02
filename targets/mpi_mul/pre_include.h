
/* End the internal_linkage scope from shims/lib/crypto/mpi/mpi-internal.h
 * before the mpi_mul/mpi_mulm renames below. */
#pragma clang attribute pop
/* Undo the rename macros so the stubs below use the original names. */
#undef mpihelp_mul_karatsuba_case
#undef mpihelp_mul
/* Provide static inline stubs for mpi-mul.c to use instead of the renamed
 * 6-arg functions. The stubs return -ENOMEM (Karatsuba path not taken in BPF). */
static inline int mpihelp_mul_karatsuba_case(
    mpi_ptr_t prodp, mpi_ptr_t up, mpi_size_t usize,
    mpi_ptr_t vp, mpi_size_t vsize, struct karatsuba_ctx *ctx)
{
    (void)prodp; (void)up; (void)usize; (void)vp; (void)vsize; (void)ctx;
    return -ENOMEM;
}
static inline int mpihelp_mul(
    mpi_ptr_t prodp, mpi_ptr_t up, mpi_size_t usize,
    mpi_ptr_t vp, mpi_size_t vsize, mpi_limb_t *_result)
{
    (void)prodp; (void)up; (void)usize; (void)vp; (void)vsize; (void)_result;
    return -ENOMEM;
}
/* Stubs for mpiutil.c functions called from mpi-mul.c.
 * These are declared with internal_linkage in mpi-internal.h so the BPF
 * backend can DCE them. Provide definitions so they can be inlined. */
static inline mpi_ptr_t mpi_alloc_limb_space(unsigned nlimbs)
    { (void)nlimbs; return NULL; }
static inline void mpi_free_limb_space(mpi_ptr_t a)
    { (void)a; }
static inline void mpi_assign_limb_space(MPI a, mpi_ptr_t ap, unsigned nlimbs)
    { (void)a; (void)ap; (void)nlimbs; }
/* mpi_resize and mpi_tdiv_r are declared in linux/mpi.h (not mpi-internal.h),
 * so we can't add internal_linkage to their declarations there.
 * Instead, rename them via macros so mpi-mul.c calls the stubs below. */
#define mpi_resize __bpf_mpi_resize
#define mpi_tdiv_r __bpf_mpi_tdiv_r
static inline int __bpf_mpi_resize(MPI a, unsigned nlimbs)
    { (void)a; (void)nlimbs; return -ENOMEM; }
static inline int __bpf_mpi_tdiv_r(MPI rem, MPI num, MPI den)
    { (void)rem; (void)num; (void)den; return 0; }
/* Rename mpi_mul and mpi_mulm so the BPF backend emits them as __bpf_*
 * symbols (not the external mpi_mul/mpi_mulm). Since they're never called
 * from bpf_prog_mpi_mul, the BPF backend will DCE them. */
#define mpi_mul __bpf_mpi_mul
#define mpi_mulm __bpf_mpi_mulm
