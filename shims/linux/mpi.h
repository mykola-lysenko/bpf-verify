/* BPF shim: linux/mpi.h
 * Re-declares all MPI functions with __attribute__((internal_linkage)) so that
 * when mpi-internal.h's pragma push applies internal_linkage to their definitions
 * in mpiutil.c / mpih-cmp.c / etc., clang does not complain that
 * "internal_linkage attribute does not appear on the first declaration".
 */
#ifndef G10_MPI_H
#define G10_MPI_H

#include <linux/types.h>
#include <linux/scatterlist.h>

#define BYTES_PER_MPI_LIMB	(BITS_PER_LONG / 8)
#define BITS_PER_MPI_LIMB	BITS_PER_LONG

typedef unsigned long int mpi_limb_t;
typedef signed long int mpi_limb_signed_t;

struct gcry_mpi {
	int alloced;
	int nlimbs;
	int nbits;
	int sign;
	unsigned flags;
	mpi_limb_t *d;
};

typedef struct gcry_mpi *MPI;

#define mpi_get_nlimbs(a)     ((a)->nlimbs)

/* All declarations carry internal_linkage so that when the pragma push in
 * mpi-internal.h applies internal_linkage to the definitions, clang sees a
 * consistent first declaration. */
#define _MPI_IL __attribute__((internal_linkage))

/*-- mpiutil.c --*/
MPI _MPI_IL mpi_alloc(unsigned nlimbs);
void _MPI_IL mpi_free(MPI a);
int _MPI_IL mpi_resize(MPI a, unsigned nlimbs);
MPI _MPI_IL mpi_copy(MPI a);

/*-- mpicoder.c --*/
MPI _MPI_IL mpi_read_raw_data(const void *xbuffer, size_t nbytes);
MPI _MPI_IL mpi_read_from_buffer(const void *buffer, unsigned *ret_nread);
MPI _MPI_IL mpi_read_raw_from_sgl(struct scatterlist *sgl, unsigned int len);
void * _MPI_IL mpi_get_buffer(MPI a, unsigned *nbytes, int *sign);
int _MPI_IL mpi_read_buffer(MPI a, uint8_t *buf, unsigned buf_len,
                             unsigned *nbytes, int *sign);
int _MPI_IL mpi_write_to_sgl(MPI a, struct scatterlist *sg, unsigned nbytes,
                               int *sign);

/*-- mpi-mod.c --*/
int _MPI_IL mpi_mod(MPI rem, MPI dividend, MPI divisor);

/*-- mpi-pow.c --*/
int _MPI_IL mpi_powm(MPI res, MPI base, MPI exp, MPI mod);

/*-- mpi-cmp.c --*/
int _MPI_IL mpi_cmp_ui(MPI u, ulong v);
int _MPI_IL mpi_cmp(MPI u, MPI v);

/*-- mpi-sub-ui.c --*/
int _MPI_IL mpi_sub_ui(MPI w, MPI u, unsigned long vval);

/*-- mpi-bit.c --*/
void _MPI_IL mpi_normalize(MPI a);
unsigned _MPI_IL mpi_get_nbits(MPI a);
int _MPI_IL mpi_test_bit(MPI a, unsigned int n);
int _MPI_IL mpi_set_bit(MPI a, unsigned int n);
int _MPI_IL mpi_rshift(MPI x, MPI a, unsigned int n);

/*-- mpi-add.c --*/
int _MPI_IL mpi_add(MPI w, MPI u, MPI v);
int _MPI_IL mpi_sub(MPI w, MPI u, MPI v);
int _MPI_IL mpi_addm(MPI w, MPI u, MPI v, MPI m);
int _MPI_IL mpi_subm(MPI w, MPI u, MPI v, MPI m);

/*-- mpi-mul.c --*/
int _MPI_IL mpi_mul(MPI w, MPI u, MPI v);
int _MPI_IL mpi_mulm(MPI w, MPI u, MPI v, MPI m);

/*-- mpi-div.c --*/
int _MPI_IL mpi_tdiv_r(MPI rem, MPI num, MPI den);
int _MPI_IL mpi_fdiv_r(MPI rem, MPI dividend, MPI divisor);

#undef _MPI_IL

/* inline functions */
static inline unsigned int mpi_get_size(MPI a)
{
	return a->nlimbs * BYTES_PER_MPI_LIMB;
}

#endif /* G10_MPI_H */
