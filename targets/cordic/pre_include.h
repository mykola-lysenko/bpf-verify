/* Step 1: define renamed struct tag BEFORE the function-rename macro. */
struct __bpf_cordic_iq { s32 i; s32 q; };
/* Step 2: rename function and inject internal_linkage.
 * The macro also renames 'struct cordic_iq' -> 'struct __bpf_cordic_iq'. */
#define cordic_iq       __bpf_cordic_iq
#define cordic_calc_iq  __attribute__((internal_linkage)) __bpf_cordic_calc_iq
/* Step 3: block linux/cordic.h -- its struct/function declarations would conflict. */
#define __CORDIC_H_
/* Provide the macros that linux/cordic.h would have given us. */
#define CORDIC_ANGLE_GEN        39797
#define CORDIC_PRECISION_SHIFT  16
#define CORDIC_NUM_ITER         (CORDIC_PRECISION_SHIFT + 2)
#define CORDIC_FIXED(X)         ((s32)((X) << CORDIC_PRECISION_SHIFT))
#define CORDIC_FLOAT(X)         (((X) >= 0)         ? ((((X) >> (CORDIC_PRECISION_SHIFT - 1)) + 1) >> 1)         : -((((-(X)) >> (CORDIC_PRECISION_SHIFT - 1)) + 1) >> 1))
