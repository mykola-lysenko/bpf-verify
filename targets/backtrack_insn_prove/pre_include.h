/* Inline the transfer helper only for this proof target. */
#undef noinline
#define noinline __attribute__((always_inline))
#pragma clang attribute push(__attribute__((always_inline)), apply_to=function)
