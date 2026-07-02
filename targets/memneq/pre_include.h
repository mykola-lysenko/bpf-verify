
/* OPTIMIZER_HIDE_VAR lowers to an extern-like barrier in this BPF harness.
 * For verification, a no-op keeps the constant-time code loadable while still
 * exercising the same data-flow operations. */
#undef OPTIMIZER_HIDE_VAR
#define OPTIMIZER_HIDE_VAR(var) do { } while (0)
