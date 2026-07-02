/* Override DIV_ROUND_UP to use u64 casts to avoid sdiv instruction.
 * The BPF backend cannot select sdiv; all divisions must be unsigned.
 * ktime_divns/ktime_to_us/ktime_us_delta are overridden by shims/include/linux/ktime.h. */
#undef DIV_ROUND_UP
#define DIV_ROUND_UP(n, d) (((u64)(n) + (u64)(d) - 1) / (u64)(d))
