/* Forward declaration with internal_linkage so rational_best_approximation()
 * (6 args) is accepted by the BPF backend. */
__attribute__((internal_linkage))
void rational_best_approximation(
    unsigned long given_numerator, unsigned long given_denominator,
    unsigned long max_numerator, unsigned long max_denominator,
    unsigned long *best_numerator, unsigned long *best_denominator);
