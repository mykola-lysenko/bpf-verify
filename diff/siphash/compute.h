/* siphash: keyed ARX pseudo-random function -- 64-bit adds, rotates and xors
 * over a 128-bit key. Stresses the BPF backend's 64-bit rotate/add lowering.
 * Hash two u64 words under a key derived from the remaining inputs. */
static __u64 diff_compute(const __u64 in[4])
{
	siphash_key_t key = { .key = { in[2], in[3] } };
	return siphash_2u64(in[0], in[1], &key);
}
