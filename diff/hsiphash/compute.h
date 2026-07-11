/* hsiphash: 32-bit-output keyed ARX PRF -- exercises the BPF backend's 32-bit
 * (on 64-bit hosts, word-sized) rotate/add lowering, complementing siphash's
 * 64-bit path. */
static __u64 diff_compute(const __u64 in[4])
{
	hsiphash_key_t key = { .key = { (unsigned long)in[2], (unsigned long)in[3] } };
	return hsiphash_2u32((__u32)in[0], (__u32)in[1], &key);
}
