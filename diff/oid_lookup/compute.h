/* oid_lookup: look_up_OID -- hash the OID octets (multiply-by-33, shift/xor
 * fold) then binary-search the sorted registry table (hash, then length, then
 * reverse memcmp). Deterministic (data,len) -> enum OID; hash arithmetic +
 * binary search + table lookup codegen, native vs BPF. Random octets mostly
 * miss (return OID__NR), but the full hash + search still runs each call. */
static __u64 diff_compute(const __u64 in[4])
{
	unsigned char oid[8];
	int i;
	unsigned int len = 3 + (unsigned int)(in[3] & 5);   /* 3..8 octets */

	for (i = 0; i < 8; i++)
		oid[i] = (unsigned char)(in[i >> 1] >> ((i & 1) * 8 + (i * 3)));

	return (__u64)(int)look_up_OID(oid, len) ^ ((__u64)len << 40);
}
