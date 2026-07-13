/* Two MAC states + scratch in a static global area (poly1305_desc_ctx is ~90
 * bytes; two of them plus the message press the 512-byte stack once the donna
 * block function's locals are added). */
/* Data buffers in a static global area; the two poly1305_desc_ctx stay on the
 * harness STACK (see harness.c) -- desc->buflen must be a verifier-tracked
 * stack value, not an unknown scalar reloaded from map memory. */
static struct {
	u8 key[POLY1305_KEY_SIZE];
	u8 msg[32];
	u8 tag1[POLY1305_DIGEST_SIZE];
} __bpf_poly;
