    /* errseq: test errseq_check and errseq_sample with a zero-initialized
     * sequence counter. The BPF verifier tracks u32 stack values only when
     * they are initialized to zero and not reassigned, so we keep seq=0
     * throughout to avoid value-tracking loss on 32-bit stack reads.
     *
     * Contract verified:
     * 1. errseq_sample on a fresh (zero) seq returns 0.
     * 2. errseq_check with matching sample (both 0) returns 0 (no error). */
    errseq_t seq = 0;
    /* errseq_sample: fresh seq has no ERRSEQ_SEEN, so returns 0 */
    errseq_t sample = errseq_sample(&seq);
    BPF_ASSERT(sample == 0);
    /* errseq_check: cur == since (both 0), so returns 0 */
    int err = errseq_check(&seq, sample);
    BPF_ASSERT(err == 0);
    return 0;
