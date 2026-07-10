#pragma clang attribute pop
static __always_inline void __bpf_ringbuf_commit_direct(struct bpf_ringbuf *rb,
                                                        void *sample,
                                                        u64 flags,
                                                        bool discard)
{
    unsigned long rec_pos, cons_pos;
    struct bpf_ringbuf_hdr *hdr;
    u32 new_len;

    hdr = sample - BPF_RINGBUF_HDR_SZ;
    new_len = hdr->len ^ BPF_RINGBUF_BUSY_BIT;
    if (discard)
        new_len |= BPF_RINGBUF_DISCARD_BIT;
    xchg(&hdr->len, new_len);

    rec_pos = (void *)hdr - (void *)rb->data;
    cons_pos = smp_load_acquire(&rb->consumer_pos) & rb->mask;
    if (flags & BPF_RB_FORCE_WAKEUP)
        irq_work_queue(&rb->work);
    else if (cons_pos == rec_pos && !(flags & BPF_RB_NO_WAKEUP))
        irq_work_queue(&rb->work);
}
