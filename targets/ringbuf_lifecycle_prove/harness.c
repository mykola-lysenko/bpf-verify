    /* ringbuf_lifecycle_prove: reserve, commit, discard, and dynptr
     * state transitions. The commit helper avoids the source pointer-mask
     * restore step, which the verifier rejects on stack/map-value pointers. */
    __u32 input_key = 0;
    __u64 *input = bpf_map_lookup_elem(&input_map, &input_key);
    __u64 choice = input ? *input : 0;
    struct {
        struct bpf_ringbuf rb;
        char data[128];
    } storage = {};
    struct bpf_ringbuf_map map = {};
    struct bpf_dynptr_kern dynptr = {};
    struct bpf_ringbuf *rb = &storage.rb;
    struct bpf_ringbuf_hdr *hdr;
    void *sample;
    int ret;
    int acc = 0;

    rb->mask = 63;
    rb->consumer_pos = 0;
    rb->producer_pos = 0;
    rb->pending_pos = 0;
    rb->overwrite_pos = 0;
    rb->overwrite_mode = false;
    rb->work.queued = 0;

    BPF_PROVE(__bpf_ringbuf_reserve(rb, RINGBUF_MAX_RECORD_SZ + 1ULL) == NULL);
    BPF_PROVE(__bpf_ringbuf_reserve(rb, 64) == NULL);

    sample = __bpf_ringbuf_reserve(rb, 8);
    BPF_PROVE(sample != NULL);
    hdr = sample - BPF_RINGBUF_HDR_SZ;
    BPF_PROVE(rb->producer_pos == 16);
    BPF_PROVE(rb->pending_pos == 0);
    BPF_PROVE(hdr->len == (8 | BPF_RINGBUF_BUSY_BIT));
    BPF_PROVE(hdr->pg_off == bpf_ringbuf_rec_pg_off(rb, hdr));

    __bpf_ringbuf_commit_direct(rb, sample, BPF_RB_NO_WAKEUP, false);
    BPF_PROVE(hdr->len == 8);
    BPF_PROVE(rb->work.queued == 0);

    sample = __bpf_ringbuf_reserve(rb, 8);
    BPF_PROVE(sample != NULL);
    hdr = sample - BPF_RINGBUF_HDR_SZ;
    BPF_PROVE(rb->producer_pos == 32);
    BPF_PROVE(rb->pending_pos == 16);
    BPF_PROVE(hdr->len == (8 | BPF_RINGBUF_BUSY_BIT));

    __bpf_ringbuf_commit_direct(rb, sample, BPF_RB_FORCE_WAKEUP, true);
    BPF_PROVE(hdr->len == (8 | BPF_RINGBUF_DISCARD_BIT));
    BPF_PROVE(rb->work.queued == 1);

    rb->consumer_pos = 0;
    rb->producer_pos = 0;
    rb->pending_pos = 0;
    rb->overwrite_pos = 0;
    rb->work.queued = 0;
    sample = __bpf_ringbuf_reserve(rb, 8);
    BPF_PROVE(sample != NULL);
    hdr = sample - BPF_RINGBUF_HDR_SZ;
    __bpf_ringbuf_commit_direct(rb, sample, 0, false);
    BPF_PROVE(hdr->len == 8);
    BPF_PROVE(rb->work.queued == 1);

    rb->consumer_pos = 0;
    rb->producer_pos = 0;
    rb->pending_pos = 0;
    rb->overwrite_pos = 0;
    rb->work.queued = 0;
    sample = __bpf_ringbuf_reserve(rb, 8);
    BPF_PROVE(sample != NULL);
    hdr = sample - BPF_RINGBUF_HDR_SZ;
    rb->consumer_pos = 8;
    __bpf_ringbuf_commit_direct(rb, sample, 0, false);
    BPF_PROVE(hdr->len == 8);
    BPF_PROVE(rb->work.queued == 0);

    rb->mask = 31;
    rb->consumer_pos = 0;
    rb->producer_pos = 0;
    rb->pending_pos = 0;
    rb->overwrite_pos = 0;
    rb->overwrite_mode = false;
    sample = __bpf_ringbuf_reserve(rb, 8);
    BPF_PROVE(sample != NULL);
    BPF_PROVE(__bpf_ringbuf_reserve(rb, 8) == NULL);

    rb->consumer_pos = 0;
    rb->producer_pos = 24;
    rb->pending_pos = 24;
    rb->overwrite_pos = 0;
    rb->overwrite_mode = true;
    hdr = (void *)rb->data;
    hdr->len = 8;
    sample = __bpf_ringbuf_reserve(rb, 8);
    BPF_PROVE(sample != NULL);
    hdr = sample - BPF_RINGBUF_HDR_SZ;
    BPF_PROVE(rb->producer_pos == 40);
    BPF_PROVE(rb->overwrite_pos == 16);
    BPF_PROVE(hdr->len == (8 | BPF_RINGBUF_BUSY_BIT));

    rb->mask = 63;
    rb->consumer_pos = 0;
    rb->producer_pos = 0;
    rb->pending_pos = 0;
    rb->overwrite_pos = 0;
    rb->overwrite_mode = false;
    rb->work.queued = 0;
    map.rb = rb;
    ret = bpf_ringbuf_reserve_dynptr(&map.map, 8, 0, &dynptr);
    BPF_PROVE(ret == 0);
    BPF_PROVE(dynptr.data != NULL);
    BPF_PROVE(dynptr.size == 8);
    BPF_PROVE(dynptr.type == BPF_DYNPTR_TYPE_RINGBUF);
    __bpf_ringbuf_commit_direct(rb, dynptr.data, BPF_RB_FORCE_WAKEUP, false);
    bpf_dynptr_set_null(&dynptr);
    BPF_PROVE(dynptr.data == NULL);
    BPF_PROVE(dynptr.size == 0);
    BPF_PROVE(rb->work.queued == 1);

    ret = bpf_ringbuf_reserve_dynptr(&map.map, 8, 1, &dynptr);
    BPF_PROVE(ret == -EINVAL);
    BPF_PROVE(dynptr.data == NULL);

    acc += (int)rb->producer_pos + (int)rb->pending_pos + ret;
    return (int)choice + acc;
