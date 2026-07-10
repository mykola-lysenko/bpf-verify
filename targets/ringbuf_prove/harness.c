    /* ringbuf_prove: verifier-enforced ring-buffer helper invariants.
     *
     * Keep the proof on stack-resident metadata and avoid reserve/commit data
     * paths that require verifier reasoning about the flexible data[] region.
     */
    __u32 input_key = 0;
    __u64 *input = bpf_map_lookup_elem(&input_map, &input_key);
    __u64 choice = input ? *input : 0;
    struct bpf_ringbuf rb = {};
    struct bpf_ringbuf_map map = {};
    struct vm_area_struct vma = {};
    unsigned long base = (choice & 7) << 3;
    unsigned long delta = (choice & 8) ? 8 : 16;
    unsigned long avail;
    __u64 qflag;
    __u64 qval;
    int ret;
    int ok;
    int acc = 0;

    rb.mask = 63;
    rb.consumer_pos = base;
    rb.producer_pos = base + delta;
    rb.pending_pos = base;
    rb.overwrite_pos = base + 8;
    map.map.max_entries = 64;
    map.rb = &rb;

    BPF_PROVE(ringbuf_total_data_sz(&rb) == 64);
    avail = ringbuf_avail_data_sz(&rb);
    BPF_KEEP_SCALAR(avail);
    if (choice & 8)
        BPF_PROVE(avail == 8);
    else
        BPF_PROVE(avail == 16);
    ret = ringbuf_map_poll_kern(&map.map, NULL, NULL);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == (EPOLLIN | EPOLLRDNORM));

    qflag = choice & 3;
    qval = bpf_ringbuf_query(&map.map, qflag);
    BPF_KEEP_SCALAR(qval);
    if (qflag == BPF_RB_AVAIL_DATA) {
        if (choice & 8)
            BPF_PROVE(qval == 8);
        else
            BPF_PROVE(qval == 16);
    } else if (qflag == BPF_RB_RING_SIZE) {
        BPF_PROVE(qval == 64);
    } else if (qflag == BPF_RB_CONS_POS) {
        BPF_PROVE((qval & 7) == 0);
        BPF_PROVE(qval <= 56);
    } else {
        BPF_PROVE((qval & 7) == 0);
        BPF_PROVE(qval >= 8 && qval <= 72);
    }

    rb.overwrite_mode = true;
    rb.producer_pos = base + 32;
    avail = ringbuf_avail_data_sz(&rb);
    BPF_KEEP_SCALAR(avail);
    BPF_PROVE(avail == 24);
    ok = bpf_ringbuf_has_space(&rb, base + ((choice & 64) ? 64 : 63),
                               base, base);
    BPF_KEEP_SCALAR(ok);
    if (choice & 64)
        BPF_PROVE(!ok);
    else
        BPF_PROVE(ok);

    rb.overwrite_mode = false;
    ok = bpf_ringbuf_has_space(&rb, base + ((choice & 128) ? 64 : 63),
                               base, base);
    BPF_KEEP_SCALAR(ok);
    if (choice & 128)
        BPF_PROVE(!ok);
    else
        BPF_PROVE(ok);
    ret = bpf_ringbuf_round_up_hdr_len(0);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == 8);
    if (choice & 16)
        ret = bpf_ringbuf_round_up_hdr_len(BPF_RINGBUF_DISCARD_BIT | 1);
    else
        ret = bpf_ringbuf_round_up_hdr_len(1);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == 16);

    rb.consumer_pos = 0;
    rb.producer_pos = 0;
    ret = ringbuf_map_poll_kern(&map.map, NULL, NULL);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == 0);
    ret = ringbuf_map_poll_user(&map.map, NULL, NULL);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == (EPOLLOUT | EPOLLWRNORM));

    rb.producer_pos = 64;
    ret = ringbuf_map_poll_user(&map.map, NULL, NULL);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == 0);

    vma.vm_flags = VM_WRITE;
    vma.vm_start = 0;
    vma.vm_end = PAGE_SIZE;
    vma.vm_pgoff = (choice & 32) ? 1 : 0;
    if (vma.vm_pgoff == 0) {
        ret = ringbuf_map_mmap_kern(&map.map, &vma);
        BPF_KEEP_SCALAR(ret);
        BPF_PROVE(ret == 0);
        ret = ringbuf_map_mmap_user(&map.map, &vma);
        BPF_KEEP_SCALAR(ret);
        BPF_PROVE(ret == -EPERM);
    } else {
        ret = ringbuf_map_mmap_user(&map.map, &vma);
        BPF_KEEP_SCALAR(ret);
        BPF_PROVE(ret == 0);
    }
    vma.vm_end = PAGE_SIZE * 2;
    ret = ringbuf_map_mmap_kern(&map.map, &vma);
    BPF_KEEP_SCALAR(ret);
    BPF_PROVE(ret == -EPERM);

    BPF_PROVE(ringbuf_map_lookup_elem(&map.map, &input_key) ==
              ERR_PTR(-ENOTSUPP));
    BPF_PROVE(ringbuf_map_update_elem(&map.map, &input_key, &choice, 0) ==
              -ENOTSUPP);
    BPF_PROVE(ringbuf_map_delete_elem(&map.map, &input_key) == -ENOTSUPP);
    BPF_PROVE(ringbuf_map_get_next_key(&map.map, &input_key, &input_key) ==
              -ENOTSUPP);

    acc += ringbuf_avail_data_sz(&rb);
    acc += (int)delta;
    return (int)choice + acc;
