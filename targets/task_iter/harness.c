    /* task_iter: task attach metadata, task/task_file sequence operations,
     * registration, and open-coded task iterator kfunc state. */
    struct bpf_iter_seq_task_info task_info = {};
    struct bpf_iter_seq_task_file_info file_info = {};
    struct bpf_iter_seq_task_vma_info vma_info = {};
    struct seq_file task_seq = { .private = &task_info };
    struct seq_file file_seq = { .private = &file_info };
    struct seq_file vma_seq = { .private = &vma_info };
    struct seq_file fdseq = {};
    union bpf_iter_link_info linfo = {};
    struct bpf_iter_aux_info aux = {};
    struct bpf_link_info link_info = {};
    struct bpf_iter_task task_it = {};
    struct bpf_iter_task_vma vma_it = {};
    struct task_struct *task;
    struct file *file;
    struct vm_area_struct *vma;
    u64 vma_ctx = 0;
    __u32 input_key = 0;
    __u64 *input = bpf_map_lookup_elem(&input_map, &input_key);
    u64 seed = input ? *input : 0;
    loff_t pos = seed & 1;
    void *next = NULL;
    u32 errors = 0;

    __bpf_iter_task_reset();
    linfo.task.tid = 1;
    linfo.task.pid = 1;
    errors |= bpf_iter_attach_task(NULL, &linfo, &aux) != -EINVAL;
    linfo.task.tid = 1;
    linfo.task.pid = 0;
    errors |= bpf_iter_attach_task(NULL, &linfo, &aux) != 0;
    errors |= aux.task.type != BPF_TASK_ITER_TID;
    errors |= aux.task.pid != 1;
    errors |= bpf_iter_fill_link_info(&aux, &link_info) != 0;
    errors |= link_info.iter.task.tid != 1;
    bpf_iter_task_show_fdinfo(&aux, &fdseq);

    errors |= init_seq_pidns(&task_info, &aux) != 0;
    task = task_seq_start(&task_seq, &pos);
    if (task) {
        errors |= task_seq_show(&task_seq, task) != 7;
        next = task_seq_next(&task_seq, task, &pos);
        task_seq_stop(&task_seq, next);
    } else {
        task_seq_stop(&task_seq, NULL);
    }
    fini_seq_pidns(&task_info);

    linfo.task.tid = 0;
    linfo.task.pid = 0;
    linfo.task.pid_fd = 2;
    errors |= bpf_iter_attach_task(NULL, &linfo, &aux) != -EBADF;
    linfo.task.pid_fd = 1;
    errors |= bpf_iter_attach_task(NULL, &linfo, &aux) != 0;
    errors |= aux.task.type != BPF_TASK_ITER_TGID;
    errors |= aux.task.pid != 1;
    link_info.iter.task.tid = 0;
    link_info.iter.task.pid = 0;
    errors |= bpf_iter_fill_link_info(&aux, &link_info) != 0;
    errors |= link_info.iter.task.pid != 1;
    bpf_iter_task_show_fdinfo(&aux, &fdseq);

    aux.task.type = BPF_TASK_ITER_ALL;
    aux.task.pid = 1;
    pos = seed & 1;
    errors |= init_seq_pidns(&file_info, &aux) != 0;
    file = task_file_seq_start(&file_seq, &pos);
    if (file) {
        errors |= task_file_seq_show(&file_seq, file) != 7;
        next = task_file_seq_next(&file_seq, file, &pos);
        task_file_seq_stop(&file_seq, next);
    } else {
        task_file_seq_stop(&file_seq, NULL);
    }
    fini_seq_pidns(&file_info);

    aux.task.type = BPF_TASK_ITER_TID;
    aux.task.pid = 1;
    pos = 0;
    errors |= init_seq_pidns(&vma_info, &aux) != 0;
    vma = task_vma_seq_start(&vma_seq, &pos);
    if (vma) {
        errors |= task_vma_seq_show(&vma_seq, vma) != 7;
        next = task_vma_seq_next(&vma_seq, vma, &pos);
        task_vma_seq_stop(&vma_seq, next);
    } else {
        errors |= 1;
        task_vma_seq_stop(&vma_seq, NULL);
    }
    fini_seq_pidns(&vma_info);

    errors |= bpf_find_vma(&__bpf_iter_task0, 0x1000, __bpf_iter_vma_cb,
                           &vma_ctx, 1) != -EINVAL;
    errors |= bpf_find_vma(NULL, 0x1000, __bpf_iter_vma_cb,
                           &vma_ctx, 0) != -ENOENT;
    errors |= bpf_find_vma(&__bpf_iter_task0, 0x3000, __bpf_iter_vma_cb,
                           &vma_ctx, 0) != -ENOENT;
    errors |= bpf_find_vma(&__bpf_iter_task0, 0x1000, __bpf_iter_vma_cb,
                           &vma_ctx, 0) != 0;
    errors |= vma_ctx != (u64)(long)&__bpf_iter_vma;

    errors |= bpf_iter_task_vma_new(&vma_it, &__bpf_iter_task0, 0x1000) !=
              -EOPNOTSUPP;
    errors |= bpf_iter_task_vma_next(&vma_it) != NULL;
    bpf_iter_task_vma_destroy(&vma_it);

    errors |= bpf_iter_task_new(&task_it, NULL, BPF_TASK_ITER_PROC_THREADS) != -EINVAL;
    errors |= bpf_iter_task_new(&task_it, NULL, BPF_TASK_ITER_ALL_PROCS) != 0;
    task = bpf_iter_task_next(&task_it);
    errors |= task == NULL;
    task = bpf_iter_task_next(&task_it);
    bpf_iter_task_destroy(&task_it);

    errors |= task_iter_init() != 0;

    return (int)(errors + __bpf_iter_runs + __bpf_iter_regs +
                 __bpf_iter_task_gets + __bpf_iter_task_puts +
                 __bpf_iter_file_gets + __bpf_iter_file_puts +
                 __bpf_iter_pid_ns_gets + __bpf_iter_pid_ns_puts +
                 __bpf_iter_mm_gets + __bpf_iter_mm_puts +
                 __bpf_iter_vma_callbacks + fdseq.writes + pos + (next != NULL) +
                 (task != NULL) + (seed & 1));
