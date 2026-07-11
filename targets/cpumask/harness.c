    /* cpumask: BPF kfunc wrappers for mutable/refcounted CPU masks.
     * Covers allocation/refcount transitions, single-bit mutation,
     * predicate/query helpers, set algebra, copying, selection helpers,
     * population from raw bitmap storage, and kfunc registration.
     */
    struct bpf_cpumask a = {};
    struct bpf_cpumask b = {};
    struct bpf_cpumask out = {};
    struct bpf_cpumask *created;
    struct bpf_cpumask *acquired;
    unsigned long raw = 0x9;

    BPF_ASSERT(cpumask_kfunc_init() == 0);
    created = bpf_cpumask_create();
    BPF_ASSERT(created != NULL);
    BPF_ASSERT(bpf_cpumask_empty((struct cpumask *)created));
    BPF_ASSERT(refcount_read(&created->usage) == 1);
    acquired = bpf_cpumask_acquire(created);
    BPF_ASSERT(acquired == created);
    BPF_ASSERT(refcount_read(&created->usage) == 2);
    bpf_cpumask_release(created);
    BPF_ASSERT(refcount_read(&created->usage) == 1);
    bpf_cpumask_release_dtor(created);
    BPF_ASSERT(__bpf_cpumask_frees == 1);

    BPF_ASSERT(bpf_cpumask_empty((struct cpumask *)&a));
    bpf_cpumask_set_cpu(1, &a);
    BPF_ASSERT(bpf_cpumask_test_cpu(1, (struct cpumask *)&a));
    BPF_ASSERT(bpf_cpumask_first((struct cpumask *)&a) == 1);
    BPF_ASSERT(bpf_cpumask_first_zero((struct cpumask *)&a) == 0);
    BPF_ASSERT(bpf_cpumask_weight((struct cpumask *)&a) == 1);
    bpf_cpumask_set_cpu(BPF_CPUMASK_NR_CPUS, &a);
    BPF_ASSERT(!bpf_cpumask_test_cpu(BPF_CPUMASK_NR_CPUS,
                                     (struct cpumask *)&a));

    BPF_ASSERT(!bpf_cpumask_test_and_set_cpu(3, &a));
    BPF_ASSERT(bpf_cpumask_test_and_set_cpu(3, &a));
    BPF_ASSERT(bpf_cpumask_test_and_clear_cpu(3, &a));
    BPF_ASSERT(!bpf_cpumask_test_and_clear_cpu(3, &a));

    bpf_cpumask_set_cpu(2, &b);
    bpf_cpumask_set_cpu(3, &b);
    BPF_ASSERT(bpf_cpumask_first_and((struct cpumask *)&a,
                                     (struct cpumask *)&b) ==
               BPF_CPUMASK_NR_CPUS);
    bpf_cpumask_set_cpu(2, &a);
    BPF_ASSERT(bpf_cpumask_first_and((struct cpumask *)&a,
                                     (struct cpumask *)&b) == 2);
    BPF_ASSERT(bpf_cpumask_intersects((struct cpumask *)&a,
                                      (struct cpumask *)&b));
    BPF_ASSERT(bpf_cpumask_and(&out, (struct cpumask *)&a,
                               (struct cpumask *)&b));
    BPF_ASSERT(bpf_cpumask_weight((struct cpumask *)&out) == 1);
    BPF_ASSERT(bpf_cpumask_test_cpu(2, (struct cpumask *)&out));

    bpf_cpumask_or(&out, (struct cpumask *)&a, (struct cpumask *)&b);
    BPF_ASSERT(bpf_cpumask_weight((struct cpumask *)&out) == 3);
    BPF_ASSERT(bpf_cpumask_subset((struct cpumask *)&a,
                                  (struct cpumask *)&out));
    bpf_cpumask_xor(&out, (struct cpumask *)&a, (struct cpumask *)&b);
    BPF_ASSERT(bpf_cpumask_test_cpu(1, (struct cpumask *)&out));
    BPF_ASSERT(!bpf_cpumask_test_cpu(2, (struct cpumask *)&out));
    BPF_ASSERT(bpf_cpumask_test_cpu(3, (struct cpumask *)&out));
    BPF_ASSERT(!bpf_cpumask_equal((struct cpumask *)&a,
                                  (struct cpumask *)&out));

    bpf_cpumask_copy(&out, (struct cpumask *)&a);
    BPF_ASSERT(bpf_cpumask_equal((struct cpumask *)&a,
                                 (struct cpumask *)&out));
    BPF_ASSERT(bpf_cpumask_any_distribute((struct cpumask *)&a) == 1);
    BPF_ASSERT(bpf_cpumask_any_and_distribute((struct cpumask *)&a,
                                              (struct cpumask *)&b) == 2);

    bpf_cpumask_setall(&out);
    BPF_ASSERT(bpf_cpumask_full((struct cpumask *)&out));
    BPF_ASSERT(bpf_cpumask_first_zero((struct cpumask *)&out) ==
               BPF_CPUMASK_NR_CPUS);
    bpf_cpumask_clear(&out);
    BPF_ASSERT(bpf_cpumask_empty((struct cpumask *)&out));
    BPF_ASSERT(bpf_cpumask_first((struct cpumask *)&out) ==
               BPF_CPUMASK_NR_CPUS);

    /* bpf_cpumask_populate() takes a struct bpf_cpumask * (the "owned cpumask"
     * requirement, bpf-next 520d7d794); out is already one, so no cast. */
    BPF_ASSERT(bpf_cpumask_populate(&out, &raw, sizeof(raw)) == 0);
    BPF_ASSERT(bpf_cpumask_test_cpu(0, (struct cpumask *)&out));
    BPF_ASSERT(bpf_cpumask_test_cpu(3, (struct cpumask *)&out));
    BPF_ASSERT(bpf_cpumask_populate(&out, &raw, 1) == -EACCES);

    return (int)(bpf_cpumask_weight((struct cpumask *)&out) +
                 __bpf_cpumask_allocs + __bpf_cpumask_frees);
