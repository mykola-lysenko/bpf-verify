    /* sysfs_btf: validate vmlinux BTF sysfs mmap acceptance/rejection paths. */
    struct vm_area_struct vma = {
        .vm_start = 0,
        .vm_end = PAGE_SIZE,
        .vm_flags = 0,
        .vm_pgoff = 0,
        .vm_page_prot = 0,
    };
    struct file file = {};
    struct kobject kobj = {};
    u32 errors = 0;

    bin_attr_btf_vmlinux.private = __bpf_sysfs_btf_start;
    bin_attr_btf_vmlinux.size = PAGE_SIZE;
    errors |= btf_sysfs_vmlinux_mmap(&file, &kobj, &bin_attr_btf_vmlinux,
                                     &vma) != 0;

    vma.vm_pgoff = 1;
    errors |= btf_sysfs_vmlinux_mmap(&file, &kobj, &bin_attr_btf_vmlinux,
                                     &vma) != -EINVAL;
    vma.vm_pgoff = 0;
    vma.vm_flags = VM_WRITE;
    errors |= btf_sysfs_vmlinux_mmap(&file, &kobj, &bin_attr_btf_vmlinux,
                                     &vma) != -EACCES;
    vma.vm_flags = 0;
    bin_attr_btf_vmlinux.private = NULL;
    errors |= btf_sysfs_vmlinux_mmap(&file, &kobj, &bin_attr_btf_vmlinux,
                                     &vma) != -EINVAL;

    return (int)(errors + __bpf_sysfs_mmaps + vma.vm_flags);
