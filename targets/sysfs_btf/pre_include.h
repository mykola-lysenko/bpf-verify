#include <linux/errno.h>
#define _LINUX_KERNEL_H
#define _KOBJECT_H_
#define _LINUX_INIT_H
#define _SYSFS_H_
#define _LINUX_MM_H
#define _LINUX_IO_H
#define _LINUX_BTF_H
#define __ro_after_init
#define __init
#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL << PAGE_SHIFT)
#define PAGE_ALIGN(x) (((x) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1))
#define PAGE_ALIGNED(x) (((x) & (PAGE_SIZE - 1)) == 0)
#define VM_WRITE 0x00000002UL
#define VM_EXEC 0x00000004UL
#define VM_MAYSHARE 0x00000080UL
#define VM_MAYEXEC 0x00000008UL
#define VM_MAYWRITE 0x00000010UL
#define VM_DONTDUMP 0x00000020UL
#define __pa_symbol(x) ((phys_addr_t)0)
#define __start_BTF __bpf_sysfs_btf_start
#define __stop_BTF __bpf_sysfs_btf_stop

struct file {
    u32 id;
};
struct kobject {
    u32 id;
};
struct attribute {
    const char *name;
    umode_t mode;
};
struct vm_area_struct {
    unsigned long vm_start;
    unsigned long vm_end;
    unsigned long vm_flags;
    unsigned long vm_pgoff;
    unsigned long vm_page_prot;
};
struct bin_attribute {
    struct attribute attr;
    ssize_t (*read)(struct file *file, struct kobject *kobj,
                    struct bin_attribute *attr, char *buf, loff_t off,
                    size_t count);
    int (*mmap)(struct file *file, struct kobject *kobj,
                const struct bin_attribute *attr,
                struct vm_area_struct *vma);
    void *private;
    size_t size;
};

static char __bpf_sysfs_btf_start[PAGE_SIZE];
static char __bpf_sysfs_btf_stop[1];
static struct kobject __bpf_sysfs_kernel_kobj;
static struct kobject *kernel_kobj = &__bpf_sysfs_kernel_kobj;
static volatile u32 __bpf_sysfs_mmaps;

static inline ssize_t sysfs_bin_attr_simple_read(struct file *file,
                                                 struct kobject *kobj,
                                                 struct bin_attribute *attr,
                                                 char *buf, loff_t off,
                                                 size_t count)
{
    (void)file;
    (void)kobj;
    (void)attr;
    (void)buf;
    (void)off;
    return (ssize_t)count;
}
static inline struct kobject *kobject_create_and_add(const char *name,
                                                     struct kobject *parent)
{
    (void)name;
    return parent ? parent : &__bpf_sysfs_kernel_kobj;
}
static inline int sysfs_create_bin_file(struct kobject *kobj,
                                        const struct bin_attribute *attr)
{
    return (!kobj || !attr) ? -EINVAL : 0;
}
static inline void vm_flags_mod(struct vm_area_struct *vma,
                                unsigned long set,
                                unsigned long clear)
{
    vma->vm_flags |= set;
    vma->vm_flags &= ~clear;
}
static inline int remap_pfn_range(struct vm_area_struct *vma,
                                  unsigned long addr, unsigned long pfn,
                                  size_t size, unsigned long prot)
{
    (void)vma;
    (void)addr;
    (void)pfn;
    (void)size;
    (void)prot;
    __bpf_sysfs_mmaps++;
    return 0;
}
