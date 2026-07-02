/* Undefine CONFIG_PRINTK so linux/bug.h uses the static inline no-op version
 * of mem_dump_obj() instead of the extern declaration that requires
 * mm/slab_common.c to be linked in. */
#undef CONFIG_PRINTK
