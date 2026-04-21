/* BPF shim: linux/mmzone.h
 * mmzone.h includes mm_types.h which contains BPF-incompatible constructs
 * (set_mask_bits with try_cmpxchg inside static inline functions).
 * For BPF verification we only need forward declarations of the key types
 * plus the MIGRATE_* enum and ZONES_SHIFT used by gfp.h.
 */
#ifndef _LINUX_MMZONE_H
#define _LINUX_MMZONE_H

#include <linux/types.h>
#include <linux/page-flags-layout.h>

/* Forward declarations of types used by gfp.h, slab.h, etc. */
struct zone;
struct pglist_data;
struct folio;
struct page;
struct mem_cgroup;

/* Minimal zone index constants needed by gfp.h */
enum zone_type {
ZONE_DMA,
ZONE_DMA32,
ZONE_NORMAL,
ZONE_MOVABLE,
__MAX_NR_ZONES
};

#define MAX_NR_ZONES__MAX_NR_ZONES
#ifndef MAX_NUMNODES
#define MAX_NUMNODES1
#endif
#define MAX_ZONES_PER_ZONELIST ((MAX_NUMNODES) * (MAX_NR_ZONES))

struct zoneref {
struct zone *zone;
int zone_idx;
};

struct zonelist {
struct zoneref _zonerefs[MAX_ZONES_PER_ZONELIST + 1];
};

/* migrate types needed by gfp.h */
enum migratetype {
MIGRATE_UNMOVABLE,
MIGRATE_MOVABLE,
MIGRATE_RECLAIMABLE,
MIGRATE_PCPTYPES,
MIGRATE_HIGHATOMIC = MIGRATE_PCPTYPES,
__MIGRATE_TYPE_END = MIGRATE_HIGHATOMIC,
MIGRATE_TYPES
};

extern int page_group_by_mobility_disabled;

static inline int get_pageblock_migratetype(struct page *page) { return MIGRATE_UNMOVABLE; }

#endif /* _LINUX_MMZONE_H */
