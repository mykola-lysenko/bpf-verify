// SPDX-License-Identifier: GPL-2.0-only
/* BPF shim: kernel/bpf/bpf_local_storage.c guard and metadata helpers.
 *
 * The real file owns allocation, RCU teardown, bucket locks, and object-specific
 * storage lifetimes. Keep this shim scoped to local-storage predicates and
 * metadata helpers that can be proved without those subsystems.
 */

#include "bpf_shim_common.h"

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif
#ifndef __rcu
#define __rcu
#endif
#ifndef ____cacheline_aligned
#define ____cacheline_aligned __attribute__((aligned(64)))
#endif

#define BPF_KEEP_SCALAR(x) asm volatile("" : "+r"(x))

#ifndef E2BIG
#define E2BIG 7
#endif
#ifndef EOPNOTSUPP
#define EOPNOTSUPP 95
#endif
#ifndef U16_MAX
#define U16_MAX 65535U
#endif
#ifndef U64_MAX
#define U64_MAX (~0ULL)
#endif

#define MAX_BPF_STACK 512
#define BPF_F_LOCK 4
#define BPF_F_NO_PREALLOC (1U << 0)
#define BPF_F_CLONE (1U << 9)
#define BPF_SPIN_LOCK BIT(0)
#define BPF_LOCAL_STORAGE_CACHE_SIZE 16
#define BPF_LOCAL_STORAGE_CREATE_FLAG_MASK (BPF_F_NO_PREALLOC | BPF_F_CLONE)

#ifndef min_t
#define min_t(type, x, y) ({		\
	type __min1 = (x);		\
	type __min2 = (y);		\
	__min1 < __min2 ? __min1 : __min2; })
#endif

typedef struct {
	int refs;
} refcount_t;

struct btf {
	int dummy;
};

enum btf_kind {
	BTF_KIND_UNKN	= 0,
	BTF_KIND_INT	= 1,
};

struct btf_type {
	u32 kind;
	u32 size;
};

union bpf_attr {
	struct {
		u32 map_type;
		u32 key_size;
		u32 value_size;
		u32 max_entries;
		u32 map_flags;
		u32 inner_map_fd;
		u32 numa_node;
		u64 map_extra;
		u32 btf_key_type_id;
		u32 btf_value_type_id;
	};
};

struct bpf_map {
	u32 key_size;
	u32 value_size;
	u32 max_entries;
	u32 map_flags;
	u32 btf_key_type_id;
	u32 btf_value_type_id;
	void *record;
};

struct btf_record {
	u32 fields;
};

static __always_inline void INIT_HLIST_HEAD(struct hlist_head *h)
{
	h->first = NULL;
}

static __always_inline void INIT_HLIST_NODE(struct hlist_node *h)
{
	h->next = NULL;
	h->pprev = NULL;
}

static __always_inline bool hlist_unhashed(const struct hlist_node *h)
{
	return !h->pprev;
}

static __always_inline bool hlist_unhashed_lockless(const struct hlist_node *h)
{
	return hlist_unhashed(h);
}

static __always_inline void hlist_add_head_rcu(struct hlist_node *n,
					       struct hlist_head *h)
{
	struct hlist_node *first = h->first;

	n->next = first;
	if (first)
		first->pprev = &n->next;
	h->first = n;
	n->pprev = &h->first;
}

static __always_inline void hlist_add_head(struct hlist_node *n,
					   struct hlist_head *h)
{
	hlist_add_head_rcu(n, h);
}

static __always_inline void hlist_del_init_rcu(struct hlist_node *n)
{
	if (!hlist_unhashed(n)) {
		if (n->next)
			n->next->pprev = n->pprev;
		*n->pprev = n->next;
	}
	INIT_HLIST_NODE(n);
}

static __always_inline bool hlist_is_singular_node(struct hlist_node *n,
						   struct hlist_head *h)
{
	return !n->next && n->pprev == &h->first;
}

#define hlist_entry(ptr, type, member) container_of(ptr, type, member)
#define hlist_entry_safe(ptr, type, member) \
	({ typeof(ptr) ____ptr = (ptr); \
	   ____ptr ? hlist_entry(____ptr, type, member) : NULL; })
#define hlist_for_each_entry_rcu(pos, head, member, cond)		     \
	for (pos = hlist_entry_safe((head)->first, typeof(*pos), member); \
	     pos;							     \
	     pos = hlist_entry_safe(pos->member.next, typeof(*pos), member))

struct bpf_local_storage_map_bucket {
	struct hlist_head list;
	rqspinlock_t lock;
};

struct bpf_local_storage_map {
	struct bpf_map map;
	struct bpf_local_storage_map_bucket *buckets;
	u32 bucket_log;
	u16 elem_size;
	u16 cache_idx;
};

struct bpf_local_storage_data {
	struct bpf_local_storage_map __rcu *smap;
	u8 data[16] __attribute__((aligned(8)));
};

#define SELEM_MAP_UNLINKED	(1 << 0)
#define SELEM_STORAGE_UNLINKED	(1 << 1)
#define SELEM_UNLINKED		(SELEM_MAP_UNLINKED | SELEM_STORAGE_UNLINKED)
#define SELEM_TOFREE		(1 << 2)

struct bpf_local_storage_elem {
	struct hlist_node map_node;
	struct hlist_node snode;
	struct bpf_local_storage __rcu *local_storage;
	union {
		struct rcu_head rcu;
		struct hlist_node free_node;
	};
	atomic_t state;
	struct bpf_local_storage_data sdata ____cacheline_aligned;
};

struct bpf_local_storage {
	struct bpf_local_storage_data __rcu *cache[BPF_LOCAL_STORAGE_CACHE_SIZE];
	struct hlist_head list;
	void *owner;
	struct rcu_head rcu;
	rqspinlock_t lock;
	u64 mem_charge;
	refcount_t owner_refcnt;
};

#define BPF_LOCAL_STORAGE_MAX_VALUE_SIZE				       \
	min_t(u32,							       \
	      (KMALLOC_MAX_SIZE - MAX_BPF_STACK -			       \
	       sizeof(struct bpf_local_storage_elem)),			       \
	      (U16_MAX - sizeof(struct bpf_local_storage_elem)))

#define SELEM(_SDATA) container_of((_SDATA), struct bpf_local_storage_elem, sdata)
#define SDATA(_SELEM) (&(_SELEM)->sdata)

struct bpf_local_storage_cache {
	rqspinlock_t idx_lock;
	u64 idx_usage_counts[BPF_LOCAL_STORAGE_CACHE_SIZE];
};

static __always_inline bool refcount_inc_not_zero(refcount_t *r)
{
	if (r->refs <= 0)
		return false;
	r->refs++;
	return true;
}

static __always_inline void refcount_dec(refcount_t *r)
{
	r->refs--;
}

static __always_inline void mem_uncharge(struct bpf_local_storage_map *smap,
					 void *owner, u32 size)
{
	(void)smap;
	(void)owner;
	(void)size;
}

static __always_inline struct bpf_local_storage __rcu **
owner_storage(struct bpf_local_storage_map *smap, void *owner)
{
	(void)smap;
	return (struct bpf_local_storage __rcu **)owner;
}

static __always_inline bool bpf_rcu_lock_held(void)
{
	return true;
}

static __always_inline bool rcu_read_lock_trace_held(void)
{
	return true;
}

static __always_inline int raw_res_spin_lock_irqsave(rqspinlock_t *lock,
						     unsigned long flags)
{
	(void)lock;
	(void)flags;
	return 0;
}

static __always_inline void raw_res_spin_unlock_irqrestore(rqspinlock_t *lock,
							   unsigned long flags)
{
	(void)lock;
	(void)flags;
}

static __always_inline void spin_lock(rqspinlock_t *lock)
{
	(void)lock;
}

static __always_inline void spin_unlock(rqspinlock_t *lock)
{
	(void)lock;
}

static __always_inline bool btf_type_is_i32(const struct btf_type *t)
{
	return t && t->kind == BTF_KIND_INT && t->size == sizeof(int);
}

static __always_inline bool btf_record_has_field(const struct btf_record *rec,
						 u32 field)
{
	return rec && (rec->fields & field);
}

static __always_inline bool selem_linked_to_storage_lockless(
	const struct bpf_local_storage_elem *selem)
{
	return !hlist_unhashed_lockless(&selem->snode);
}

static __always_inline bool selem_linked_to_storage(
	const struct bpf_local_storage_elem *selem)
{
	return !hlist_unhashed(&selem->snode);
}

static __always_inline bool selem_linked_to_map(
	const struct bpf_local_storage_elem *selem)
{
	return !hlist_unhashed(&selem->map_node);
}

static __always_inline void
__bpf_local_storage_insert_cache(struct bpf_local_storage *local_storage,
				 struct bpf_local_storage_map *smap,
				 struct bpf_local_storage_elem *selem)
{
	unsigned long flags = 0;
	u16 cache_idx = smap->cache_idx;
	int err;

	if (cache_idx >= BPF_LOCAL_STORAGE_CACHE_SIZE)
		return;

	/* spinlock is needed to avoid racing with the
	 * parallel delete.  Otherwise, publishing an already
	 * deleted sdata to the cache will become a use-after-free
	 * problem in the next bpf_local_storage_lookup().
	 */
	err = raw_res_spin_lock_irqsave(&local_storage->lock, flags);
	if (err)
		return;

	if (selem_linked_to_storage(selem))
		rcu_assign_pointer(local_storage->cache[cache_idx],
				   SDATA(selem));
	raw_res_spin_unlock_irqrestore(&local_storage->lock, flags);
}

/* If cacheit_lockit is false, this lookup function is lockless */
static __always_inline struct bpf_local_storage_data *
bpf_local_storage_lookup(struct bpf_local_storage *local_storage,
			 struct bpf_local_storage_map *smap,
			 bool cacheit_lockit)
{
	struct bpf_local_storage_data *sdata;
	struct bpf_local_storage_elem *selem;
	u16 cache_idx = smap->cache_idx;

	if (cache_idx >= BPF_LOCAL_STORAGE_CACHE_SIZE)
		return NULL;

	/* Fast path (cache hit) */
	sdata = rcu_dereference_check(local_storage->cache[cache_idx],
				      bpf_rcu_lock_held());
	if (sdata && rcu_access_pointer(sdata->smap) == smap)
		return sdata;

	/* Slow path (cache miss) */
	hlist_for_each_entry_rcu(selem, &local_storage->list, snode,
				 rcu_read_lock_trace_held())
		if (rcu_access_pointer(SDATA(selem)->smap) == smap)
			break;

	if (!selem)
		return NULL;
	if (cacheit_lockit)
		__bpf_local_storage_insert_cache(local_storage, smap, selem);
	return SDATA(selem);
}

static __always_inline int
bpf_local_storage_update_flags_check(struct bpf_local_storage_map *smap,
				     u64 map_flags)
{
	/* BPF_EXIST and BPF_NOEXIST cannot be both set */
	if (unlikely((map_flags & ~BPF_F_LOCK) > BPF_EXIST) ||
	    /* BPF_F_LOCK can only be used in a value with spin_lock */
	    unlikely((map_flags & BPF_F_LOCK) &&
		     !btf_record_has_field(smap->map.record, BPF_SPIN_LOCK)))
		return -EINVAL;

	return 0;
}

static __always_inline int check_flags(const struct bpf_local_storage_data *old_sdata,
				       u64 map_flags)
{
	if (old_sdata && (map_flags & ~BPF_F_LOCK) == BPF_NOEXIST)
		/* elem already exists */
		return -EEXIST;

	if (!old_sdata && (map_flags & ~BPF_F_LOCK) == BPF_EXIST)
		/* elem doesn't exist, cannot update it */
		return -ENOENT;

	return 0;
}

static __always_inline void
bpf_selem_link_storage_nolock(struct bpf_local_storage *local_storage,
			      struct bpf_local_storage_elem *selem)
{
	struct bpf_local_storage_map *smap;

	smap = rcu_dereference_check(SDATA(selem)->smap, bpf_rcu_lock_held());
	local_storage->mem_charge += smap->elem_size;

	RCU_INIT_POINTER(selem->local_storage, local_storage);
	hlist_add_head_rcu(&selem->snode, &local_storage->list);
}

static __always_inline void
bpf_selem_unlink_storage_nolock_misc(struct bpf_local_storage_elem *selem,
				     struct bpf_local_storage_map *smap,
				     struct bpf_local_storage *local_storage,
				     bool free_local_storage, bool pin_owner)
{
	void *owner = local_storage->owner;
	u16 cache_idx = smap->cache_idx;
	u32 uncharge = smap->elem_size;

	if (cache_idx < BPF_LOCAL_STORAGE_CACHE_SIZE &&
	    rcu_access_pointer(local_storage->cache[cache_idx]) ==
	    SDATA(selem))
		RCU_INIT_POINTER(local_storage->cache[cache_idx], NULL);

	if (pin_owner && !refcount_inc_not_zero(&local_storage->owner_refcnt))
		return;

	uncharge += free_local_storage ? sizeof(*local_storage) : 0;
	mem_uncharge(smap, local_storage->owner, uncharge);
	local_storage->mem_charge -= uncharge;

	if (free_local_storage) {
		local_storage->owner = NULL;

		/* After this RCU_INIT, owner may be freed and cannot be used */
		RCU_INIT_POINTER(*owner_storage(smap, owner), NULL);
	}

	if (pin_owner)
		refcount_dec(&local_storage->owner_refcnt);
}

static __always_inline bool
bpf_selem_unlink_storage_nolock(struct bpf_local_storage *local_storage,
				struct bpf_local_storage_elem *selem,
				struct hlist_head *free_selem_list)
{
	struct bpf_local_storage_map *smap;
	bool free_local_storage;

	smap = rcu_dereference_check(SDATA(selem)->smap, bpf_rcu_lock_held());

	free_local_storage = hlist_is_singular_node(&selem->snode,
						    &local_storage->list);

	bpf_selem_unlink_storage_nolock_misc(selem, smap, local_storage,
					     free_local_storage, false);

	hlist_del_init_rcu(&selem->snode);

	hlist_add_head(&selem->free_node, free_selem_list);

	return free_local_storage;
}

static __always_inline void
bpf_selem_link_map_nolock(struct bpf_local_storage_map_bucket *b,
			  struct bpf_local_storage_elem *selem)
{
	hlist_add_head_rcu(&selem->map_node, &b->list);
}

static __always_inline void
bpf_selem_unlink_map_nolock(struct bpf_local_storage_elem *selem)
{
	hlist_del_init_rcu(&selem->map_node);
}

static __always_inline u16
bpf_local_storage_cache_idx_get(struct bpf_local_storage_cache *cache)
{
	u64 min_usage = U64_MAX;
	u16 i, res = 0;

	spin_lock(&cache->idx_lock);

	for (i = 0; i < BPF_LOCAL_STORAGE_CACHE_SIZE; i++) {
		if (cache->idx_usage_counts[i] < min_usage) {
			min_usage = cache->idx_usage_counts[i];
			res = i;

			/* Found a free cache_idx */
			if (!min_usage)
				break;
		}
	}
	cache->idx_usage_counts[res]++;

	spin_unlock(&cache->idx_lock);

	return res;
}

static __always_inline void
bpf_local_storage_cache_idx_free(struct bpf_local_storage_cache *cache,
				 u16 idx)
{
	spin_lock(&cache->idx_lock);
	cache->idx_usage_counts[idx]--;
	spin_unlock(&cache->idx_lock);
}

static __always_inline int bpf_local_storage_map_alloc_check(union bpf_attr *attr)
{
	if (attr->map_flags & ~BPF_LOCAL_STORAGE_CREATE_FLAG_MASK ||
	    !(attr->map_flags & BPF_F_NO_PREALLOC) ||
	    attr->max_entries ||
	    attr->key_size != sizeof(int) || !attr->value_size ||
	    /* Enforce BTF for userspace sk dumping */
	    !attr->btf_key_type_id || !attr->btf_value_type_id)
		return -EINVAL;

	if (attr->value_size > BPF_LOCAL_STORAGE_MAX_VALUE_SIZE)
		return -E2BIG;

	return 0;
}

static __always_inline int
bpf_local_storage_map_check_btf(struct bpf_map *map, const struct btf *btf,
				const struct btf_type *key_type,
				const struct btf_type *value_type)
{
	(void)map;
	(void)btf;
	(void)value_type;

	if (!btf_type_is_i32(key_type))
		return -EINVAL;

	return 0;
}

static __always_inline u64 bpf_local_storage_map_mem_usage(const struct bpf_map *map)
{
	struct bpf_local_storage_map *smap = (struct bpf_local_storage_map *)map;
	u64 usage = sizeof(*smap);

	/* The dynamically callocated selems are not counted currently. */
	usage += sizeof(*smap->buckets) * (1ULL << smap->bucket_log);
	return usage;
}
