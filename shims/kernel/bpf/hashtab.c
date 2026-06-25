// SPDX-License-Identifier: GPL-2.0-only
/* BPF shim: kernel/bpf/hashtab.c guard, layout, and accounting helpers.
 *
 * The real file pulls in RCU nulls lists, bpf_mem_alloc, map-in-map, LRU, and
 * rhashtable machinery. Keep this shim scoped to helper bodies that can be
 * verified without those subsystems.
 */

#include "bpf_shim_common.h"

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif
#ifndef __percpu
#define __percpu
#endif

#define BPF_KEEP_SCALAR(x) asm volatile("" : "+r"(x))

#define E2BIG 7
#define EPERM 1
#define ENOTSUPP 95

#define CAP_SYS_ADMIN 21
#define PCPU_MIN_UNIT_SIZE (32U << 10)
#define PERCPU_COUNTER_BATCH 32
#define HTAB_TEST_NR_CPUS 4

#define BPF_EXIST 2
#define BPF_F_LOCK 4
#define BPF_F_ALL_CPUS 16

#define BPF_F_NO_PREALLOC   (1U << 0)
#define BPF_F_NO_COMMON_LRU (1U << 1)
#define BPF_F_NUMA_NODE     (1U << 2)
#define BPF_F_RDONLY        (1U << 3)
#define BPF_F_WRONLY        (1U << 4)
#define BPF_F_ZERO_SEED     (1U << 6)
#define BPF_F_RDONLY_PROG   (1U << 7)
#define BPF_F_WRONLY_PROG   (1U << 8)

#define BPF_F_ACCESS_MASK \
	(BPF_F_RDONLY | BPF_F_RDONLY_PROG | BPF_F_WRONLY | BPF_F_WRONLY_PROG)

#define HTAB_CREATE_FLAG_MASK						\
	(BPF_F_NO_PREALLOC | BPF_F_NO_COMMON_LRU | BPF_F_NUMA_NODE |	\
	 BPF_F_ACCESS_MASK | BPF_F_ZERO_SEED)

#ifndef round_up
#define round_up(x, y) ((((x) + (y) - 1) / (y)) * (y))
#endif

enum bpf_map_type {
	BPF_MAP_TYPE_UNSPEC,
	BPF_MAP_TYPE_HASH,
	BPF_MAP_TYPE_ARRAY,
	BPF_MAP_TYPE_PROG_ARRAY,
	BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	BPF_MAP_TYPE_PERCPU_HASH,
	BPF_MAP_TYPE_PERCPU_ARRAY,
	BPF_MAP_TYPE_STACK_TRACE,
	BPF_MAP_TYPE_CGROUP_ARRAY,
	BPF_MAP_TYPE_LRU_HASH,
	BPF_MAP_TYPE_LRU_PERCPU_HASH,
	BPF_MAP_TYPE_LPM_TRIE,
	BPF_MAP_TYPE_ARRAY_OF_MAPS,
	BPF_MAP_TYPE_HASH_OF_MAPS,
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
	};
};

struct bpf_map {
	u32 map_type;
	u32 key_size;
	u32 value_size;
	u32 max_entries;
	u32 map_flags;
	int numa_node;
	u32 elem_count;
};

struct bpf_mem_alloc {
	int dummy;
};

struct hlist_nulls_node {
	struct hlist_nulls_node *next;
	struct hlist_nulls_node **pprev;
};

struct hlist_nulls_head {
	struct hlist_nulls_node *first;
};

struct bucket {
	struct hlist_nulls_head head;
	rqspinlock_t raw_lock;
};

struct pcpu_freelist_node {
	struct pcpu_freelist_node *next;
};

struct pcpu_freelist_head {
	struct pcpu_freelist_node *first;
	rqspinlock_t lock;
};

struct pcpu_freelist {
	struct pcpu_freelist_head __percpu *freelist;
};

struct llist_node {
	struct llist_node *next;
};

struct bpf_lru_node {
	union {
		struct list_head list;
		struct llist_node llist;
	};
	u16 cpu;
	u8 type;
	u8 ref;
	u8 pending_free;
};

struct bpf_lru {
	void *storage[12];
};

struct percpu_counter {
	s64 count;
};

struct bpf_htab {
	struct bpf_map map;
	struct bpf_mem_alloc ma;
	struct bpf_mem_alloc pcpu_ma;
	struct bucket *buckets;
	void *elems;
	union {
		struct pcpu_freelist freelist;
		struct bpf_lru lru;
	};
	struct htab_elem *__percpu *extra_elems;
	struct percpu_counter pcount;
	atomic_t count;
	bool use_percpu_counter;
	u32 n_buckets;
	u32 elem_size;
	u32 hashrnd;
};

struct htab_elem {
	union {
		struct hlist_nulls_node hash_node;
		struct {
			void *padding;
			union {
				struct pcpu_freelist_node fnode;
				struct htab_elem *batch_flink;
			};
		};
	};
	union {
		void *ptr_to_pptr;
		struct bpf_lru_node lru_node;
	};
	u32 hash;
	char key[] __attribute__((aligned(8)));
};

static __always_inline bool capable(int cap)
{
	(void)cap;
	return false;
}

static __always_inline unsigned int num_possible_cpus(void)
{
	return HTAB_TEST_NR_CPUS;
}

static __always_inline int bpf_map_attr_numa_node(const union bpf_attr *attr)
{
	return (attr->map_flags & BPF_F_NUMA_NODE) ?
	       (int)attr->numa_node : NUMA_NO_NODE;
}

static __always_inline bool bpf_map_flags_access_ok(u32 access_flags)
{
	return (access_flags & (BPF_F_RDONLY_PROG | BPF_F_WRONLY_PROG)) !=
	       (BPF_F_RDONLY_PROG | BPF_F_WRONLY_PROG);
}

static __always_inline int atomic_read(const atomic_t *v)
{
	return v->counter;
}

static __always_inline void atomic_set(atomic_t *v, int i)
{
	v->counter = i;
}

static __always_inline void atomic_inc(atomic_t *v)
{
	v->counter++;
}

static __always_inline void atomic_dec(atomic_t *v)
{
	v->counter--;
}

static __always_inline void percpu_counter_set(struct percpu_counter *fbc, s64 amount)
{
	fbc->count = amount;
}

static __always_inline s64 percpu_counter_sum(struct percpu_counter *fbc)
{
	return fbc->count;
}

static __always_inline void percpu_counter_add_batch(struct percpu_counter *fbc,
						     s64 amount,
						     s32 batch)
{
	(void)batch;
	fbc->count += amount;
}

static __always_inline int __percpu_counter_compare(struct percpu_counter *fbc,
						    s64 rhs,
						    s32 batch)
{
	(void)batch;

	if (fbc->count < rhs)
		return -1;
	if (fbc->count > rhs)
		return 1;
	return 0;
}

static __always_inline void bpf_map_inc_elem_count(struct bpf_map *map)
{
	map->elem_count++;
}

static __always_inline void bpf_map_dec_elem_count(struct bpf_map *map)
{
	map->elem_count--;
}

static __always_inline bool htab_is_prealloc(const struct bpf_htab *htab)
{
	return !(htab->map.map_flags & BPF_F_NO_PREALLOC);
}

static __always_inline bool htab_is_lru(const struct bpf_htab *htab)
{
	return htab->map.map_type == BPF_MAP_TYPE_LRU_HASH ||
		htab->map.map_type == BPF_MAP_TYPE_LRU_PERCPU_HASH;
}

static __always_inline bool htab_is_percpu(const struct bpf_htab *htab)
{
	return htab->map.map_type == BPF_MAP_TYPE_PERCPU_HASH ||
		htab->map.map_type == BPF_MAP_TYPE_LRU_PERCPU_HASH;
}

static __always_inline bool is_fd_htab(const struct bpf_htab *htab)
{
	return htab->map.map_type == BPF_MAP_TYPE_HASH_OF_MAPS;
}

static __always_inline void *htab_elem_value(struct htab_elem *l, u32 key_size)
{
	return l->key + round_up(key_size, 8);
}

static __always_inline void htab_elem_set_ptr(struct htab_elem *l, u32 key_size,
					      void __percpu *pptr)
{
	*(void __percpu **)htab_elem_value(l, key_size) = pptr;
}

static __always_inline void __percpu *htab_elem_get_ptr(struct htab_elem *l,
							u32 key_size)
{
	return *(void __percpu **)htab_elem_value(l, key_size);
}

static __always_inline void *fd_htab_map_get_ptr(const struct bpf_map *map,
						 struct htab_elem *l)
{
	return *(void **)htab_elem_value(l, map->key_size);
}

static __always_inline struct htab_elem *get_htab_elem(struct bpf_htab *htab,
						       int i)
{
	return (struct htab_elem *)(htab->elems + i * (u64)htab->elem_size);
}

static __always_inline bool htab_has_extra_elems(struct bpf_htab *htab)
{
	return !htab_is_percpu(htab) && !htab_is_lru(htab) && !is_fd_htab(htab);
}

/* Called from syscall */
static __always_inline int htab_map_alloc_check(union bpf_attr *attr)
{
	bool percpu = (attr->map_type == BPF_MAP_TYPE_PERCPU_HASH ||
		       attr->map_type == BPF_MAP_TYPE_LRU_PERCPU_HASH);
	bool lru = (attr->map_type == BPF_MAP_TYPE_LRU_HASH ||
		    attr->map_type == BPF_MAP_TYPE_LRU_PERCPU_HASH);
	bool percpu_lru = (attr->map_flags & BPF_F_NO_COMMON_LRU);
	bool prealloc = !(attr->map_flags & BPF_F_NO_PREALLOC);
	bool zero_seed = (attr->map_flags & BPF_F_ZERO_SEED);
	int numa_node = bpf_map_attr_numa_node(attr);

	BUILD_BUG_ON(offsetof(struct htab_elem, fnode.next) !=
		     offsetof(struct htab_elem, hash_node.pprev));

	if (zero_seed && !capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (attr->map_flags & ~HTAB_CREATE_FLAG_MASK ||
	    !bpf_map_flags_access_ok(attr->map_flags))
		return -EINVAL;

	if (!lru && percpu_lru)
		return -EINVAL;

	if (lru && !prealloc)
		return -ENOTSUPP;

	if (numa_node != NUMA_NO_NODE && (percpu || percpu_lru))
		return -EINVAL;

	if (attr->max_entries == 0 || attr->key_size == 0 ||
	    attr->value_size == 0)
		return -EINVAL;

	if ((u64)attr->key_size + attr->value_size >= KMALLOC_MAX_SIZE -
	   sizeof(struct htab_elem))
		return -E2BIG;

	if (percpu && round_up(attr->value_size, 8) > PCPU_MIN_UNIT_SIZE)
		return -E2BIG;

	return 0;
}

static __always_inline bool is_map_full(struct bpf_htab *htab)
{
	if (htab->use_percpu_counter)
		return __percpu_counter_compare(&htab->pcount, htab->map.max_entries,
						PERCPU_COUNTER_BATCH) >= 0;
	return atomic_read(&htab->count) >= htab->map.max_entries;
}

static __always_inline void inc_elem_count(struct bpf_htab *htab)
{
	bpf_map_inc_elem_count(&htab->map);

	if (htab->use_percpu_counter)
		percpu_counter_add_batch(&htab->pcount, 1, PERCPU_COUNTER_BATCH);
	else
		atomic_inc(&htab->count);
}

static __always_inline void dec_elem_count(struct bpf_htab *htab)
{
	bpf_map_dec_elem_count(&htab->map);

	if (htab->use_percpu_counter)
		percpu_counter_add_batch(&htab->pcount, -1, PERCPU_COUNTER_BATCH);
	else
		atomic_dec(&htab->count);
}

static __always_inline int htab_map_check_update_flags(bool onallcpus,
						       u64 map_flags)
{
	if (unlikely(!onallcpus && map_flags > BPF_EXIST))
		return -EINVAL;
	if (unlikely(onallcpus && ((map_flags & BPF_F_LOCK) ||
				   (u32)map_flags > BPF_F_ALL_CPUS)))
		return -EINVAL;
	return 0;
}

static __always_inline u64 htab_map_mem_usage(const struct bpf_map *map)
{
	struct bpf_htab *htab = container_of(map, struct bpf_htab, map);
	u32 value_size = round_up(htab->map.value_size, 8);
	bool prealloc = htab_is_prealloc(htab);
	bool percpu = htab_is_percpu(htab);
	bool lru = htab_is_lru(htab);
	u64 num_entries, usage;

	usage = sizeof(struct bpf_htab) +
		sizeof(struct bucket) * htab->n_buckets;

	if (prealloc) {
		num_entries = map->max_entries;
		if (htab_has_extra_elems(htab))
			num_entries += num_possible_cpus();

		usage += htab->elem_size * num_entries;

		if (percpu)
			usage += value_size * num_possible_cpus() * num_entries;
		else if (!lru)
			usage += sizeof(struct htab_elem *) * num_possible_cpus();
	} else {
#define LLIST_NODE_SZ sizeof(struct llist_node)

		num_entries = htab->use_percpu_counter ?
					  percpu_counter_sum(&htab->pcount) :
					  atomic_read(&htab->count);
		usage += (htab->elem_size + LLIST_NODE_SZ) * num_entries;
		if (percpu) {
			usage += (LLIST_NODE_SZ + sizeof(void *)) * num_entries;
			usage += value_size * num_possible_cpus() * num_entries;
		}
	}
	return usage;
}
