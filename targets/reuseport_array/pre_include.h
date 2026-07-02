#include <linux/errno.h>
#define _LINUX_BPF_H 1
#define _LINUX_ERR_H
#define __SOCK_DIAG_H__
#define _SOCK_REUSEPORT_H
#define _LINUX_BTF_IDS_H
#define __rcu
#define S32_MAX 2147483647
#define U32_MAX ((u32)~0U)
#define AF_INET 2
#define AF_INET6 10
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define SOCK_STREAM 1
#define SOCK_DGRAM 2
#define BPF_ANY 0
#define BPF_NOEXIST 1
#define BPF_EXIST 2
#define BPF_F_NUMA_NODE (1U << 2)
#define NUMA_NO_NODE (-1)
#define ERR_PTR(error) ((void *)(long)(error))
#define PTR_ERR(ptr) ((long)(ptr))
#define IS_ERR(ptr) ((unsigned long)(void *)(ptr) >= (unsigned long)-4095)
#define BTF_ID_LIST_SINGLE(name, prefix, typename) static u32 name[1];
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x, v) do { (x) = (v); } while (0)
#define unlikely(x) (x)
#define struct_size(p, member, count)     (sizeof(*(p)) + sizeof(*(p)->member) * (count))
#define rcu_access_pointer(p) (p)
#define rcu_dereference(p) (p)
#define rcu_dereference_protected(p, c) (p)
#define rcu_assign_pointer(p, v) do { (p) = (v); } while (0)
#define RCU_INIT_POINTER(p, v) do { (p) = (v); } while (0)
#define SK_USER_DATA_NOCOPY 0UL
#define SK_USER_DATA_BPF 0UL
#define SK_USER_DATA_PTRMASK (~0UL)

typedef struct {
    u32 locked;
} spinlock_t;
typedef struct {
    u32 locked;
} rwlock_t;
static spinlock_t reuseport_lock;

struct sock_reuseport {
    u8 has_conns;
};
enum sock_flags {
    SOCK_RCU_FREE = 0,
};
struct sock {
    rwlock_t sk_callback_lock;
    void *sk_user_data;
    struct sock_reuseport *sk_reuseport_cb;
    u16 sk_protocol;
    u16 sk_type;
    u16 sk_family;
    unsigned long sk_flags;
    bool hashed;
    u64 cookie;
};
struct socket {
    struct sock *sk;
};
union bpf_attr {
    struct {
        u32 map_type;
        u32 key_size;
        u32 value_size;
        u32 max_entries;
        u32 map_flags;
        u32 numa_node;
    };
};
struct bpf_map {
    const struct bpf_map_ops *ops;
    u32 map_type;
    u32 key_size;
    u32 value_size;
    u32 max_entries;
    u32 map_flags;
    int numa_node;
};
struct bpf_map_ops {
    bool (*map_meta_equal)(const struct bpf_map *meta0,
                           const struct bpf_map *meta1);
    int (*map_alloc_check)(union bpf_attr *attr);
    struct bpf_map *(*map_alloc)(union bpf_attr *attr);
    void (*map_free)(struct bpf_map *map);
    void *(*map_lookup_elem)(struct bpf_map *map, void *key);
    int (*map_get_next_key)(struct bpf_map *map, void *key, void *next_key);
    long (*map_delete_elem)(struct bpf_map *map, void *key);
    u64 (*map_mem_usage)(const struct bpf_map *map);
    const u32 *map_btf_id;
};
struct __bpf_reuseport_array_4 {
    struct bpf_map map;
    struct sock *ptrs[4];
};
static struct __bpf_reuseport_array_4 __bpf_reuseport_alloc_array;
static u8 __bpf_reuseport_allocated;
static u32 __bpf_reuseport_frees;

static inline void spin_lock_bh(spinlock_t *lock)
{
    lock->locked = 1;
}
static inline void spin_unlock_bh(spinlock_t *lock)
{
    lock->locked = 0;
}
static inline void write_lock_bh(rwlock_t *lock)
{
    lock->locked = 1;
}
static inline void write_unlock_bh(rwlock_t *lock)
{
    lock->locked = 0;
}
static inline void rcu_read_lock(void)
{
}
static inline void rcu_read_unlock(void)
{
}
static inline bool sock_flag(const struct sock *sk, enum sock_flags flag)
{
    return sk->sk_flags & (1UL << flag);
}
static inline bool sk_hashed(const struct sock *sk)
{
    return sk->hashed;
}
static inline void *__locked_read_sk_user_data_with_flags(const struct sock *sk,
                                                          unsigned long flags)
{
    (void)flags;
    return sk->sk_user_data;
}
static inline u64 __sock_gen_cookie(struct sock *sk)
{
    return sk->cookie;
}
static inline struct socket *sockfd_lookup(int fd, int *err)
{
    (void)fd;
    *err = -EBADF;
    return NULL;
}
static inline void sockfd_put(struct socket *socket)
{
    (void)socket;
}
static inline int array_map_alloc_check(union bpf_attr *attr)
{
    if (attr->key_size != sizeof(u32) || !attr->max_entries ||
        attr->max_entries > 4)
        return -EINVAL;
    return 0;
}
static inline int bpf_map_attr_numa_node(const union bpf_attr *attr)
{
    return (attr->map_flags & BPF_F_NUMA_NODE) ?
           (int)attr->numa_node : NUMA_NO_NODE;
}
static inline void bpf_map_init_from_attr(struct bpf_map *map,
                                          union bpf_attr *attr)
{
    map->map_type = attr->map_type;
    map->key_size = attr->key_size;
    map->value_size = attr->value_size;
    map->max_entries = attr->max_entries;
    map->map_flags = attr->map_flags;
    map->numa_node = bpf_map_attr_numa_node(attr);
}
static inline bool bpf_map_meta_equal(const struct bpf_map *meta0,
                                      const struct bpf_map *meta1)
{
    (void)meta0;
    (void)meta1;
    return true;
}
static inline void __bpf_reuseport_zero_array(struct __bpf_reuseport_array_4 *array)
{
    array->map.ops = 0;
    array->map.map_type = 0;
    array->map.key_size = 0;
    array->map.value_size = 0;
    array->map.max_entries = 0;
    array->map.map_flags = 0;
    array->map.numa_node = 0;
    array->ptrs[0] = 0;
    array->ptrs[1] = 0;
    array->ptrs[2] = 0;
    array->ptrs[3] = 0;
}
static inline void *__bpf_reuseport_area_alloc(u64 size, int numa_node)
{
    (void)numa_node;
    if (size > sizeof(__bpf_reuseport_alloc_array) || __bpf_reuseport_allocated)
        return 0;
    __bpf_reuseport_allocated = 1;
    __bpf_reuseport_zero_array(&__bpf_reuseport_alloc_array);
    return &__bpf_reuseport_alloc_array;
}
static inline void __bpf_reuseport_area_free(void *ptr)
{
    (void)ptr;
    __bpf_reuseport_allocated = 0;
    __bpf_reuseport_frees++;
}
#define bpf_map_area_alloc(size, numa_node)     __bpf_reuseport_area_alloc((size), (numa_node))
#define bpf_map_area_free(ptr) __bpf_reuseport_area_free(ptr)
static inline void __bpf_reuseport_init_sock(struct sock *sk, u16 protocol,
                                             u16 family, u16 type,
                                             struct sock_reuseport *reuse,
                                             u64 cookie)
{
    sk->sk_callback_lock.locked = 0;
    sk->sk_user_data = 0;
    sk->sk_reuseport_cb = reuse;
    sk->sk_protocol = protocol;
    sk->sk_family = family;
    sk->sk_type = type;
    sk->sk_flags = 1UL << SOCK_RCU_FREE;
    sk->hashed = true;
    sk->cookie = cookie;
}
