// SPDX-License-Identifier: GPL-2.0-only
/* BPF shim: kernel/bpf/verifier.c predicate helpers.
 *
 * The real verifier pulls in most BPF subsystems. Keep this shim scoped to
 * small verifier-local predicates that can be proved without building a full
 * verifier environment.
 */

#include "bpf_shim_common.h"

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

#define BPF_KEEP_SCALAR(x) asm volatile("" : "+r"(x))

#ifndef EPERM
#define EPERM 1
#endif
#ifndef EACCES
#define EACCES 13
#endif

#define MAX_BPF_FUNC_REG_ARGS 5
#define BPF_REG_0 0
#define BPF_REG_1 1
#define BPF_REG_2 2
#define BPF_REG_3 3
#define BPF_REG_4 4
#define BPF_REG_5 5

#define BPF_BASE_TYPE_BITS 8
#define BPF_BASE_TYPE_MASK ((1U << BPF_BASE_TYPE_BITS) - 1)

enum bpf_type_flag {
	PTR_MAYBE_NULL		= BIT(0 + BPF_BASE_TYPE_BITS),
	MEM_RDONLY		= BIT(1 + BPF_BASE_TYPE_BITS),
	MEM_RINGBUF		= BIT(2 + BPF_BASE_TYPE_BITS),
	MEM_USER		= BIT(3 + BPF_BASE_TYPE_BITS),
	MEM_PERCPU		= BIT(4 + BPF_BASE_TYPE_BITS),
	OBJ_RELEASE		= BIT(5 + BPF_BASE_TYPE_BITS),
	PTR_UNTRUSTED		= BIT(6 + BPF_BASE_TYPE_BITS),
	MEM_UNINIT		= BIT(7 + BPF_BASE_TYPE_BITS),
	DYNPTR_TYPE_LOCAL	= BIT(8 + BPF_BASE_TYPE_BITS),
	DYNPTR_TYPE_RINGBUF	= BIT(9 + BPF_BASE_TYPE_BITS),
	MEM_FIXED_SIZE		= BIT(10 + BPF_BASE_TYPE_BITS),
	MEM_ALLOC		= BIT(11 + BPF_BASE_TYPE_BITS),
	PTR_TRUSTED		= BIT(12 + BPF_BASE_TYPE_BITS),
	MEM_RCU			= BIT(13 + BPF_BASE_TYPE_BITS),
	NON_OWN_REF		= BIT(14 + BPF_BASE_TYPE_BITS),
	DYNPTR_TYPE_SKB		= BIT(15 + BPF_BASE_TYPE_BITS),
	DYNPTR_TYPE_XDP		= BIT(16 + BPF_BASE_TYPE_BITS),
	MEM_ALIGNED		= BIT(17 + BPF_BASE_TYPE_BITS),
	MEM_WRITE		= BIT(18 + BPF_BASE_TYPE_BITS),
	DYNPTR_TYPE_SKB_META	= BIT(19 + BPF_BASE_TYPE_BITS),
	DYNPTR_TYPE_FILE	= BIT(20 + BPF_BASE_TYPE_BITS),
	__BPF_TYPE_FLAG_MAX,
	__BPF_TYPE_LAST_FLAG	= __BPF_TYPE_FLAG_MAX - 1,
};

#define DYNPTR_TYPE_FLAG_MASK	(DYNPTR_TYPE_LOCAL | DYNPTR_TYPE_RINGBUF | \
				 DYNPTR_TYPE_SKB | DYNPTR_TYPE_XDP | \
				 DYNPTR_TYPE_SKB_META | DYNPTR_TYPE_FILE)
#define BPF_TYPE_LIMIT		(__BPF_TYPE_LAST_FLAG | (__BPF_TYPE_LAST_FLAG - 1))
#define BPF_REG_TRUSTED_MODIFIERS (MEM_ALLOC | PTR_TRUSTED | NON_OWN_REF)

enum bpf_arg_type {
	ARG_DONTCARE = 0,
	ARG_CONST_MAP_PTR,
	ARG_PTR_TO_MAP_KEY,
	ARG_PTR_TO_MAP_VALUE,
	ARG_PTR_TO_MEM,
	ARG_PTR_TO_ARENA,
	ARG_CONST_SIZE,
	ARG_CONST_SIZE_OR_ZERO,
	ARG_PTR_TO_CTX,
	ARG_ANYTHING,
	ARG_PTR_TO_SPIN_LOCK,
	ARG_PTR_TO_SOCK_COMMON,
	ARG_PTR_TO_SOCKET,
	ARG_PTR_TO_BTF_ID,
	ARG_PTR_TO_RINGBUF_MEM,
	ARG_CONST_ALLOC_SIZE_OR_ZERO,
	ARG_PTR_TO_BTF_ID_SOCK_COMMON,
	ARG_PTR_TO_PERCPU_BTF_ID,
	ARG_PTR_TO_FUNC,
	ARG_PTR_TO_STACK,
	ARG_PTR_TO_CONST_STR,
	ARG_PTR_TO_TIMER,
	ARG_KPTR_XCHG_DEST,
	ARG_PTR_TO_DYNPTR,
	__BPF_ARG_TYPE_MAX,

	ARG_PTR_TO_MAP_VALUE_OR_NULL = PTR_MAYBE_NULL | ARG_PTR_TO_MAP_VALUE,
	ARG_PTR_TO_MEM_OR_NULL = PTR_MAYBE_NULL | ARG_PTR_TO_MEM,
	ARG_PTR_TO_CTX_OR_NULL = PTR_MAYBE_NULL | ARG_PTR_TO_CTX,
	ARG_PTR_TO_SOCKET_OR_NULL = PTR_MAYBE_NULL | ARG_PTR_TO_SOCKET,
	ARG_PTR_TO_STACK_OR_NULL = PTR_MAYBE_NULL | ARG_PTR_TO_STACK,
	ARG_PTR_TO_BTF_ID_OR_NULL = PTR_MAYBE_NULL | ARG_PTR_TO_BTF_ID,
	ARG_PTR_TO_UNINIT_MEM = MEM_UNINIT | MEM_WRITE | ARG_PTR_TO_MEM,
	ARG_PTR_TO_FIXED_SIZE_MEM = MEM_FIXED_SIZE | ARG_PTR_TO_MEM,
	__BPF_ARG_TYPE_LIMIT = BPF_TYPE_LIMIT,
};

enum bpf_return_type {
	RET_INTEGER,
	RET_VOID,
	RET_PTR_TO_MAP_VALUE,
};

enum bpf_reg_type {
	NOT_INIT = 0,
	SCALAR_VALUE,
	PTR_TO_CTX,
	CONST_PTR_TO_MAP,
	PTR_TO_MAP_VALUE,
	PTR_TO_MAP_KEY,
	PTR_TO_STACK,
	PTR_TO_PACKET_META,
	PTR_TO_PACKET,
	PTR_TO_PACKET_END,
	PTR_TO_FLOW_KEYS,
	PTR_TO_SOCKET,
	PTR_TO_SOCK_COMMON,
	PTR_TO_TCP_SOCK,
	PTR_TO_TP_BUFFER,
	PTR_TO_XDP_SOCK,
	PTR_TO_BTF_ID,
	PTR_TO_MEM,
	PTR_TO_ARENA,
	PTR_TO_BUF,
	PTR_TO_FUNC,
	PTR_TO_INSN,
	CONST_PTR_TO_DYNPTR,
	__BPF_REG_TYPE_MAX,

	PTR_TO_MAP_VALUE_OR_NULL = PTR_MAYBE_NULL | PTR_TO_MAP_VALUE,
	PTR_TO_SOCKET_OR_NULL = PTR_MAYBE_NULL | PTR_TO_SOCKET,
	PTR_TO_SOCK_COMMON_OR_NULL = PTR_MAYBE_NULL | PTR_TO_SOCK_COMMON,
	PTR_TO_TCP_SOCK_OR_NULL = PTR_MAYBE_NULL | PTR_TO_TCP_SOCK,
	PTR_TO_BTF_ID_OR_NULL = PTR_MAYBE_NULL | PTR_TO_BTF_ID,
	__BPF_REG_TYPE_LIMIT = BPF_TYPE_LIMIT,
};

enum bpf_map_type {
	BPF_MAP_TYPE_UNSPEC,
	BPF_MAP_TYPE_HASH,
	BPF_MAP_TYPE_ARRAY,
	BPF_MAP_TYPE_SOCKMAP,
	BPF_MAP_TYPE_SOCKHASH,
};

enum bpf_func_id {
	BPF_FUNC_unspec,
	BPF_FUNC_map_lookup_elem,
	BPF_FUNC_sk_lookup_tcp,
	BPF_FUNC_sk_lookup_udp,
	BPF_FUNC_skc_lookup_tcp,
	BPF_FUNC_ringbuf_reserve,
	BPF_FUNC_kptr_xchg,
	BPF_FUNC_tcp_sock,
	BPF_FUNC_sk_fullsock,
	BPF_FUNC_skc_to_tcp_sock,
	BPF_FUNC_skc_to_tcp6_sock,
	BPF_FUNC_skc_to_udp6_sock,
	BPF_FUNC_skc_to_mptcp_sock,
	BPF_FUNC_skc_to_tcp_timewait_sock,
	BPF_FUNC_skc_to_tcp_request_sock,
	BPF_FUNC_for_each_map_elem,
	BPF_FUNC_find_vma,
	BPF_FUNC_loop,
	BPF_FUNC_user_ringbuf_drain,
	BPF_FUNC_timer_set_callback,
};

enum bpf_dynptr_type {
	BPF_DYNPTR_TYPE_INVALID,
	BPF_DYNPTR_TYPE_LOCAL,
	BPF_DYNPTR_TYPE_RINGBUF,
	BPF_DYNPTR_TYPE_SKB,
	BPF_DYNPTR_TYPE_XDP,
	BPF_DYNPTR_TYPE_SKB_META,
	BPF_DYNPTR_TYPE_FILE,
};

struct btf;
struct bpf_prog;
struct bpf_verifier_env {
	int dummy;
};

struct bpf_map {
	enum bpf_map_type map_type;
};

struct tnum {
	u64 value;
	u64 mask;
};

struct bpf_reg_state {
	enum bpf_reg_type type;
	union {
		struct bpf_map *map_ptr;
		int range;
		struct {
			struct btf *btf;
			u32 btf_id;
		};
		struct {
			enum bpf_dynptr_type type;
			bool first_slot;
		} dynptr;
	};
	struct tnum var_off;
	u32 id;
};

struct bpf_func_state {
	int allocated_stack;
};

struct bpf_func_proto {
	u64 (*func)(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5);
	bool gpl_only;
	bool pkt_access;
	bool might_sleep;
	bool allow_fastcall;
	enum bpf_return_type ret_type;
	union {
		struct {
			enum bpf_arg_type arg1_type;
			enum bpf_arg_type arg2_type;
			enum bpf_arg_type arg3_type;
			enum bpf_arg_type arg4_type;
			enum bpf_arg_type arg5_type;
		};
		enum bpf_arg_type arg_type[5];
	};
	union {
		struct {
			u32 *arg1_btf_id;
			u32 *arg2_btf_id;
			u32 *arg3_btf_id;
			u32 *arg4_btf_id;
			u32 *arg5_btf_id;
		};
		u32 *arg_btf_id[5];
		struct {
			size_t arg1_size;
			size_t arg2_size;
			size_t arg3_size;
			size_t arg4_size;
			size_t arg5_size;
		};
		size_t arg_size[5];
	};
	int *ret_btf_id;
	bool (*allowed)(const struct bpf_prog *prog);
};

struct bpf_call_arg_meta {
	u8 release_regno;
};

#define BPF_PTR_POISON ((u32 *)1UL)

typedef struct argno {
	int argno;
} argno_t;

static __always_inline struct tnum tnum_const(u64 value)
{
	return (struct tnum){ .value = value, .mask = 0 };
}

static __always_inline struct tnum tnum_subreg(struct tnum tnum)
{
	return (struct tnum){
		.value = (u32)tnum.value,
		.mask = (u32)tnum.mask,
	};
}

static __always_inline bool tnum_is_const(struct tnum tnum)
{
	return tnum.mask == 0;
}

static __always_inline bool tnum_subreg_is_const(struct tnum tnum)
{
	return tnum_subreg(tnum).mask == 0;
}

static __always_inline bool tnum_equals_const(struct tnum tnum, u64 value)
{
	return tnum_is_const(tnum) && tnum.value == value;
}

static __always_inline u32 base_type(u32 type)
{
	return type & BPF_BASE_TYPE_MASK;
}

static __always_inline u32 type_flag(u32 type)
{
	return type & ~BPF_BASE_TYPE_MASK;
}

static __always_inline bool type_may_be_null(u32 type)
{
	return type & PTR_MAYBE_NULL;
}

static __always_inline bool bpf_type_has_unsafe_modifiers(u32 type)
{
	return type_flag(type) & ~BPF_REG_TRUSTED_MODIFIERS;
}

static __always_inline bool reg_is_referenced(struct bpf_verifier_env *env,
					      const struct bpf_reg_state *reg)
{
	(void)env;
	return reg->id != 0;
}

static __always_inline bool is_trusted_reg(struct bpf_verifier_env *env,
					   const struct bpf_reg_state *reg)
{
	if (reg_is_referenced(env, reg))
		return true;

	return type_flag(reg->type) & BPF_REG_TRUSTED_MODIFIERS &&
	       !bpf_type_has_unsafe_modifiers(reg->type);
}

static __always_inline bool type_is_pkt_pointer(enum bpf_reg_type type)
{
	type = base_type(type);
	return type == PTR_TO_PACKET ||
	       type == PTR_TO_PACKET_META;
}

static __always_inline argno_t argno_from_reg(u32 regno)
{
	return (argno_t){ .argno = regno };
}

static __always_inline argno_t argno_from_arg(u32 arg)
{
	return (argno_t){ .argno = -arg };
}

static __always_inline int reg_from_argno(argno_t a)
{
	if (a.argno >= 0)
		return a.argno;
	if (a.argno >= -MAX_BPF_FUNC_REG_ARGS)
		return -a.argno;
	return -1;
}

static __always_inline int arg_from_argno(argno_t a)
{
	if (a.argno < 0)
		return -a.argno;
	return -1;
}

static __always_inline int arg_idx_from_argno(argno_t a)
{
	return arg_from_argno(a) - 1;
}

static __always_inline bool reg_not_null(struct bpf_verifier_env *env,
					 const struct bpf_reg_state *reg)
{
	enum bpf_reg_type type;

	type = reg->type;
	if (type_may_be_null(type))
		return false;

	type = base_type(type);
	return type == PTR_TO_SOCKET ||
		type == PTR_TO_TCP_SOCK ||
		type == PTR_TO_MAP_VALUE ||
		type == PTR_TO_MAP_KEY ||
		type == PTR_TO_SOCK_COMMON ||
		(type == PTR_TO_BTF_ID && is_trusted_reg(env, reg)) ||
		(type == PTR_TO_MEM && !(reg->type & PTR_UNTRUSTED)) ||
		type == CONST_PTR_TO_MAP;
}

static __always_inline bool type_is_rdonly_mem(u32 type)
{
	return type & MEM_RDONLY;
}

static __always_inline bool is_acquire_function(enum bpf_func_id func_id,
						const struct bpf_map *map)
{
	enum bpf_map_type map_type = map ? map->map_type : BPF_MAP_TYPE_UNSPEC;

	if (func_id == BPF_FUNC_sk_lookup_tcp ||
	    func_id == BPF_FUNC_sk_lookup_udp ||
	    func_id == BPF_FUNC_skc_lookup_tcp ||
	    func_id == BPF_FUNC_ringbuf_reserve ||
	    func_id == BPF_FUNC_kptr_xchg)
		return true;

	if (func_id == BPF_FUNC_map_lookup_elem &&
	    (map_type == BPF_MAP_TYPE_SOCKMAP ||
	     map_type == BPF_MAP_TYPE_SOCKHASH))
		return true;

	return false;
}

static __always_inline bool is_ptr_cast_function(enum bpf_func_id func_id)
{
	return func_id == BPF_FUNC_tcp_sock ||
		func_id == BPF_FUNC_sk_fullsock ||
		func_id == BPF_FUNC_skc_to_tcp_sock ||
		func_id == BPF_FUNC_skc_to_tcp6_sock ||
		func_id == BPF_FUNC_skc_to_udp6_sock ||
		func_id == BPF_FUNC_skc_to_mptcp_sock ||
		func_id == BPF_FUNC_skc_to_tcp_timewait_sock ||
		func_id == BPF_FUNC_skc_to_tcp_request_sock;
}

static __always_inline bool is_sync_callback_calling_function(enum bpf_func_id func_id)
{
	return func_id == BPF_FUNC_for_each_map_elem ||
	       func_id == BPF_FUNC_find_vma ||
	       func_id == BPF_FUNC_loop ||
	       func_id == BPF_FUNC_user_ringbuf_drain;
}

static __always_inline bool is_async_callback_calling_function(enum bpf_func_id func_id)
{
	return func_id == BPF_FUNC_timer_set_callback;
}

static __always_inline bool is_callback_calling_function(enum bpf_func_id func_id)
{
	return is_sync_callback_calling_function(func_id) ||
	       is_async_callback_calling_function(func_id);
}

static __always_inline bool is_spi_bounds_valid(struct bpf_func_state *state,
						int spi, int nr_slots)
{
	int allocated_slots = state->allocated_stack / 8;

	return spi - nr_slots + 1 >= 0 && spi < allocated_slots;
}

static __always_inline enum bpf_dynptr_type arg_to_dynptr_type(enum bpf_arg_type arg_type)
{
	switch (arg_type & DYNPTR_TYPE_FLAG_MASK) {
	case DYNPTR_TYPE_LOCAL:
		return BPF_DYNPTR_TYPE_LOCAL;
	case DYNPTR_TYPE_RINGBUF:
		return BPF_DYNPTR_TYPE_RINGBUF;
	case DYNPTR_TYPE_SKB:
		return BPF_DYNPTR_TYPE_SKB;
	case DYNPTR_TYPE_XDP:
		return BPF_DYNPTR_TYPE_XDP;
	case DYNPTR_TYPE_SKB_META:
		return BPF_DYNPTR_TYPE_SKB_META;
	case DYNPTR_TYPE_FILE:
		return BPF_DYNPTR_TYPE_FILE;
	default:
		return BPF_DYNPTR_TYPE_INVALID;
	}
}

static __always_inline enum bpf_type_flag get_dynptr_type_flag(enum bpf_dynptr_type type)
{
	switch (type) {
	case BPF_DYNPTR_TYPE_LOCAL:
		return DYNPTR_TYPE_LOCAL;
	case BPF_DYNPTR_TYPE_RINGBUF:
		return DYNPTR_TYPE_RINGBUF;
	case BPF_DYNPTR_TYPE_SKB:
		return DYNPTR_TYPE_SKB;
	case BPF_DYNPTR_TYPE_XDP:
		return DYNPTR_TYPE_XDP;
	case BPF_DYNPTR_TYPE_SKB_META:
		return DYNPTR_TYPE_SKB_META;
	case BPF_DYNPTR_TYPE_FILE:
		return DYNPTR_TYPE_FILE;
	default:
		return 0;
	}
}

static __always_inline bool dynptr_type_referenced(enum bpf_dynptr_type type)
{
	return type == BPF_DYNPTR_TYPE_RINGBUF || type == BPF_DYNPTR_TYPE_FILE;
}

static __always_inline bool error_recoverable_with_nospec(int err)
{
	return err == -EPERM || err == -EACCES || err == -EINVAL;
}

static __always_inline bool reg_is_pkt_pointer(const struct bpf_reg_state *reg)
{
	return type_is_pkt_pointer(reg->type);
}

static __always_inline bool reg_is_pkt_pointer_any(const struct bpf_reg_state *reg)
{
	return reg_is_pkt_pointer(reg) ||
	       reg->type == PTR_TO_PACKET_END;
}

static __always_inline bool reg_is_dynptr_slice_pkt(const struct bpf_reg_state *reg)
{
	return base_type(reg->type) == PTR_TO_MEM &&
	       (reg->type &
		(DYNPTR_TYPE_SKB | DYNPTR_TYPE_XDP | DYNPTR_TYPE_SKB_META));
}

static __always_inline bool reg_is_init_pkt_pointer(const struct bpf_reg_state *reg,
						    enum bpf_reg_type which)
{
	return reg->type == which &&
	       reg->id == 0 &&
	       tnum_equals_const(reg->var_off, 0);
}

static __always_inline bool is_spillable_regtype(enum bpf_reg_type type)
{
	switch (base_type(type)) {
	case PTR_TO_MAP_VALUE:
	case PTR_TO_STACK:
	case PTR_TO_CTX:
	case PTR_TO_PACKET:
	case PTR_TO_PACKET_META:
	case PTR_TO_PACKET_END:
	case PTR_TO_FLOW_KEYS:
	case CONST_PTR_TO_MAP:
	case PTR_TO_SOCKET:
	case PTR_TO_SOCK_COMMON:
	case PTR_TO_TCP_SOCK:
	case PTR_TO_XDP_SOCK:
	case PTR_TO_BTF_ID:
	case PTR_TO_BUF:
	case PTR_TO_MEM:
	case PTR_TO_FUNC:
	case PTR_TO_MAP_KEY:
	case PTR_TO_ARENA:
		return true;
	default:
		return false;
	}
}

static __always_inline bool is_reg_const(struct bpf_reg_state *reg, bool subreg32)
{
	return reg->type == SCALAR_VALUE &&
	       tnum_is_const(subreg32 ? tnum_subreg(reg->var_off) : reg->var_off);
}

static __always_inline u64 reg_const_value(struct bpf_reg_state *reg, bool subreg32)
{
	return subreg32 ? tnum_subreg(reg->var_off).value : reg->var_off.value;
}

static __always_inline bool __is_pointer_value(bool allow_ptr_leaks,
					       const struct bpf_reg_state *reg)
{
	if (allow_ptr_leaks)
		return false;

	return reg->type != SCALAR_VALUE;
}

static __always_inline bool arg_type_is_mem_size(enum bpf_arg_type type)
{
	return type == ARG_CONST_SIZE ||
	       type == ARG_CONST_SIZE_OR_ZERO;
}

static __always_inline bool arg_type_is_raw_mem(enum bpf_arg_type type)
{
	return base_type(type) == ARG_PTR_TO_MEM &&
	       type & MEM_UNINIT;
}

static __always_inline bool arg_type_is_release(enum bpf_arg_type type)
{
	return type & OBJ_RELEASE;
}

static __always_inline bool arg_type_is_dynptr(enum bpf_arg_type type)
{
	return base_type(type) == ARG_PTR_TO_DYNPTR;
}

static __always_inline bool check_raw_mode_ok(const struct bpf_func_proto *fn)
{
	int count = 0;

	if (arg_type_is_raw_mem(fn->arg1_type))
		count++;
	if (arg_type_is_raw_mem(fn->arg2_type))
		count++;
	if (arg_type_is_raw_mem(fn->arg3_type))
		count++;
	if (arg_type_is_raw_mem(fn->arg4_type))
		count++;
	if (arg_type_is_raw_mem(fn->arg5_type))
		count++;

	return count <= 1;
}

static __always_inline bool check_args_pair_invalid(const struct bpf_func_proto *fn,
						    int arg)
{
	bool is_fixed = fn->arg_type[arg] & MEM_FIXED_SIZE;
	bool has_size = fn->arg_size[arg] != 0;
	bool is_next_size = false;

	if (arg + 1 < ARRAY_SIZE(fn->arg_type))
		is_next_size = arg_type_is_mem_size(fn->arg_type[arg + 1]);

	if (base_type(fn->arg_type[arg]) != ARG_PTR_TO_MEM)
		return is_next_size;

	return has_size == is_next_size || is_next_size == is_fixed;
}

static __always_inline bool check_arg_pair_ok(const struct bpf_func_proto *fn)
{
	if (arg_type_is_mem_size(fn->arg1_type) ||
	    check_args_pair_invalid(fn, 0) ||
	    check_args_pair_invalid(fn, 1) ||
	    check_args_pair_invalid(fn, 2) ||
	    check_args_pair_invalid(fn, 3) ||
	    check_args_pair_invalid(fn, 4))
		return false;

	return true;
}

static __always_inline bool check_btf_id_ok(const struct bpf_func_proto *fn)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(fn->arg_type); i++) {
		if (base_type(fn->arg_type[i]) == ARG_PTR_TO_BTF_ID)
			return !!fn->arg_btf_id[i];
		if (base_type(fn->arg_type[i]) == ARG_PTR_TO_SPIN_LOCK)
			return fn->arg_btf_id[i] == BPF_PTR_POISON;
		if (base_type(fn->arg_type[i]) != ARG_PTR_TO_BTF_ID && fn->arg_btf_id[i] &&
		    (base_type(fn->arg_type[i]) != ARG_PTR_TO_MEM ||
		     !(fn->arg_type[i] & MEM_FIXED_SIZE)))
			return false;
	}

	return true;
}

static __always_inline bool check_mem_arg_rw_flag_ok(const struct bpf_func_proto *fn)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(fn->arg_type); i++) {
		enum bpf_arg_type arg_type = fn->arg_type[i];

		if (base_type(arg_type) != ARG_PTR_TO_MEM)
			continue;
		if (!(arg_type & (MEM_WRITE | MEM_RDONLY)))
			return false;
	}

	return true;
}

static __always_inline bool check_proto_release_reg(const struct bpf_func_proto *fn,
						    struct bpf_call_arg_meta *meta)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(fn->arg_type); i++) {
		enum bpf_arg_type arg_type = fn->arg_type[i];

		if (arg_type_is_release(arg_type)) {
			if (meta->release_regno)
				return false;
			meta->release_regno = i + 1;
		}
	}

	return true;
}

static __always_inline int check_func_proto(const struct bpf_func_proto *fn,
					    struct bpf_call_arg_meta *meta)
{
	return check_raw_mode_ok(fn) &&
	       check_arg_pair_ok(fn) &&
	       check_mem_arg_rw_flag_ok(fn) &&
	       check_proto_release_reg(fn, meta) &&
	       check_btf_id_ok(fn) ? 0 : -EINVAL;
}
