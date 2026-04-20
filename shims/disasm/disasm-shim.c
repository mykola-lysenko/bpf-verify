/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
 * Self-contained shim for kernel/bpf/disasm.c
 *
 * Avoids uapi/linux/bpf.h (which pulls in linux/types.h -> uapi/linux/types.h
 * -> linux/posix_types.h -> asm/percpu.h which has x86 inline assembly).
 *
 * Instead, we define struct bpf_insn, all BPF opcode constants, and the
 * __BPF_FUNC_MAPPER macro directly.  The harness template already provides
 * linux/types.h (__u8, __u16, __u32, __u64, __s16, __s32, bool).
 *
 * snprintf, strcpy, BUILD_BUG_ON, and __stringify are stubbed in
 * EXTRA_PRE_INCLUDE in pipeline.py (inserted before this shim).
 */

/* ── Guard uapi/linux/bpf.h and uapi/linux/bpf_common.h so they are not
 *    re-included by disasm.c's own #include chain ─────────────────────────── */
#define _UAPI__LINUX_BPF_H__
#define _UAPI__LINUX_BPF_COMMON_H__

/* ── BPF instruction classes (from uapi/linux/bpf_common.h) ─────────────── */
#define BPF_CLASS(code) ((code) & 0x07)
#define BPF_LD          0x00
#define BPF_LDX         0x01
#define BPF_ST          0x02
#define BPF_STX         0x03
#define BPF_ALU         0x04
#define BPF_JMP         0x05
#define BPF_RET         0x06
#define BPF_MISC        0x07

/* ld/ldx fields */
#define BPF_SIZE(code)  ((code) & 0x18)
#define BPF_W           0x00
#define BPF_H           0x08
#define BPF_B           0x10
#define BPF_MODE(code)  ((code) & 0xe0)
#define BPF_IMM         0x00
#define BPF_ABS         0x20
#define BPF_IND         0x40
#define BPF_MEM         0x60
#define BPF_LEN         0x80
#define BPF_MSH         0xa0

/* alu/jmp fields */
#define BPF_OP(code)    ((code) & 0xf0)
#define BPF_ADD         0x00
#define BPF_SUB         0x10
#define BPF_MUL         0x20
#define BPF_DIV         0x30
#define BPF_OR          0x40
#define BPF_AND         0x50
#define BPF_LSH         0x60
#define BPF_RSH         0x70
#define BPF_NEG         0x80
#define BPF_MOD         0x90
#define BPF_XOR         0xa0
#define BPF_JA          0x00
#define BPF_JEQ         0x10
#define BPF_JGT         0x20
#define BPF_JGE         0x30
#define BPF_JSET        0x40
#define BPF_SRC(code)   ((code) & 0x08)
#define BPF_K           0x00
#define BPF_X           0x08
#define BPF_MAXINSNS    4096

/* ── eBPF-specific constants (from uapi/linux/bpf.h) ────────────────────── */
#define BPF_JMP32       0x06
#define BPF_ALU64       0x07
#define BPF_DW          0x18
#define BPF_ATOMIC      0xc0
#define BPF_XADD        0xc0
#define BPF_MOV         0xb0
#define BPF_ARSH        0xc0
#define BPF_END         0xd0
#define BPF_TO_LE       0x00
#define BPF_TO_BE       0x08
#define BPF_FROM_LE     BPF_TO_LE
#define BPF_FROM_BE     BPF_TO_BE
#define BPF_JNE         0x50
#define BPF_JLT         0xa0
#define BPF_JLE         0xb0
#define BPF_JSGT        0x60
#define BPF_JSGE        0x70
#define BPF_JSLT        0xc0
#define BPF_JSLE        0xd0
#define BPF_CALL        0x80
#define BPF_EXIT        0x90
#define BPF_FETCH       0x01
#define BPF_XCHG        (0xe0 | BPF_FETCH)
#define BPF_CMPXCHG     (0xf0 | BPF_FETCH)

/* Special insn->off values for address-space cast and per-CPU address resolution
 * (from uapi/linux/bpf.h enum bpf_addr_space_cast, used in disasm.c) */
#define BPF_ADDR_SPACE_CAST 1
#define BPF_ADDR_PERCPU     2

/* Atomic operation modifiers for load-acquire and store-release
 * (from uapi/linux/bpf.h, used in disasm.c:271) */
#define BPF_LOAD_ACQ  0x100
#define BPF_STORE_REL 0x110

/* Load with sign extension (from uapi/linux/bpf.h, used in disasm.c:298) */
#define BPF_MEMSX     0x80

/* Conditional pseudo-jump opcode (from uapi/linux/bpf.h, used in disasm.c:364) */
#define BPF_JCOND     0xe0

/* BPF_MAY_GOTO src_reg value for conditional jumps (from uapi/linux/bpf.h) */
#define BPF_MAY_GOTO  0

/* Pseudo source register values */
#define BPF_PSEUDO_MAP_FD           1
#define BPF_PSEUDO_MAP_IDX          5
#define BPF_PSEUDO_MAP_VALUE        2
#define BPF_PSEUDO_MAP_IDX_VALUE    6
#define BPF_PSEUDO_BTF_ID           3
#define BPF_PSEUDO_FUNC             4
#define BPF_PSEUDO_CALL             1
#define BPF_PSEUDO_KFUNC_CALL       2

/* ── struct bpf_insn ─────────────────────────────────────────────────────── */
struct bpf_insn {
	__u8	code;
	__u8	dst_reg:4;
	__u8	src_reg:4;
	__s16	off;
	__s32	imm;
};

/* ── __BPF_FUNC_MAPPER and enum bpf_func_id ─────────────────────────────── */
#define __BPF_FUNC_MAPPER(FN)		\
	FN(unspec),			\
	FN(map_lookup_elem),		\
	FN(map_update_elem),		\
	FN(map_delete_elem),		\
	FN(probe_read),			\
	FN(ktime_get_ns),		\
	FN(trace_printk),		\
	FN(get_prandom_u32),		\
	FN(get_smp_processor_id),	\
	FN(skb_store_bytes),		\
	FN(l3_csum_replace),		\
	FN(l4_csum_replace),		\
	FN(tail_call),			\
	FN(clone_redirect),		\
	FN(get_current_pid_tgid),	\
	FN(get_current_uid_gid),	\
	FN(get_current_comm),		\
	FN(get_cgroup_classid),		\
	FN(skb_vlan_push),		\
	FN(skb_vlan_pop),		\
	FN(skb_get_tunnel_key),		\
	FN(skb_set_tunnel_key),		\
	FN(perf_event_read),		\
	FN(redirect),			\
	FN(get_route_realm),		\
	FN(perf_event_output),		\
	FN(skb_load_bytes),		\
	FN(get_stackid),		\
	FN(csum_diff),			\
	FN(skb_get_tunnel_opt),		\
	FN(skb_set_tunnel_opt),		\
	FN(skb_change_proto),		\
	FN(skb_change_type),		\
	FN(skb_under_cgroup),		\
	FN(get_hash_recalc),		\
	FN(get_current_task),		\
	FN(probe_write_user),		\
	FN(current_task_under_cgroup),	\
	FN(skb_change_tail),		\
	FN(skb_pull_data),		\
	FN(csum_update),		\
	FN(set_hash_invalid),		\
	FN(get_numa_node_id),		\
	FN(skb_change_head),		\
	FN(xdp_adjust_head),		\
	FN(probe_read_str),		\
	FN(get_socket_cookie),		\
	FN(get_socket_uid),		\
	FN(set_hash),			\
	FN(setsockopt),			\
	FN(skb_adjust_room),		\
	FN(redirect_map),		\
	FN(sk_redirect_map),		\
	FN(sock_map_update),		\
	FN(xdp_adjust_meta),		\
	FN(perf_event_read_value),	\
	FN(perf_prog_read_value),	\
	FN(getsockopt),			\
	FN(override_return),		\
	FN(sock_ops_cb_flags_set),	\
	FN(msg_redirect_map),		\
	FN(msg_apply_bytes),		\
	FN(msg_cork_bytes),		\
	FN(msg_pull_data),		\
	FN(bind),			\
	FN(xdp_adjust_tail),		\
	FN(skb_get_xfrm_state),		\
	FN(get_stack),			\
	FN(skb_load_bytes_relative),	\
	FN(fib_lookup),			\
	FN(sock_hash_update),		\
	FN(msg_redirect_hash),		\
	FN(sk_redirect_hash),		\
	FN(lwt_push_encap),		\
	FN(lwt_seg6_store_bytes),	\
	FN(lwt_seg6_adjust_srh),	\
	FN(lwt_seg6_action),		\
	FN(rc_repeat),			\
	FN(rc_keydown),			\
	FN(skb_cgroup_id),		\
	FN(get_current_cgroup_id),	\
	FN(get_local_storage),		\
	FN(sk_select_reuseport),	\
	FN(skb_ancestor_cgroup_id),	\
	FN(sk_lookup_tcp),		\
	FN(sk_lookup_udp),		\
	FN(sk_release),			\
	FN(map_push_elem),		\
	FN(map_pop_elem),		\
	FN(map_peek_elem),		\
	FN(msg_push_data),		\
	FN(msg_pop_data),		\
	FN(rc_pointer_rel),		\
	FN(spin_lock),			\
	FN(spin_unlock),		\
	FN(sk_fullsock),		\
	FN(tcp_sock),			\
	FN(skb_ecn_set_ce),		\
	FN(get_listener_sock),		\
	FN(skc_lookup_tcp),		\
	FN(tcp_check_syncookie),	\
	FN(sysctl_get_name),		\
	FN(sysctl_get_current_value),	\
	FN(sysctl_get_new_value),	\
	FN(sysctl_set_new_value),	\
	FN(strtol),			\
	FN(strtoul),			\
	FN(sk_storage_get),		\
	FN(sk_storage_delete),		\
	FN(send_signal),		\
	FN(tcp_gen_syncookie),		\
	FN(skb_output),			\
	FN(probe_read_user),		\
	FN(probe_read_kernel),		\
	FN(probe_read_user_str),	\
	FN(probe_read_kernel_str),	\
	FN(tcp_send_ack),		\
	FN(send_signal_thread),		\
	FN(jiffies64),			\
	FN(read_branch_records),	\
	FN(get_ns_current_pid_tgid),	\
	FN(xdp_output),			\
	FN(get_netns_cookie),		\
	FN(get_current_ancestor_cgroup_id),	\
	FN(sk_assign),			\
	FN(ktime_get_boot_ns),		\
	FN(seq_printf),			\
	FN(seq_write),			\
	FN(sk_cgroup_id),		\
	FN(sk_ancestor_cgroup_id),	\
	FN(ringbuf_output),		\
	FN(ringbuf_reserve),		\
	FN(ringbuf_submit),		\
	FN(ringbuf_discard),		\
	FN(ringbuf_query),		\
	FN(csum_level),			\
	FN(skc_to_tcp6_sock),		\
	FN(skc_to_tcp_sock),		\
	FN(skc_to_tcp_timewait_sock),	\
	FN(skc_to_tcp_request_sock),	\
	FN(skc_to_udp6_sock),		\
	FN(get_task_stack),		\
	FN(load_hdr_opt),		\
	FN(store_hdr_opt),		\
	FN(reserve_hdr_opt),		\
	FN(inode_storage_get),		\
	FN(inode_storage_delete),	\
	FN(d_path),			\
	FN(copy_from_user),		\
	FN(snprintf_btf),		\
	FN(seq_printf_btf),		\
	FN(skb_cgroup_classid),		\
	FN(redirect_neigh),		\
	FN(per_cpu_ptr),		\
	FN(this_cpu_ptr),		\
	FN(redirect_peer),		\
	FN(task_storage_get),		\
	FN(task_storage_delete),	\
	FN(get_current_task_btf),	\
	FN(bprm_opts_set),		\
	FN(ktime_get_coarse_ns),	\
	FN(ima_inode_hash),		\
	FN(sock_from_file),		\
	FN(check_mtu),			\
	FN(for_each_map_elem),		\
	FN(snprintf),			\
	FN(sys_bpf),			\
	FN(btf_find_by_name_kind),	\
	FN(sys_close),			\
	FN(timer_init),			\
	FN(timer_set_callback),		\
	FN(timer_start),		\
	FN(timer_cancel),		\
	FN(get_func_ip),		\
	FN(get_attach_cookie),		\
	FN(task_pt_regs),		\
	FN(get_branch_snapshot),	\
	FN(trace_vprintk),		\
	FN(skc_to_unix_sock),		\
	FN(kallsyms_lookup_name),	\
	FN(find_vma),			\
	FN(loop),			\
	FN(strncmp),			\
	FN(get_func_arg),		\
	FN(get_func_ret),		\
	FN(get_func_arg_cnt),		\
	FN(get_retval),			\
	FN(set_retval),			\
	FN(xdp_get_buff_len),		\
	FN(xdp_load_bytes),		\
	FN(xdp_store_bytes),		\
	FN(copy_from_user_task),	\
	FN(skb_set_tstamp),		\
	FN(ima_file_hash),		\
	FN(kptr_xchg),			\
	FN(map_lookup_percpu_elem),	\
	FN(skc_to_mptcp_sock),		\
	FN(dynptr_from_mem),		\
	FN(ringbuf_reserve_dynptr),	\
	FN(ringbuf_submit_dynptr),	\
	FN(ringbuf_discard_dynptr),	\
	FN(dynptr_read),		\
	FN(dynptr_write),		\
	FN(dynptr_data),		\
	FN(tcp_raw_gen_syncookie_ipv4),	\
	FN(tcp_raw_gen_syncookie_ipv6),	\
	FN(tcp_raw_check_syncookie_ipv4),	\
	FN(tcp_raw_check_syncookie_ipv6),	\
	FN(ktime_get_tai_ns),		\
	FN(user_ringbuf_drain),		\
	/* */

#define __BPF_ENUM_FN(x) BPF_FUNC_ ## x
enum bpf_func_id {
	__BPF_FUNC_MAPPER(__BPF_ENUM_FN)
	__BPF_FUNC_MAX_ID,
};
#undef __BPF_ENUM_FN

/* ── Inline disasm.h replacement (avoids linux/kernel.h __printf) ─────────── */
#ifndef __BPF_DISASM_H__
#define __BPF_DISASM_H__

typedef void (*bpf_insn_print_t)(void *private_data, const char *fmt, ...);

typedef const char *(*bpf_insn_revmap_call_t)(void *private_data,
					      const struct bpf_insn *insn);
typedef const char *(*bpf_insn_print_imm_t)(void *private_data,
					    const struct bpf_insn *insn,
					    __u64 full_imm);

struct bpf_insn_cbs {
	bpf_insn_print_t	cb_print;
	bpf_insn_revmap_call_t	cb_call;
	bpf_insn_print_imm_t	cb_imm;
	void			*private_data;
};

extern const char *const bpf_alu_string[16];
extern const char *const bpf_class_string[8];
const char *func_id_name(int id);
void print_bpf_insn(const struct bpf_insn_cbs *cbs,
		    const struct bpf_insn *insn,
		    bool allow_ptr_leaks);
#endif /* __BPF_DISASM_H__ */

/* ── Now include the actual disasm.c source ───────────────────────────────── */
#include "/home/ubuntu/bpf-next-0aa637869/kernel/bpf/disasm.c"
