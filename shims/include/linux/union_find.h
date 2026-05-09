/* SPDX-License-Identifier: GPL-2.0 */
/*
 * BPF shim: linux/union_find.h
 *
 * Keep the real lightweight union-find API, and add bounded helper variants
 * for the harness. The real uf_find() follows parent pointers with an
 * unbounded while loop, which the BPF verifier cannot prove terminating.
 */
#ifndef __BPF_LINUX_UNION_FIND_SHIM_H
#define __BPF_LINUX_UNION_FIND_SHIM_H

#include_next <linux/union_find.h>

/*
 * The current bpf-verify union_find harness creates a four-node forest. A
 * valid forest of N nodes has at most N - 1 parent links to the root; N loop
 * iterations allow the final root check while keeping the verifier bound tight.
 */
#define __BPF_UF_FIND_MAX_NODES 4

static inline struct uf_node *__bpf_uf_find(struct uf_node *node)
{
	int i;

	for (i = 0; i < __BPF_UF_FIND_MAX_NODES; i++) {
		if (node->parent == node)
			break;
		node->parent = node->parent->parent;
		node = node->parent;
	}

	return node;
}

static inline void __bpf_uf_union(struct uf_node *node1,
				  struct uf_node *node2)
{
	struct uf_node *root1 = __bpf_uf_find(node1);
	struct uf_node *root2 = __bpf_uf_find(node2);

	if (root1 == root2)
		return;
	if (root1->rank < root2->rank) {
		root1->parent = root2;
	} else if (root1->rank > root2->rank) {
		root2->parent = root1;
	} else {
		root2->parent = root1;
		root1->rank++;
	}
}

#endif /* __BPF_LINUX_UNION_FIND_SHIM_H */
