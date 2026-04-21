/* SPDX-License-Identifier: GPL-2.0 */
/* BPF shim: linux/union_find.h
 * Provides a bounded uf_find() to replace the unbounded while loop
 * in the original implementation. The BPF verifier rejects unbounded
 * loops that follow pointer chains through stack memory.
 */
#ifndef __LINUX_UNION_FIND_H
#define __LINUX_UNION_FIND_H

struct uf_node {
struct uf_node *parent;
unsigned int rank;
};

/* This macro is used for static initialization of a union-find node. */
#define UF_INIT_NODE(node){.parent = &node, .rank = 0}

/**
 * uf_node_init - Initialize a union-find node
 */
static inline void uf_node_init(struct uf_node *node)
{
node->parent = node;
node->rank = 0;
}

/* Declare uf_find and uf_union so the source file (union_find.c) can define them. */
struct uf_node *uf_find(struct uf_node *node);
void uf_union(struct uf_node *node1, struct uf_node *node2);

/* __bpf_uf_find - Bounded find with path compression for BPF verifier.
 * The original uf_find() uses an unbounded while loop that the BPF verifier
 * rejects as a potential infinite loop. This version uses a bounded for loop
 * (max 64 iterations) that the verifier can prove terminates. */
static inline struct uf_node *__bpf_uf_find(struct uf_node *node)
{
	int i;
	for (i = 0; i < 64; i++) {
		if (node->parent == node)
			break;
		node->parent = node->parent->parent;
		node = node->parent;
	}
	return node;
}

/* __bpf_uf_union - Bounded union by rank for BPF verifier. */
static inline void __bpf_uf_union(struct uf_node *node1, struct uf_node *node2)
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

#endif /* __LINUX_UNION_FIND_H */
