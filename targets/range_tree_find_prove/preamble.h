static struct range_node __bpf_range_tree_node0;
static u32 __bpf_range_tree_used;

static void __bpf_range_tree_zero_node(struct range_node *rn)
{
    rn->rn_rbnode.__rb_parent_color = 0;
    rn->rn_rbnode.rb_right = 0;
    rn->rn_rbnode.rb_left = 0;
    rn->rb_range_size.__rb_parent_color = 0;
    rn->rb_range_size.rb_right = 0;
    rn->rb_range_size.rb_left = 0;
    rn->rn_start = 0;
    rn->rn_last = 0;
    rn->__rn_subtree_last = 0;
}

static void *__bpf_range_tree_alloc(size_t size, unsigned int flags, int node)
{
    (void)flags;
    (void)node;
    if (size != sizeof(struct range_node))
        return 0;
    if (__bpf_range_tree_used)
        return 0;
    __bpf_range_tree_used = 1;
    __bpf_range_tree_zero_node(&__bpf_range_tree_node0);
    return &__bpf_range_tree_node0;
}

static void __bpf_range_tree_free(const void *ptr)
{
    (void)ptr;
}

static __attribute__((always_inline)) s64
__bpf_range_tree_find_three(struct range_tree *rt, struct range_node *root,
                            struct range_node *left, struct range_node *right,
                            u32 len)
{
    s64 best = -ENOENT;

    if (rt->range_size_root.rb_root.rb_node != &root->rb_range_size)
        return -EFAULT;
    if (root->rb_range_size.rb_left != &left->rb_range_size)
        return -EFAULT;
    if (root->rb_range_size.rb_right != &right->rb_range_size)
        return -EFAULT;

    if (len <= rn_size(root)) {
        best = root->rn_start;
        if (len <= rn_size(right))
            best = right->rn_start;
    } else if (len <= rn_size(left)) {
        best = left->rn_start;
    }

    return best;
}
