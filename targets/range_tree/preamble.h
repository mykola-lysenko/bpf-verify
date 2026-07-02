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
