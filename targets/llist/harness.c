    /* llist: assert add/del_first contract:
     * After adding one node, del_first must return that exact node,
     * and the list must be empty afterwards. */
    struct llist_head head;
    struct llist_node node;
    init_llist_head(&head);
    /* Property: list is empty initially */
    BPF_ASSERT(llist_empty(&head));
    llist_add(&node, &head);
    /* Property: list is non-empty after add */
    BPF_ASSERT(!llist_empty(&head));
    struct llist_node *first = llist_del_first(&head);
    /* Property: del_first returns the node we added */
    BPF_ASSERT(first == &node);
    /* Property: list is empty again after del_first */
    BPF_ASSERT(llist_empty(&head));
    return 0;
