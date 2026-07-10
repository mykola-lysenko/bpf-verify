    /* plist: verify init/empty contract.
     *
     * C-related finding: struct plist_node contains mixed-size fields
     * (int prio at offset 0, then struct list_head fields as 64-bit pointers).
     * When plist_add() reads node->prio (32-bit) from a stack slot that was
     * written by plist_node_init() using 64-bit stores (struct initialization),
     * the BPF verifier rejects it with "invalid size of register fill".
     * This is a BPF stack-access size-consistency requirement: reads must use
     * the same width as the corresponding write.
     *
     * The harness is therefore limited to init/empty checks which only use
     * 64-bit pointer stores/loads (the list_head next/prev pointers). */
    struct plist_head head;
    plist_head_init(&head);
    /* Property: freshly initialized head is empty */
    BPF_ASSERT(plist_head_empty(&head));
    return 0;
