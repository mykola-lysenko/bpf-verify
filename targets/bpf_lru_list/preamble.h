#define __bpf_lru_list_empty(head)     ((head)->next == (head) && (head)->prev == (head))

#define __bpf_lru_list_single(head, node)     ((head)->next == &(node)->list &&      (head)->prev == &(node)->list &&      (node)->list.prev == (head) &&      (node)->list.next == (head))

