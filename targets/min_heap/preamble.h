/* Typed heap storage: 8 preallocated int slots.
 * Defined here (after min_heap.c is included) so MIN_HEAP_PREALLOCATED
 * is available from linux/min_heap.h. */
MIN_HEAP_PREALLOCATED(int, bpf_int_heap, 8) __bpf_heap_storage;
/* BPF-friendly heap operations that call concrete functions directly.
 * Defined here (after min_heap.c is included) so min_heap_char is available.
 * The standard __min_heap_push/pop use function pointers (struct min_heap_callbacks)
 * which generate 'callx' instructions that the BPF verifier rejects.
 * These versions call __bpf_int_less and __bpf_int_swap directly. */
static void __bpf_heap_sift_up(int *data, size_t idx)
{
    /* Bounded loop: heap has max 8 elements, depth <= 3. Use 4 iterations. */
    int i;
    for (i = 0; i < 4 && idx > 0; i++) {
        size_t par = (idx - 1) / 2;
        if (!__bpf_int_less(data + idx, data + par, NULL))
            break;
        __bpf_int_swap(data + idx, data + par, NULL);
        idx = par;
    }
}
static void __bpf_heap_sift_down(int *data, size_t n, size_t pos)
{
    /* Bounded loop: heap has max 8 elements, depth <= 3. Use 4 iterations. */
    int i;
    for (i = 0; i < 4; i++) {
        size_t left = 2 * pos + 1;
        size_t right = 2 * pos + 2;
        size_t smallest = pos;
        if (left < n && __bpf_int_less(data + left, data + smallest, NULL))
            smallest = left;
        if (right < n && __bpf_int_less(data + right, data + smallest, NULL))
            smallest = right;
        if (smallest == pos)
            break;
        __bpf_int_swap(data + pos, data + smallest, NULL);
        pos = smallest;
    }
}
static bool __bpf_heap_push(min_heap_char *heap, const int *val)
{
    if (heap->nr >= heap->size)
        return false;
    int *data = (int *)heap->data;
    data[heap->nr] = *val;
    __bpf_heap_sift_up(data, heap->nr);
    heap->nr++;
    return true;
}
static bool __bpf_heap_pop(min_heap_char *heap)
{
    if (heap->nr == 0)
        return false;
    int *data = (int *)heap->data;
    heap->nr--;
    data[0] = data[heap->nr];
    if (heap->nr > 0)
        __bpf_heap_sift_down(data, heap->nr, 0);
    return true;
}
