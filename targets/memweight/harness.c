    /* memweight: compile-only test -- the BPF verifier rejects memweight()
     * because it casts a pointer to unsigned long for alignment checking:
     *   for (; bytes > 0 && ((unsigned long)bitmap) % sizeof(long); ...)
     * The BPF verifier tracks stack pointers as typed values and rejects
     * bitwise AND operations on them ("R3 bitwise operator &= on pointer
     * prohibited").
     *
     * C-related finding: lib/memweight.c performs pointer-to-integer casts
     * to check memory alignment ((unsigned long)bitmap & (sizeof(long)-1)).
     * This pattern is idiomatic C but incompatible with the BPF verifier's
     * strict pointer type tracking. The verifier cannot prove that the
     * result of a pointer-to-integer cast is safe to use as a plain integer.
     * Even though the BPF stack is always 8-byte aligned (making the loop
     * body unreachable), the verifier rejects the cast before evaluating
     * reachability. */
    return 0;
