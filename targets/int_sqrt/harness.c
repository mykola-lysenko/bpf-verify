    /* int_sqrt: verify known concrete values.
     *
     * int_sqrt uses a shift-and-subtract loop whose iteration count depends
     * on the input value. For symbolic (map-derived) inputs the BPF verifier
     * cannot bound the loop and hits the 1,000,000-instruction limit.
     *
     * We therefore use only concrete constant inputs. The verifier inlines
     * int_sqrt and constant-folds the entire loop body for each literal,
     * producing a straight-line program with no branches. This keeps the
     * instruction count well below the limit while still exercising the
     * function across a representative set of inputs.
     *
     * Properties verified (all provable by constant-folding):
     *   int_sqrt(0)   == 0
     *   int_sqrt(1)   == 1
     *   int_sqrt(4)   == 2
     *   int_sqrt(9)   == 3
     *   int_sqrt(16)  == 4
     *   int_sqrt(100) == 10
     *   int_sqrt(255) == 15  (floor(sqrt(255)) = 15 since 15^2=225 <= 255 < 256=16^2) */
    BPF_ASSERT(int_sqrt(0)   == 0);
    BPF_ASSERT(int_sqrt(1)   == 1);
    BPF_ASSERT(int_sqrt(4)   == 2);
    BPF_ASSERT(int_sqrt(9)   == 3);
    BPF_ASSERT(int_sqrt(16)  == 4);
    BPF_ASSERT(int_sqrt(100) == 10);
    BPF_ASSERT(int_sqrt(255) == 15);
    return 0;
