/* snprintf is variadic; BPF does not support variadic calls.
 * The harness body does not call oid_registry functions that use snprintf,
 * but the compiler still emits a reference. Stub it out. */
#define snprintf(buf, size, fmt, ...) (0)
