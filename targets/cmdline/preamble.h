#pragma clang attribute pop
static int __bpf_cmdline_digit(unsigned char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

__attribute__((always_inline)) unsigned long long __bpf_cmdline_simple_strtoull(const char *cp,
                                                                                char **endp,
                                                                                unsigned int base)
{
    const char *p = cp;
    unsigned long long result = 0;

    if (!base) {
        base = 10;
        if (p[0] == '0') {
            base = 8;
            p++;
            if (p[0] == 'x' || p[0] == 'X') {
                base = 16;
                p++;
            }
        }
    }

    for (int i = 0; i < 32; i++) {
        int digit = __bpf_cmdline_digit(*p);

        if (digit < 0 || digit >= base)
            break;
        result = result * base + digit;
        p++;
    }

    if (endp)
        *endp = (char *)p;
    return result;
}

__attribute__((always_inline)) long __bpf_cmdline_simple_strtol(const char *cp,
                                                                char **endp,
                                                                unsigned int base)
{
    if (*cp == '-')
        return -(long)__bpf_cmdline_simple_strtoull(cp + 1, endp, base);
    return (long)__bpf_cmdline_simple_strtoull(cp, endp, base);
}

__kernel_size_t __bpf_cmdline_strlen(const char *s)
{
    __kernel_size_t n = 0;

    for (int i = 0; i < 64; i++) {
        if (!s[i])
            break;
        n++;
    }

    return n;
}

int __bpf_cmdline_strncmp(const char *s1, const char *s2, __kernel_size_t n)
{
    for (int i = 0; i < 64; i++) {
        unsigned char c1, c2;

        if ((__kernel_size_t)i >= n)
            break;
        c1 = s1[i];
        c2 = s2[i];
        if (c1 != c2)
            return c1 - c2;
        if (!c1)
            break;
    }

    return 0;
}

char *__bpf_cmdline_skip_spaces(const char *str)
{
    const char *p = str;

    for (int i = 0; i < 64; i++) {
        if (*p != ' ' && *p != '\t' && *p != '\n' &&
            *p != '\r' && *p != '\f' && *p != '\v')
            break;
        p++;
    }

    return (char *)p;
}
