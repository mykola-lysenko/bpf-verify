/* parser.c's other exported parsers (match_token/int/u64/strdup, all
 * unexercised here) reference these from other TUs; provide them so the object
 * loads. Real implementations for the string ops (small, and correctness-free
 * for our path), trivial stubs for the number/alloc parsers we never call. */
void *memcpy(void *d, const void *s, __kernel_size_t n)
{ unsigned char *dd=d; const unsigned char *ss=s; while(n--) *dd++=*ss++; return d; }
__kernel_size_t strlen(const char *s){ __kernel_size_t n=0; while(s[n]) n++; return n; }
int strncmp(const char *a, const char *b, __kernel_size_t n)
{ while(n--){ if(*a!=*b) return (int)(unsigned char)*a-(int)(unsigned char)*b; if(!*a) break; a++; b++; } return 0; }
int strcmp(const char *a, const char *b)
{ while(*a && *a==*b){ a++; b++; } return (int)(unsigned char)*a-(int)(unsigned char)*b; }
char *strchr(const char *s, int c)
{ for(;; s++){ if(*s==(char)c) return (char *)s; if(!*s) return (void *)0; } }

/* unexercised-path stubs */
unsigned long simple_strtoul(const char *cp, char **endp, unsigned int base)
{ (void)cp;(void)base; if(endp) *endp=(char *)cp; return 0; }
long simple_strtol(const char *cp, char **endp, unsigned int base)
{ (void)cp;(void)base; if(endp) *endp=(char *)cp; return 0; }
int kstrtouint(const char *s, unsigned int base, unsigned int *res)
{ (void)s;(void)base; if(res) *res=0; return -22; }
int kstrtoull(const char *s, unsigned int base, unsigned long long *res)
{ (void)s;(void)base; if(res) *res=0; return -22; }
char *kmemdup_nul(const char *s, __kernel_size_t len, gfp_t gfp)
{ (void)s;(void)len;(void)gfp; return (void *)0; }
