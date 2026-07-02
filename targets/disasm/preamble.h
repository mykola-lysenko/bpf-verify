static void disasm_count_cb(void *private_data, const char *fmt, ...)
{
    int *cnt = (int *)private_data;
    (*cnt)++;
}
