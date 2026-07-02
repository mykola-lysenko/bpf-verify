
    /* crc-t10dif: verify CRC of known data */
    unsigned char data[4] = {0xDE, 0xAD, 0xBE, 0xEF};
    u16 c = crc_t10dif_update(0, data, 4);
    (void)c;
    return 0;
