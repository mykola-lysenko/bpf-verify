    /* crc7_be computes a 7-bit CRC */
    __u8 buf[4] = {{0x01, 0x02, 0x03, 0x04}};
    __u8 crc = crc7_be(0, buf, sizeof(buf));
    return (int)crc;
