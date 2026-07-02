/* Block inftrees.h and provide all its contents with internal_linkage on
 * zlib_inflate_table. codetype is an enum (not unsigned char). */
#define INFTREES_H
typedef struct {
    unsigned char op;
    unsigned char bits;
    unsigned short val;
} code;
#define ENOUGH 2048
#define MAXD 592
typedef enum { CODES, LENS, DISTS } codetype;
__attribute__((internal_linkage))
int zlib_inflate_table(codetype type, unsigned short *lens, unsigned codes,
    code **table, unsigned *bits, unsigned short *work);
