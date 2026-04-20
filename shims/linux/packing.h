/* BPF shim: linux/packing.h
 * The real packing.h declares several functions with >5 arguments, which the
 * BPF backend rejects for non-static functions. We redeclare them with
 * __attribute__((internal_linkage)) so the BPF backend accepts them.
 * All struct definitions and macros are included from the real header.
 */
#ifndef _LINUX_PACKING_H
#define _LINUX_PACKING_H

/* Include the real packing.h content except the function declarations */
#include <linux/array_size.h>
#include <linux/bitops.h>
#include <linux/build_bug.h>
#include <linux/minmax.h>
#include <linux/stddef.h>
#include <linux/types.h>

#define GEN_PACKED_FIELD_STRUCT(__type) \
	struct packed_field_ ## __type { \
		__type startbit; \
		__type endbit; \
		__type offset; \
		__type size; \
	}

GEN_PACKED_FIELD_STRUCT(u8);
GEN_PACKED_FIELD_STRUCT(u16);

#define PACKED_FIELD(start, end, struct_name, struct_field) \
{ \
	(start), \
	(end), \
	offsetof(struct_name, struct_field), \
	sizeof_field(struct_name, struct_field), \
}

/* QUIRK_* flags for packing/unpacking */
#define QUIRK_MSB_ON_THE_RIGHT	BIT(0)
#define QUIRK_LITTLE_ENDIAN	BIT(1)
#define QUIRK_LSW32_IS_FIRST	BIT(2)

enum packing_op {
	PACK,
	UNPACK,
};

/* Declare >5-arg functions with internal_linkage so BPF backend accepts them */
__attribute__((internal_linkage))
int packing(void *pbuf, u64 *uval, int startbit, int endbit, size_t pbuflen,
	    enum packing_op op, u8 quirks);

__attribute__((internal_linkage))
int pack(void *pbuf, u64 uval, size_t startbit, size_t endbit, size_t pbuflen,
	 u8 quirks);

__attribute__((internal_linkage))
int unpack(const void *pbuf, u64 *uval, size_t startbit, size_t endbit,
	   size_t pbuflen, u8 quirks);

__attribute__((internal_linkage))
void pack_fields_u8(void *pbuf, size_t pbuflen, const void *ustruct,
		    const struct packed_field_u8 *fields, size_t num_fields,
		    u8 quirks);

__attribute__((internal_linkage))
void pack_fields_u16(void *pbuf, size_t pbuflen, const void *ustruct,
		     const struct packed_field_u16 *fields, size_t num_fields,
		     u8 quirks);

__attribute__((internal_linkage))
void unpack_fields_u8(const void *pbuf, size_t pbuflen, void *ustruct,
		      const struct packed_field_u8 *fields, size_t num_fields,
		      u8 quirks);

__attribute__((internal_linkage))
void unpack_fields_u16(const void *pbuf, size_t pbuflen, void *ustruct,
		       const struct packed_field_u16 *fields, size_t num_fields,
		       u8 quirks);

#endif /* _LINUX_PACKING_H */
