/*
 * Simple ASN.1 parser
 * Copyright (C) 2000-2004 Andreas Steffen, Zuercher Hochschule Winterthur
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <https://www.gnu.org/licenses/gpl2.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 */

#include <stdlib.h>
#include <string.h>
#include <time.h>


#include "sysdep.h"
#include "constants.h"
#include "lswlog.h"
#include "lswalloc.h"
#include "realtime.h"
#include "asn1.h"
#include "oid.h"

/*
 * If the oid is listed in the oid_names table then the corresponding
 * position in the oid_names table is returned otherwise -1 is returned
 */
int known_oid(chunk_t object)
{
	int oid = 0;

	while (object.len > 0) {
		if (oid_names[oid].octet == *object.ptr) {
			object.len--;
			object.ptr++;
			if (object.len == 0) {
				/* at end of object */
				if (oid_names[oid].down == 0)
					return oid;	/* found terminal symbol */
				else
					return OID_UNKNOWN;	/* end of object but not terminal */
			} else {
				/* object continues */
				if (oid_names[oid].down == 0) {
					return OID_UNKNOWN;	/* terminal but not end of object */
				} else {
					/* advance to next hex octet in table
					 * so we can match next octet of OID
					 */
					oid++;
				}
			}
		} else {
			if (oid_names[oid].next != 0)
				oid = oid_names[oid].next;
			else
				return OID_UNKNOWN;
		}
	}
	return OID_UNKNOWN;
}

/*
 * Decode the length in bytes of an ASN.1 object.
 * Blob is updated to reflect the tag and length have been consumed
 */

err_t unwrap_asn1_length(chunk_t *blob, size_t *length)
{
	*length = 0;

	if (blob->len == 0) {
		return "insufficient number of octets to parse ASN.1 length";
	}

	/* read first octet of length field */
	uint8_t n = *blob->ptr++;
	blob->len--;

	if ((n & 0x80) == 0) { /* single length octet */
		if (n > blob->len) {
			return "number of length octets is larger than ASN.1 object";
		}
		*length = n;
		return NULL;
	}

	/* composite length, determine number of length octets */
	n &= 0x7f;

	if (n > blob->len) {
		return "number of length octets is larger than ASN.1 object";
	}

	if (n > sizeof(*length)) {
#if 0
		dbg("number of length octets is larger than limit of %zd octets",
		    sizeof(len));
#else
		return "number of length octets is larger than sizeof(size_t)";
#endif
	}

	size_t len = 0;
	while (n-- > 0) {
		len = 256 * len + *blob->ptr++;
		blob->len--;
	}
	if (len > blob->len) {
		return "length is larger than remaining blob size";
	}

	*length = len;
	return NULL;
}

/*
 * codes ASN.1 lengths up to a size of 16'777'215 bytes
 */
void code_asn1_length(size_t length, chunk_t *code)
{
	if (length < 128) {
		code->ptr[0] = length;
		code->len = 1;
	} else if (length < 256) {
		code->ptr[0] = 0x81;
		code->ptr[1] = (uint8_t) length;
		code->len = 2;
	} else if (length < 65536) {
		code->ptr[0] = 0x82;
		code->ptr[1] = length >> 8;
		code->ptr[2] = length & 0x00ff;
		code->len = 3;
	} else {
		code->ptr[0] = 0x83;
		code->ptr[1] = length >> 16;
		code->ptr[2] = (length >> 8) & 0x00ff;
		code->ptr[3] = length & 0x0000ff;
		code->len = 4;
	}
}

/*
 * Determines if a character string is of type ASN.1 PrintableString.
 * See https://en.wikipedia.org/w/index.php?title=PrintableString
 */

bool is_asn1_printablestring(shunk_t str)
{
	/*
	 * Map ASCII character onto a printable bit.  The printable
	 * characters are:
	 *
	 * "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 '()+,-./:=?"
	 *
	 * Each byte contains a bit mask of valid characters.  The
	 * most-significant bit contains the first character's bit,
	 * and so on (so &0x80 checks the left-most character).
	 */
	static const uint8_t printable_set[256 / 8] = {
		0000u,	/* 0x00            */
		0000u,	/* 0x08            */
		0000u,	/* 0x10            */
		0000u,	/* 0x18            */
		0201u,	/* 0x20          '  (first is the real SPACE) */
		0337u,	/* 0x28 ()  +, -./ */
		0377u,	/* 0x30 01 234 567 */
		0345u,	/* 0x38 89 :   = ? */
		0177u,	/* 0x40  A BCD EFG */
		0377u,	/* 0x48 HI JKL MNO */
		0377u,	/* 0x50 PQ RST UVW */
		0340u,	/* 0x58 XY Z       */
		0177u,	/* 0x60  a bcd efg */
		0377u,	/* 0x68 hi jkl mno */
		0377u,	/* 0x70 pq rst uvw */
		0340u,	/* 0x78 xy z      */
	};

	const uint8_t *s = str.ptr;
	for (unsigned i = 0; i < str.len; i++) {
		/*
		 * Check if the bit within printable_set[] is set.
		 * Left shift the mask so that 0x80 checks the bit.
		 */
		uint8_t u = s[i];
		uint8_t ps = printable_set[u / 8];
		uint8_t pb = ps << (u % 8);
		/* printf("checking '%c' %o %x\n", u, ps, pb); */
		if (!(pb & 0x80)) {
			return false;
		}
	}
	return true;
}

/*
 * tests if a blob contains a valid ASN.1 set or sequence
 */
err_t asn1_ok(chunk_t blob)
{
	if (blob.len < 1) {
		return "cert blob is empty: not binary ASN.1";
	}

	switch (blob.ptr[0]) {
	case ASN1_SEQUENCE:
	case ASN1_SET:
		break;	/* looks OK */
	default:
		return "  cert blob content is not binary ASN.1";
	}

	size_t len;
	err_t e = unwrap_asn1_length(&blob, &len);
	if (e != NULL) {
		return e;
	}

	return NULL;
}

static err_t unwrap_asn1_type(chunk_t *container, enum asn1_type ty)
{
	const uint8_t *b = hunk_get(container, sizeof(uint8_t));
	if (b == NULL) {
		return "missing ASN.1 type";
	}

	if (*b != ty) {
		return "unexpected ASN.1 type";
	}

	return NULL;
}

err_t unwrap_asn1_container(enum asn1_type ty, chunk_t *container, chunk_t *contents)
{
	err_t e;

	e = unwrap_asn1_type(container, ty);
	if (e != NULL) {
		return e;
	}

	size_t sz;
	e = unwrap_asn1_length(container, &sz);
	if (e != NULL) {
		return e;
	}

	if (sz > container->len) {
		return "ASN1 length larger than space";
	}

	contents->ptr = container->ptr;
	contents->len = sz;
	container->ptr += sz;
	container->len -= sz;
	return NULL;
}
