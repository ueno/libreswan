/*
 * unit tests for cryptographic helper function - calculate KE and nonce
 *
 * Copyright (C) 2006 Michael C. Richardson <mcr@xelerance.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 * This code was developed with the support of IXIA communications.
 */

#include "../../../programs/pluto/hmac.c"
#include "../../../programs/pluto/crypto.c"
#include "../../../programs/pluto/ike_alg.c"
#include "../../../programs/pluto/crypt_utils.c"
#include "../../../programs/pluto/crypt_dh.c"
#include "../../../programs/pluto/ikev2_prfplus.c"

#include "crypto.h"

char *progname;

void exit_log(const char *message, ...)
{
	va_list args;
	char m[LOG_WIDTH];      /* longer messages will be truncated */

	va_start(args, message);
	vsnprintf(m, sizeof(m), message, args);
	va_end(args);

	fprintf(stderr, "FATAL ERROR: %s\n", m);
	exit(0);
}

void exit_tool(int code)
{
	exit(code);
}

/*
 * while the rest of this file is covered under the GPL, the following
 * constant values, being inputs and outputs of a mathematical formula
 * are hereby placed in the public domain, including the expression of them
 * in the form of this C code.
 *
 * I.e. please rip off my test data so that the world will be a better place.
 *
 */

/* test case 2 - DH operation */
u_int16_t tc2_oakleygroup  = OAKLEY_GROUP_MODP1536;
oakley_auth_t tc2_auth         = AUTH_ALGORITHM_HMAC_MD5;
oakley_hash_t tc2_hash         = OAKLEY_MD5;
struct encrypt_desc *tc2_encrypter = &crypto_encrypter_3des;
enum phase1_role tc2_init      = INITIATOR;

unsigned char tc2_gi[] = {
	0xff, 0xbc, 0x6a, 0x92,  0xa6, 0xb9, 0x55, 0x9b,
	0x05, 0xfa, 0x96, 0xa7,  0xa4, 0x35, 0x07, 0xb4,
	0xc1, 0xe1, 0xc0, 0x86,  0x1a, 0x58, 0x71, 0xd9,
	0xba, 0x73, 0xa1, 0x63,  0x11, 0x37, 0x88, 0xc0,
	0xde, 0xbb, 0x39, 0x79,  0xe7, 0xff, 0x0c, 0x52,
	0xb4, 0xce, 0x60, 0x50,  0xeb, 0x05, 0x36, 0x9e,
	0xa4, 0x30, 0x0d, 0x2b,  0xff, 0x3b, 0x1b, 0x29,
	0x9f, 0x3b, 0x80, 0x2c,  0xcb, 0x13, 0x31, 0x8c,
	0x2a, 0xb9, 0xe3, 0xb5,  0x62, 0x7c, 0xb4, 0xb3,
	0x5e, 0xb9, 0x39, 0x98,  0x20, 0x76, 0xb5, 0x7c,
	0x05, 0x0d, 0x7b, 0x35,  0xc3, 0xc5, 0xc7, 0xcc,
	0x8c, 0x0f, 0xea, 0xb7,  0xb6, 0x4a, 0x7d, 0x7b,
	0x6b, 0x8f, 0x6b, 0x4d,  0xab, 0xf4, 0xac, 0x40,
	0x6d, 0xd2, 0x01, 0x26,  0xb9, 0x0a, 0x98, 0xac,
	0x76, 0x6e, 0xfa, 0x37,  0xa7, 0x89, 0x0c, 0x43,
	0x94, 0xff, 0x9a, 0x77,  0x61, 0x5b, 0x58, 0xf5,
	0x2d, 0x65, 0x1b, 0xbf,  0xa5, 0x8d, 0x2a, 0x54,
	0x9a, 0xf8, 0xb0, 0x1a,  0xa4, 0xbc, 0xa3, 0xd7,
	0x62, 0x42, 0x66, 0x63,  0xb1, 0x55, 0xd4, 0xeb,
	0xda, 0x9f, 0x60, 0xa6,  0xa1, 0x35, 0x73, 0xe6,
	0xa8, 0x88, 0x13, 0x5c,  0xdc, 0x67, 0x3d, 0xd4,
	0x83, 0x02, 0x99, 0x03,  0xf3, 0xa9, 0x0e, 0xca,
	0x23, 0xe1, 0xec, 0x1e,  0x27, 0x03, 0x31, 0xb2,
	0xd0, 0x50, 0xf4, 0xf7,  0x58, 0xf4, 0x99, 0x27,
};
unsigned int tc2_gi_len = sizeof(tc2_gi);

unsigned char tc2_gr[] = {
	0xcd, 0x30, 0xdf, 0x6e,  0xc0, 0x85, 0x44, 0x12,
	0x53, 0x01, 0x80, 0xd8,  0x7e, 0x1a, 0xfb, 0xb3,
	0x26, 0x79, 0x3e, 0x99,  0x56, 0xc8, 0x6a, 0x96,
	0x25, 0x53, 0xc2, 0x77,  0xad, 0x5b, 0xab, 0x50,
	0xf8, 0x32, 0x5a, 0xd8,  0x64, 0x0b, 0x0e, 0xfe,
	0xa5, 0x1d, 0x6c, 0x83,  0x1f, 0xa1, 0x7c, 0xfb,
	0x0f, 0x2e, 0x1a, 0xf4,  0xb1, 0x66, 0xa0, 0xfe,
	0x30, 0x75, 0x12, 0xad,  0x0f, 0x81, 0xab, 0xb8,
	0xaa, 0xfb, 0x68, 0x48,  0xec, 0x10, 0xa4, 0x97,
	0x6c, 0x3d, 0xb1, 0x17,  0xec, 0xe1, 0xe6, 0x61,
	0xdb, 0xbf, 0x48, 0x0c,  0x28, 0x2e, 0x3f, 0x11,
	0x07, 0xc1, 0x86, 0x42,  0x80, 0x1e, 0xe8, 0x3f,
	0x9e, 0x4a, 0xb9, 0xab,  0x63, 0x6f, 0x23, 0x7d,
	0xaa, 0xf6, 0xa7, 0xaa,  0xd8, 0x22, 0x99, 0x3e,
	0xa4, 0x1e, 0xa3, 0x31,  0xee, 0x27, 0x82, 0x0b,
	0x93, 0xf5, 0x0b, 0x8f,  0x3f, 0x71, 0x05, 0x61,
	0xc9, 0x25, 0x70, 0x26,  0x97, 0xba, 0x6b, 0x1e,
	0x95, 0x3c, 0x21, 0xfb,  0xc9, 0xa7, 0x7d, 0x2b,
	0x5f, 0x87, 0x3c, 0xfc,  0x50, 0x99, 0xe7, 0x7d,
	0x48, 0x4c, 0xdd, 0x52,  0x66, 0x4b, 0xcf, 0x0d,
	0xbf, 0x00, 0xca, 0xfd,  0xae, 0x6d, 0xe7, 0x14,
	0x6d, 0x11, 0x35, 0xf6,  0x5d, 0x93, 0x5f, 0x60,
	0xb9, 0x73, 0x0f, 0xe0,  0x49, 0x2c, 0x2a, 0xf8,
	0xc9, 0x04, 0xf6, 0x4c,  0x59, 0x16, 0x90, 0x9d,
};
unsigned int tc2_gr_len = sizeof(tc2_gr);

unsigned char tc2_ni[] = {
	0xb5, 0xce, 0x84, 0x19,  0x09, 0x5c, 0x6e, 0x2b,
	0x6b, 0x62, 0xd3, 0x05,  0x53, 0x05, 0xb3, 0xc4,
};
unsigned int tc2_ni_len = sizeof(tc2_ni);

unsigned char tc2_nr[] = {
	0x47, 0xe9, 0xf9, 0x25,  0x8c, 0xa2, 0x38, 0x58,
	0xf6, 0x75, 0xb1, 0x66,  0xb0, 0x2c, 0xc2, 0x92,
};
unsigned int tc2_nr_len = sizeof(tc2_nr);

unsigned char tc2_icookie[] = {
	0x75, 0x46, 0xd3, 0xd6,  0xea, 0x09, 0xf7, 0xdf,
};
unsigned int tc2_icookie_len = sizeof(tc2_icookie);

unsigned char tc2_rcookie[] = {
	0x61, 0xa6, 0x78, 0x6a,  0x41, 0xea, 0x48, 0x06,
};
unsigned int tc2_rcookie_len = sizeof(tc2_rcookie);

unsigned char tc2_secret[] = {
	0x17, 0x9b, 0xb3, 0x22,  0xa6, 0x77, 0x6f, 0xbc,
	0x01, 0x4e, 0x41, 0x03,  0xf0, 0xf6, 0x2e, 0x93,
	0xfb, 0x07, 0xd0, 0x93,  0x84, 0x57, 0xe4, 0x54,
	0x1e, 0x64, 0x46, 0xa9,  0x34, 0x37, 0xc0, 0x9d,
};
unsigned int tc2_secret_len = sizeof(tc2_secret);

int main(int argc, char *argv[])
{
	struct pluto_crypto_req r;
	struct pcr_skeyid_r *skr = &r.pcr_d.dhr;
	struct pcr_skeyid_q *skq = &r.pcr_d.dhq;

	progname = argv[0];

	/* initialize list of moduli */
	init_crypto();

	skq->thespace.start = 0;
	skq->thespace.len   = sizeof(skq->space);
	skq->auth     = tc2_auth;
	skq->prf_hash = tc2_hash;
	skq->oakley_group = tc2_oakleygroup;
	skq->init = tc2_init;
	skq->keysize = tc2_encrypter->keydeflen / BITS_PER_BYTE;

#define copydatlen(field, data, len) do { \
		chunk_t tchunk;           \
		setchunk(tchunk, data, len); \
		pluto_crypto_copychunk(&skq->thespace, skq->space \
				       , &skq->field, tchunk); }   \
	while (0)

	copydatlen(ni, tc2_ni, tc2_ni_len);
	copydatlen(nr, tc2_nr, tc2_nr_len);
	copydatlen(gi, tc2_gi, tc2_gi_len);
	copydatlen(gr, tc2_gr, tc2_gr_len);
	copydatlen(secret, tc2_secret, tc2_secret_len);
	copydatlen(icookie, tc2_icookie, tc2_icookie_len);
	copydatlen(rcookie, tc2_rcookie, tc2_rcookie_len);

#define dumpdat(field) \
	libreswan_DBG_dump(#field,      \
			   wire_chunk_ptr(skq, &skq->field), \
			   skq->field.len);

	dumpdat(icookie);
	dumpdat(rcookie);
	dumpdat(ni);
	dumpdat(nr);
	dumpdat(gi);
	dumpdat(gr);
	dumpdat(secret);

	fflush(stdout);
	fflush(stderr);

	calc_dh_iv(&r);

	printf("\noutput:\n");

	{
		void *shared = wire_chunk_ptr(skr, &skr->shared);

		libreswan_DBG_dump("shared", shared, skr->shared.len);
	}

	exit(4);
}
