/*
 *  NIST SP800-38D compliant GCM implementation
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/*
 * Copyright (c) 2024, Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 * - Original code modifications: refactoring and API simplifications
 */

/*
 * AES-GCM test vectors from:
 * http://csrc.nist.gov/groups/STM/cavp/documents/mac/gcmtestvectors.zip
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../gcm.h"

#define MAX_TESTS   4

static const int key_index[MAX_TESTS] = { 0, 0, 1, 1 };

static const uint8_t key[MAX_TESTS][32] = {
	{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
	  0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
	  0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
	  0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08 },
};

static const size_t iv_len[MAX_TESTS] = { 12, 12, 12, 12 };

static const int iv_index[MAX_TESTS] = { 0, 0, 1, 1 };

static const uint8_t iv[MAX_TESTS][64] = {
	{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	  0x00, 0x00, 0x00, 0x00 },
	{ 0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
	  0xde, 0xca, 0xf8, 0x88 },
};

static const size_t aad_len[MAX_TESTS] = { 0, 0, 0, 20 };

static const int aad_index[MAX_TESTS] = { 0, 0, 0, 1 };

static const uint8_t aad[MAX_TESTS][64] = {
	{ 0x00 },
	{ 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
	  0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
	  0xab, 0xad, 0xda, 0xd2 },
};

static const size_t pt_len[MAX_TESTS] = { 0, 16, 64, 60 };

static const int pt_index[MAX_TESTS] = { 0, 0, 1, 1 };

static const uint8_t pt[MAX_TESTS][64] = {
	{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5,
	  0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
	  0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
	  0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
	  0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
	  0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
	  0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
	  0xba, 0x63, 0x7b, 0x39, 0x1a, 0xaf, 0xd2, 0x55 },
};

static const uint8_t ct[MAX_TESTS * 3][64] = {
	{ 0x00 },
	{ 0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92,
	  0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78 },
	{ 0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24,
	  0x4b, 0x72, 0x21, 0xb7, 0x84, 0xd0, 0xd4, 0x9c,
	  0xe3, 0xaa, 0x21, 0x2f, 0x2c, 0x02, 0xa4, 0xe0,
	  0x35, 0xc1, 0x7e, 0x23, 0x29, 0xac, 0xa1, 0x2e,
	  0x21, 0xd5, 0x14, 0xb2, 0x54, 0x66, 0x93, 0x1c,
	  0x7d, 0x8f, 0x6a, 0x5a, 0xac, 0x84, 0xaa, 0x05,
	  0x1b, 0xa3, 0x0b, 0x39, 0x6a, 0x0a, 0xac, 0x97,
	  0x3d, 0x58, 0xe0, 0x91, 0x47, 0x3f, 0x59, 0x85 },
	{ 0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24,
	  0x4b, 0x72, 0x21, 0xb7, 0x84, 0xd0, 0xd4, 0x9c,
	  0xe3, 0xaa, 0x21, 0x2f, 0x2c, 0x02, 0xa4, 0xe0,
	  0x35, 0xc1, 0x7e, 0x23, 0x29, 0xac, 0xa1, 0x2e,
	  0x21, 0xd5, 0x14, 0xb2, 0x54, 0x66, 0x93, 0x1c,
	  0x7d, 0x8f, 0x6a, 0x5a, 0xac, 0x84, 0xaa, 0x05,
	  0x1b, 0xa3, 0x0b, 0x39, 0x6a, 0x0a, 0xac, 0x97,
	  0x3d, 0x58, 0xe0, 0x91 },
	{ 0x00 },
	{ 0x98, 0xe7, 0x24, 0x7c, 0x07, 0xf0, 0xfe, 0x41,
	  0x1c, 0x26, 0x7e, 0x43, 0x84, 0xb0, 0xf6, 0x00 },
	{ 0x39, 0x80, 0xca, 0x0b, 0x3c, 0x00, 0xe8, 0x41,
	  0xeb, 0x06, 0xfa, 0xc4, 0x87, 0x2a, 0x27, 0x57,
	  0x85, 0x9e, 0x1c, 0xea, 0xa6, 0xef, 0xd9, 0x84,
	  0x62, 0x85, 0x93, 0xb4, 0x0c, 0xa1, 0xe1, 0x9c,
	  0x7d, 0x77, 0x3d, 0x00, 0xc1, 0x44, 0xc5, 0x25,
	  0xac, 0x61, 0x9d, 0x18, 0xc8, 0x4a, 0x3f, 0x47,
	  0x18, 0xe2, 0x44, 0x8b, 0x2f, 0xe3, 0x24, 0xd9,
	  0xcc, 0xda, 0x27, 0x10, 0xac, 0xad, 0xe2, 0x56 },
	{ 0x39, 0x80, 0xca, 0x0b, 0x3c, 0x00, 0xe8, 0x41,
	  0xeb, 0x06, 0xfa, 0xc4, 0x87, 0x2a, 0x27, 0x57,
	  0x85, 0x9e, 0x1c, 0xea, 0xa6, 0xef, 0xd9, 0x84,
	  0x62, 0x85, 0x93, 0xb4, 0x0c, 0xa1, 0xe1, 0x9c,
	  0x7d, 0x77, 0x3d, 0x00, 0xc1, 0x44, 0xc5, 0x25,
	  0xac, 0x61, 0x9d, 0x18, 0xc8, 0x4a, 0x3f, 0x47,
	  0x18, 0xe2, 0x44, 0x8b, 0x2f, 0xe3, 0x24, 0xd9,
	  0xcc, 0xda, 0x27, 0x10 },
	{ 0x00 },
	{ 0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e,
	  0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3, 0x9d, 0x18 },
	{ 0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07,
	  0xf4, 0x7f, 0x37, 0xa3, 0x2a, 0x84, 0x42, 0x7d,
	  0x64, 0x3a, 0x8c, 0xdc, 0xbf, 0xe5, 0xc0, 0xc9,
	  0x75, 0x98, 0xa2, 0xbd, 0x25, 0x55, 0xd1, 0xaa,
	  0x8c, 0xb0, 0x8e, 0x48, 0x59, 0x0d, 0xbb, 0x3d,
	  0xa7, 0xb0, 0x8b, 0x10, 0x56, 0x82, 0x88, 0x38,
	  0xc5, 0xf6, 0x1e, 0x63, 0x93, 0xba, 0x7a, 0x0a,
	  0xbc, 0xc9, 0xf6, 0x62, 0x89, 0x80, 0x15, 0xad },
	{ 0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07,
	  0xf4, 0x7f, 0x37, 0xa3, 0x2a, 0x84, 0x42, 0x7d,
	  0x64, 0x3a, 0x8c, 0xdc, 0xbf, 0xe5, 0xc0, 0xc9,
	  0x75, 0x98, 0xa2, 0xbd, 0x25, 0x55, 0xd1, 0xaa,
	  0x8c, 0xb0, 0x8e, 0x48, 0x59, 0x0d, 0xbb, 0x3d,
	  0xa7, 0xb0, 0x8b, 0x10, 0x56, 0x82, 0x88, 0x38,
	  0xc5, 0xf6, 0x1e, 0x63, 0x93, 0xba, 0x7a, 0x0a,
	  0xbc, 0xc9, 0xf6, 0x62 },
};

static const uint8_t tag[MAX_TESTS * 3][16] = {
	{ 0x58, 0xe2, 0xfc, 0xce, 0xfa, 0x7e, 0x30, 0x61,
	  0x36, 0x7f, 0x1d, 0x57, 0xa4, 0xe7, 0x45, 0x5a },
	{ 0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd,
	  0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57, 0xbd, 0xdf },
	{ 0x4d, 0x5c, 0x2a, 0xf3, 0x27, 0xcd, 0x64, 0xa6,
	  0x2c, 0xf3, 0x5a, 0xbd, 0x2b, 0xa6, 0xfa, 0xb4 },
	{ 0x5b, 0xc9, 0x4f, 0xbc, 0x32, 0x21, 0xa5, 0xdb,
	  0x94, 0xfa, 0xe9, 0x5a, 0xe7, 0x12, 0x1a, 0x47 },
	{ 0xcd, 0x33, 0xb2, 0x8a, 0xc7, 0x73, 0xf7, 0x4b,
	  0xa0, 0x0e, 0xd1, 0xf3, 0x12, 0x57, 0x24, 0x35 },
	{ 0x2f, 0xf5, 0x8d, 0x80, 0x03, 0x39, 0x27, 0xab,
	  0x8e, 0xf4, 0xd4, 0x58, 0x75, 0x14, 0xf0, 0xfb },
	{ 0x99, 0x24, 0xa7, 0xc8, 0x58, 0x73, 0x36, 0xbf,
	  0xb1, 0x18, 0x02, 0x4d, 0xb8, 0x67, 0x4a, 0x14 },
	{ 0x25, 0x19, 0x49, 0x8e, 0x80, 0xf1, 0x47, 0x8f,
	  0x37, 0xba, 0x55, 0xbd, 0x6d, 0x27, 0x61, 0x8c },
	{ 0x53, 0x0f, 0x8a, 0xfb, 0xc7, 0x45, 0x36, 0xb9,
	  0xa9, 0x63, 0xb4, 0xf1, 0xc4, 0xcb, 0x73, 0x8b },
	{ 0xd0, 0xd1, 0xc8, 0xa7, 0x99, 0x99, 0x6b, 0xf0,
	  0x26, 0x5b, 0x98, 0xb5, 0xd4, 0x8a, 0xb9, 0x19 },
	{ 0xb0, 0x94, 0xda, 0xc5, 0xd9, 0x34, 0x71, 0xbd,
	  0xec, 0x1a, 0x50, 0x22, 0x70, 0xe3, 0xcc, 0x6c },
	{ 0x76, 0xfc, 0x6e, 0xce, 0x0f, 0x4e, 0x17, 0x68,
	  0xcd, 0xdf, 0x88, 0x53, 0xbb, 0x2d, 0x55, 0x1b },
};

void gcm_test(int inplace, int key_len, int j, int i)
{
	struct gcm_context ctx;
	uint8_t buf[64];
	uint8_t tag_buf[16];
	int ret;

	gcm_init(&ctx);

	printf("(inplace=%d) AES-GCM-%3d #%d (%s): ",
	       inplace, key_len, i, "enc");

	gcm_setkey(&ctx, key[key_index[i]], key_len);

	if (inplace) {
		memcpy(buf, pt[pt_index[i]], pt_len[i]);
		ret = gcm_crypt_and_tag(&ctx, GCM_ENCRYPT, pt_len[i],
					iv[iv_index[i]], iv_len[i],
					aad[aad_index[i]], aad_len[i],
					buf, buf, 16, tag_buf);
	} else {
		ret = gcm_crypt_and_tag(&ctx, GCM_ENCRYPT, pt_len[i],
					iv[iv_index[i]], iv_len[i],
					aad[aad_index[i]], aad_len[i],
					pt[pt_index[i]], buf, 16, tag_buf);
	}

	if ((ret != 0) ||
	    (memcmp(buf, ct[j * MAX_TESTS + i], pt_len[i]) != 0) ||
	    (memcmp(tag_buf, tag[j * MAX_TESTS + i], 16) != 0)) {
		printf("failed\n");
		exit(1);
	}

	gcm_free(&ctx);

	printf("passed\n");

	printf("AES-GCM-%3d #%d (%s): ", key_len, i, "dec");

	gcm_setkey(&ctx, key[key_index[i]], key_len);

	if (inplace) {
		memcpy(buf, ct[j * MAX_TESTS + i], pt_len[i]);
		ret = gcm_crypt_and_tag(&ctx, GCM_DECRYPT, pt_len[i],
					iv[iv_index[i]], iv_len[i],
					aad[aad_index[i]], aad_len[i],
					buf, buf, 16, tag_buf);
	} else {
		ret = gcm_crypt_and_tag(&ctx, GCM_DECRYPT, pt_len[i],
					iv[iv_index[i]], iv_len[i],
					aad[aad_index[i]], aad_len[i],
					ct[j * MAX_TESTS + i], buf, 16, tag_buf);
	}

	if ((ret != 0) ||
	    (memcmp(buf, pt[pt_index[i]], pt_len[i]) != 0) ||
	    (memcmp(tag_buf, tag[j * MAX_TESTS + i], 16) != 0)) {
		printf("failed\n");
		exit(1);
	}

	gcm_free(&ctx);

	printf("passed\n");

	printf("AES-GCM-%3d #%d split (%s): ", key_len, i, "enc");

	gcm_setkey(&ctx, key[key_index[i]], key_len);

	ret = gcm_start(&ctx, GCM_ENCRYPT, iv[iv_index[i]], iv_len[i],
			aad[aad_index[i]], aad_len[i]);
	if (ret != 0) {
		printf("failed\n");
		exit(1);
	}

	if (pt_len[i] > 32) {
		size_t rest_len = (pt_len[i] - 32);

		if (inplace) {
			memcpy(buf, pt[pt_index[i]], 32);
			ret = gcm_update(&ctx, 0, 32, buf, buf);
		} else {
			ret = gcm_update(&ctx, 0, 32, pt[pt_index[i]], buf);
		}

		if (ret != 0) {
			printf("failed\n");
			exit(1);
		}

		if (inplace) {
			memcpy((buf + 32), (pt[pt_index[i]] + 32), 32);
			ret = gcm_update(&ctx, 32, rest_len,
					 (buf + 32), (buf + 32));
		} else {
			ret = gcm_update(&ctx, 32, rest_len,
					 (pt[pt_index[i]] + 32), (buf + 32));
		}

		if (ret != 0) {
			printf("failed\n");
			exit(1);
		}
	} else {
		if (inplace) {
			memcpy(buf, pt[pt_index[i]], pt_len[i]);
			ret = gcm_update(&ctx, 0, pt_len[i], buf, buf);
		} else {
			ret = gcm_update(&ctx, 0, pt_len[i], pt[pt_index[i]], buf);
		}

		if (ret != 0) {
			printf("failed\n");
			exit(1);
		}
	}

	ret = gcm_finish(&ctx, pt_len[i], aad_len[i], tag_buf, 16);
	if ((ret != 0) ||
	    (memcmp(buf, ct[j * MAX_TESTS + i], pt_len[i]) != 0) ||
	    (memcmp(tag_buf, tag[j * MAX_TESTS + i], 16) != 0)) {
		printf("failed\n");
		exit(1);
	}

	gcm_free(&ctx);

	printf("passed\n");

	printf("AES-GCM-%3d #%d split (%s): ", key_len, i, "dec");

	gcm_setkey(&ctx, key[key_index[i]], key_len);

	ret = gcm_start(&ctx, GCM_DECRYPT, iv[iv_index[i]], iv_len[i],
			aad[aad_index[i]], aad_len[i]);
	if (ret != 0) {
		printf("failed\n");
		exit(1);
	}

	if (pt_len[i] > 32) {
		size_t rest_len = (pt_len[i] - 32);

		if (inplace) {
			memcpy(buf, ct[j * MAX_TESTS + i], 32);
			ret = gcm_update(&ctx, 0, 32, buf, buf);
		} else {
			ret = gcm_update(&ctx, 0, 32, ct[j * MAX_TESTS + i], buf);
		}

		if (ret != 0) {
			printf("failed\n");
			exit(1);
		}

		if (inplace) {
			memcpy((buf + 32), (ct[j * MAX_TESTS + i] + 32), rest_len);
			ret = gcm_update(&ctx, 32, rest_len,
					 (buf + 32), (buf + 32));
		} else {
			ret = gcm_update(&ctx, 32, rest_len,
					 (ct[j * MAX_TESTS + i] + 32), (buf + 32));
		}

		if (ret != 0) {
			printf("failed\n");
			exit(1);
		}
	} else {
		if (inplace) {
			memcpy(buf, ct[j * MAX_TESTS + i], pt_len[i]);
			ret = gcm_update(&ctx, 0, pt_len[i], buf, buf);
		} else {
			ret = gcm_update(&ctx, 0, pt_len[i],
					 ct[j * MAX_TESTS + i], buf);
		}

		if (ret != 0) {
			printf("failed\n");
			exit(1);
		}
	}

	ret = gcm_finish(&ctx, pt_len[i], aad_len[i], tag_buf, 16);
	if ((ret != 0) ||
	    (memcmp(buf, pt[pt_index[i]], pt_len[i]) != 0) ||
	    (memcmp(tag_buf, tag[j * MAX_TESTS + i], 16) != 0)) {
		printf("failed\n");
		exit(1);
	}

	gcm_free(&ctx);

	printf("passed\n");
}

void do_gcm_test(int inplace)
{
	int i, j, key_len;

	for (j = 0; j < 3; j++) {
		key_len = (128 + 64 * j);
		for (i = 0; i < MAX_TESTS; i++)
			gcm_test(inplace, key_len, j, i);
	}
}

/* ---------------------------------------- */

static void dump_mem(char *label, uint8_t *buf, int len)
{
	int i;

	printf("%s: ", label);
	for (i = 0; i < len; i++)
		printf("%02x ", buf[i]);
	printf("\n");
}

#define STRIDE 7
#define AAD "foobar"
#define DLEN 54 /* 3x blocks + 6B total datalen (plaintext/ciphertext) */
#define KEY_SIZE 16
#define TAG_SIZE 16
#define IV_SIZE 12

struct test_data {
	uint8_t key[KEY_SIZE];
	uint8_t iv[IV_SIZE];
	uint8_t pt[DLEN];
	uint8_t ct[DLEN];
	uint8_t tag[TAG_SIZE];
	uint8_t tag2[TAG_SIZE];
};

static void init_test_data(struct test_data *td)
{
	memset((uint8_t *)td, 0, sizeof(*td));

	memset(td->key, 0x11, KEY_SIZE);
	*((uint32_t *)td->key) = 0xDEADBEEF;

	memset(td->iv, 0x22, IV_SIZE);
	*((uint32_t *)td->iv) = 0xCAFECAFE;

	memset((td->pt +  0), 0x33, 16);
	memset((td->pt + 16), 0xCC, 16);
	memset((td->pt + 32), 0xAA, 16);
	memset((td->pt + 48), 0x55, 6); /* not a full block */
}

void do_gcm_test_updates(int inplace)
{
	struct gcm_context ctx;
	struct test_data td;
	char label[32];
	int stride, offset, length, work_len;
	int ret;

	init_test_data(&td);

	printf("----> (inplace=%d) GCM partials test\n", inplace);

	dump_mem("ptxt", td.pt, DLEN);

	gcm_init(&ctx);

	gcm_setkey(&ctx, td.key, (KEY_SIZE * 8));

	/* -------------------- */

	printf("----> encrypting single call\n");

	if (inplace) {
		memcpy(td.ct, td.pt, DLEN);
		gcm_crypt_and_tag(&ctx, GCM_ENCRYPT, DLEN, td.iv, IV_SIZE,
				  (uint8_t *)AAD, strlen(AAD),
				  td.ct, td.ct, TAG_SIZE, td.tag);
	} else {
		gcm_crypt_and_tag(&ctx, GCM_ENCRYPT, DLEN, td.iv, IV_SIZE,
				  (uint8_t *)AAD, strlen(AAD),
				  td.pt, td.ct, TAG_SIZE, td.tag);
	}

	dump_mem("ctxt", td.ct, DLEN);
	dump_mem("tag", td.tag, TAG_SIZE);

	memcpy(td.tag2, td.tag, TAG_SIZE); /* save a copy to compare against */

	/* -------------------- */

	printf("----> encrypting with partials\n");

	for (stride = 1; stride < DLEN; stride++) {
		printf("--> STRIDE=%d\n", stride);
		offset = 0;
		length = DLEN;
		work_len = stride;

		memset(td.ct, 0, DLEN);
		memset(td.tag, 0, TAG_SIZE);

		gcm_start(&ctx, GCM_ENCRYPT, td.iv, IV_SIZE,
			  (uint8_t *)AAD, strlen(AAD));

		while (length) {
			if ((offset + stride) >= DLEN)
				work_len = (DLEN - offset);

			if (inplace) {
				memcpy((td.ct + offset), (td.pt + offset), work_len);
				ret = gcm_update(&ctx, offset, work_len, (td.ct + offset),
						 (td.ct + offset));
			} else {
				ret = gcm_update(&ctx, offset, work_len, (td.pt + offset),
						 (td.ct + offset));
			}

			if (ret) {
				printf("ERROR: update partial failed\n");
				exit(1);
			}

			sprintf(label, "ct-%d", offset);
			dump_mem(label, (td.ct + offset), work_len);

			offset += work_len;
			length -= work_len;
		}

		gcm_finish(&ctx, DLEN, strlen(AAD), td.tag, TAG_SIZE);

		//dump_mem("ctxt", td.ct, DLEN);
		dump_mem("tag", td.tag, TAG_SIZE);

		if (memcmp(td.tag, td.tag2, TAG_SIZE)) {
			printf("ERROR: authentication failed\n");
			exit(1);
		}
	}

	/* -------------------- */

	printf("----> decrypting single call\n");

	memset(td.pt, 0, DLEN);

	if (inplace) {
		memcpy(td.pt, td.ct, DLEN);
		ret = gcm_auth_decrypt(&ctx, DLEN, td.iv, IV_SIZE,
				       (uint8_t *)AAD, strlen(AAD),
				       td.tag, TAG_SIZE, td.pt, td.pt);
	} else {
		ret = gcm_auth_decrypt(&ctx, DLEN, td.iv, IV_SIZE,
				       (uint8_t *)AAD, strlen(AAD),
				       td.tag, TAG_SIZE, td.ct, td.pt);
	}

	if (ret) {
		printf("ERROR: authentication failed\n");
		exit(1);
	}

	dump_mem("ptxt", td.pt, DLEN);
	dump_mem("tag", td.tag, TAG_SIZE);

	/* -------------------- */

	printf("----> decrypting with partials\n");

	for (stride = 1; stride < DLEN; stride++) {
		printf("--> STRIDE=%d\n", stride);
		offset = 0;
		length = DLEN;
		work_len = stride;

		memset(td.pt, 0, DLEN);

		gcm_start(&ctx, GCM_DECRYPT, td.iv, IV_SIZE,
			  (uint8_t *)AAD, strlen(AAD));

		while (length) {
			if ((offset + stride) >= DLEN)
				work_len = (DLEN - offset);

			if (inplace) {
				memcpy((td.pt + offset), (td.ct + offset), work_len);
				ret = gcm_update(&ctx, offset, work_len, (td.pt + offset),
						 (td.pt + offset));
			} else {
				ret = gcm_update(&ctx, offset, work_len, (td.ct + offset),
						 (td.pt + offset));
			}

			if (ret) {
				printf("ERROR: update partial failed\n");
				exit(1);
			}

			sprintf(label, "pt-%d", offset);
			dump_mem(label, (td.pt + offset), work_len);

			offset += work_len;
			length -= work_len;
		}

		gcm_finish(&ctx, DLEN, strlen(AAD), td.tag2, TAG_SIZE);

		//dump_mem("ptxt", td.pt, DLEN);
		dump_mem("tag", td.tag2, TAG_SIZE);

		if (memcmp(td.tag, td.tag2, TAG_SIZE)) {
			printf("ERROR: authentication failed\n");
			exit(1);
		}
	}

	/* -------------------- */

	gcm_free(&ctx);

	printf("----> GCM partials test done!\n");
}

