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
 * AES test vectors from:
 * http://csrc.nist.gov/archive/aes/rijndael/rijndael-vals.zip
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../aes.h"

static const uint8_t aes_test_ecb_dec[3][16] = {
	{ 0x44, 0x41, 0x6A, 0xC2, 0xD1, 0xF5, 0x3C, 0x58,
	  0x33, 0x03, 0x91, 0x7E, 0x6B, 0xE9, 0xEB, 0xE0 },
	{ 0x48, 0xE3, 0x1E, 0x9E, 0x25, 0x67, 0x18, 0xF2,
	  0x92, 0x29, 0x31, 0x9C, 0x19, 0xF1, 0x5B, 0xA4 },
	{ 0x05, 0x8C, 0xCF, 0xFD, 0xBB, 0xCB, 0x38, 0x2D,
	  0x1F, 0x6F, 0x56, 0x58, 0x5D, 0x8A, 0x4A, 0xDE }
};

static const uint8_t aes_test_ecb_enc[3][16] = {
	{ 0xC3, 0x4C, 0x05, 0x2C, 0xC0, 0xDA, 0x8D, 0x73,
	  0x45, 0x1A, 0xFE, 0x5F, 0x03, 0xBE, 0x29, 0x7F },
	{ 0xF3, 0xF6, 0x75, 0x2A, 0xE8, 0xD7, 0x83, 0x11,
	  0x38, 0xF0, 0x41, 0x56, 0x06, 0x31, 0xB1, 0x14 },
	{ 0x8B, 0x79, 0xEE, 0xCC, 0x93, 0xA0, 0xEE, 0x5D,
	  0xFF, 0x30, 0xB4, 0xEA, 0x21, 0x63, 0x6D, 0xA4 }
};

void do_aes_test(void)
{
	int i, j, u, v;
	uint8_t key[32];
	uint8_t buf[64];
	int keybits;
	struct aes_context aes_ctx;

	memset(key, 0, 32);

	for (i = 0; i < 6; i++) {
		u = (i >> 1);
		v = (i & 1);

		keybits = (128 + u * 64);

		printf("AES-ECB-%3d (%s): ", keybits, (v == 0) ? "dec" : "enc");

		memset(buf, 0, 16);

		if (v == 0) { /* decryption */

			aes_init(&aes_ctx);
			aes_setkey_dec(&aes_ctx, key, keybits);

			for (j = 0; j < 10000; j++)
				AES_DECRYPT(&aes_ctx, buf);

			if (memcmp(buf, aes_test_ecb_dec[u], 16) != 0) {
				printf("failed\n");
				exit(1);
			}

		} else { /* encryption */

			aes_init(&aes_ctx);
			aes_setkey_enc(&aes_ctx, key, keybits);

			for (j = 0; j < 10000; j++)
				AES_ENCRYPT(&aes_ctx, buf);

			if (memcmp(buf, aes_test_ecb_enc[u], 16) != 0) {
				printf("failed\n");
				exit(1);
			}
		}

		printf("passed\n");
	}
}

