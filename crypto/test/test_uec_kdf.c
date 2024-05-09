/*
 * Copyright (c) 2024, Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

/*
 * UEC KDF overview (IPv4/SSI and IPv6)...
 *
 *   Key size: 256b (AES-256)
 *   Counter size: 1B/8b (counter prefixed to fixed data by KDF)
 *
 *   Label: "UE1" (3B, no delimiter)
 *
 *   Context:
 *     - zero padding
 *     - a REKEY value that is based on a timestamp
 *     - the Source IP Address
 *
 *   REKEY computation (example):
 *     - programmable REKEY.mask
 *         - 0xFF000000 (mask off some amount of time)
 *     - programmable REKEY.rshift (depends on mask)
 *         - 24
 *     - 2B REKEY value (big endian!)
 *         - rekey = htons((uint16_t)((ts & mask) >> rshift))
 *
 *   IPv4 context 7B/56b:
 *     - 8b zero pad
 *     - 16b rekey
 *     - 32b source IPv4 address
 *
 *   IPv6 context 23B/184b:
 *     - 40b zero pad
 *     - 16b rekey
 *     - 128b source IPv6 address
 *
 *
 * UEC KDF overview (Domain mode)...
 *
 *   Key size: 256b (AES-256)
 *   Counter size: 1B/8b (counter prefixed to fixed data by KDF)
 *
 *   Label: "UE2" (3B, no delimiter)
 *
 *   Context:
 *     - zero padding
 *     - a REKEY value that is based on a timestamp
 *     - the SDI
 *
 *   REKEY computation (example):
 *     - programmable REKEY.mask
 *         - 0xFF000000 (mask off some amount of time)
 *     - programmable REKEY.rshift (depends on mask)
 *         - 24
 *     - 2B REKEY value (big endian!)
 *         - rekey = htons((uint16_t)((ts & mask) >> rshift))
 *
 *   Domain mode context 7B/56b:
 *     - 8b zero pad
 *     - 16b rekey
 *     - 32b SDI
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "../kdf_ctr_cmac_aes.h"

#define UEC_KEY_SIZE      256
#define UEC_CTR_SIZE      8
#define UEC_IPV4_CTX_SIZE 7
#define UEC_DOMM_CTX_SIZE 7
#define UEC_IPV6_CTX_SIZE 23

uint8_t key[32] = {
	0x34, 0x44, 0x8a, 0x06, 0x42, 0x92, 0x60, 0x1b,
	0x11, 0xa0, 0x97, 0x8f, 0x56, 0xa2, 0xd3, 0x4c,
	0xf3, 0xfc, 0x35, 0xed, 0xe1, 0xa6, 0xbc, 0x04,
	0xf8, 0xdb, 0x3e, 0x52, 0x43, 0xa2, 0xb0, 0xca,
};

char *label1 = "UE1";
char *label2 = "UE2";

uint64_t ts       = 0x1DC07480E5000000; // Oct 26, 1985 1:20 AM + 229ms
uint64_t ts_mask  = 0x00000000FF000000;
uint32_t ts_shift = 24;

uint8_t ipv4[4] = {
	/* 192.168.42.1 */
	0x48, 0x2a, 0xa8, 0xc0,
};

uint8_t ipv6[16] = {
	/* 2001:0cb0:0000:0000:0fc0:0000:0000:0abc */
	0x20, 0x01, 0x0c, 0xb0, 0x00, 0x00, 0x00, 0x00,
	0x0f, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x0a, 0xbc,
};

uint8_t ipv4_sdk[32] = {
	0x2a, 0x0a, 0x3f, 0xe1, 0x37, 0x02, 0xc8, 0xb4,
	0xd6, 0xcd, 0x3d, 0x0b, 0x40, 0x3f, 0x6d, 0x4f,
	0x51, 0x48, 0x31, 0x58, 0xb5, 0xea, 0x59, 0x82,
	0x7a, 0xfe, 0x1b, 0xcf, 0x9f, 0xc5, 0x56, 0x54,
};

uint8_t ipv6_sdk[32] = {
	0x36, 0xf6, 0x1b, 0x13, 0x80, 0x1b, 0xef, 0x83,
	0x12, 0x7e, 0x20, 0xfe, 0x16, 0x24, 0xc1, 0x50,
	0x82, 0xb2, 0x8f, 0xa8, 0x43, 0x79, 0xea, 0x9f,
	0xb7, 0xe3, 0x61, 0x72, 0x05, 0x0f, 0xdd, 0x55,
};

uint8_t domain_sdi[4] = {
	0x80, 0x00, 0x00, 0xE5,
};

uint8_t domain_sdk[32] = {
	0x67, 0x90, 0x53, 0x36, 0xae, 0xbd, 0x8a, 0xfc,
	0xf3, 0xd2, 0x22, 0x96, 0x6f, 0x70, 0xe8, 0x7f,
	0xed, 0x42, 0xe9, 0xe0, 0x75, 0xe1, 0x79, 0x22,
	0xd2, 0xbe, 0xe3, 0x5f, 0x25, 0x7c, 0xf6, 0x57,
};

static void print_bytes(uint8_t *data, int len)
{
	int i;

	for (i = 0; i < len; i++)
		printf("%02x", data[i]);
	printf("\n");
}

void test_uec_kdf(void)
{
	uint8_t derived_key[32];
	uint8_t *context;
	uint16_t rekey;

	rekey = (uint16_t)((ts & ts_mask) >> ts_shift);
	rekey = htons(rekey);

	/***********************************************************/

	memset(derived_key, 0, sizeof(derived_key));

	context = calloc(1, UEC_IPV4_CTX_SIZE);
	memcpy((context + 1), (uint8_t *)&rekey, 2);
	memcpy((context + 3), ipv4, 4);

	kdf_ctr_cmac_aes(key,
			 UEC_KEY_SIZE,
			 UEC_CTR_SIZE,
			 (uint8_t *)label1,
			 strlen(label1), /* ignore delimiter */
			 context,
			 UEC_IPV4_CTX_SIZE,
			 derived_key,
			 UEC_KEY_SIZE);

	free(context);

	printf("UEC KDF IPv4: ");
	print_bytes(derived_key, 32);

	if (memcmp(ipv4_sdk, derived_key, 32) != 0)
		printf("ERROR: IPv4 derived key mismatch\n");

	/***********************************************************/

	memset(derived_key, 0, sizeof(derived_key));

	context = calloc(1, UEC_IPV6_CTX_SIZE);
	memcpy((context + 5), (uint8_t *)&rekey, 2);
	memcpy((context + 7), ipv6, 16);

	kdf_ctr_cmac_aes(key,
			 UEC_KEY_SIZE,
			 UEC_CTR_SIZE,
			 (uint8_t *)label1,
			 strlen(label1), /* ignore delimiter */
			 context,
			 UEC_IPV6_CTX_SIZE,
			 derived_key,
			 UEC_KEY_SIZE);

	free(context);

	printf("UEC KDF IPv6: ");
	print_bytes(derived_key, 32);

	if (memcmp(ipv6_sdk, derived_key, 32) != 0)
		printf("ERROR: IPv6 derived key mismatch\n");

	/***********************************************************/

	memset(derived_key, 0, sizeof(derived_key));

	context = calloc(1, UEC_DOMM_CTX_SIZE);
	memcpy((context + 1), (uint8_t *)&rekey, 2);
	memcpy((context + 3), domain_sdi, 4);

	kdf_ctr_cmac_aes(key,
			 UEC_KEY_SIZE,
			 UEC_CTR_SIZE,
			 (uint8_t *)label2,
			 strlen(label2), /* ignore delimiter */
			 context,
			 UEC_DOMM_CTX_SIZE,
			 derived_key,
			 UEC_KEY_SIZE);

	free(context);

	printf("UEC KDF DOMAIN: ");
	print_bytes(derived_key, 32);

	if (memcmp(domain_sdk, derived_key, 32) != 0)
		printf("ERROR: Domain mode derived key mismatch\n");
}

