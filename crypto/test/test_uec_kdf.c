/*
 * Copyright (c) 2024, Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

/*
 * UEC KDF overview (IPv4/SSI and IPv6)...
 *
 *   Key size: 256b (AES-256)
 *   Counter size: 1B/8b (counter prefixed to fixed data by KDF)
 *   L: 2B/16b (=384, total keybits to generate by KDF)
 *
 *   Label: "U1" (2B, no delimiter) Cluster mode KDF
 *   Label: "U2" (2B, no delimiter) Server mode KDF
 *
 *   Context:
 *     - zero padding
 *     - epoch
 *     - a REKEY value that is based on a timestamp
 *     - the Source IP Address
 *
 *   REKEY computation (example):
 *     - programmable REKEY.mask
 *         - 0x000000FFFF000000 (mask off some amount of time)
 *     - programmable REKEY.rshift (based on mask)
 *         - 24
 *     - 4B REKEY value (big endian!)
 *         - rekey = htonl((uint32_t)((ts & mask) >> rshift))
 *
 *   IPv4 context 10B/80b:
 *     - 16b epoch
 *     - 32b rekey
 *     - 32b source IPv4 address
 *
 *   IPv6 context 26B/208b:
 *     - 32b zero pad
 *     - 16b epoch
 *     - 32b rekey
 *     - 128b source IPv6 address
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>

#include "../kdf_ctr_cmac_aes.h"

#define UEC_KEY_SIZE      256 /* bits */
#define UEC_KDF_KEY_SIZE  352 /* bits */
#define UEC_IVMASK_SIZE   96  /* bits */
#define UEC_CTR_SIZE      8   /* bits */
#define UEC_IPV4_CTX_SIZE 10  /* bytes */
#define UEC_IPV6_CTX_SIZE 26  /* bytes */

#define KEY "34448a064292601b11a0978f56a2d34cf3fc35ede1a6bc04f8db3e5243a2b0ca"
uint8_t key[UEC_KEY_SIZE / 8] = { 0 };

char *clusterLabel = "U1";
char *serverLabel  = "U2";

uint64_t ts          = 0x1DC074E500000023; // Oct 26, 1985 1:21 AM
uint64_t ts_mask     = 0x0000FFFF00000000;
uint32_t ts_shift    = 32;
uint32_t epoch_shift = 48;

/* 192.168.42.1 */
#define IPV4 "c0a82a01"
uint8_t ipv4[4] = { 0 };

/* 2001:0cb0:0000:0000:0fc0:0000:0000:0abc */
#define IPV6 "20010cb0000000000fc0000000000abc"
uint8_t ipv6[16] = { 0 };

#define IPV4_SDK "151b4ddb30112971ddeff3213000ee74d8f18aac2135601f1e5215e505fed449"
uint8_t ipv4_sdk[UEC_KEY_SIZE / 8] = { 0 };

#define IPV6_SDK "55d1ee8647bd53fad0e5325795af18e7559b7d42a895edf70f9c170341e8f767"
uint8_t ipv6_sdk[UEC_KEY_SIZE / 8] = { 0 };

#define IPV4_SERVER_SDK "245e67ab286218530edd53c26ea9ec33c96b35192d0a0eb54d08be281c5d304b"
uint8_t ipv4_server_sdk[UEC_KEY_SIZE / 8] = { 0 };

#define IPV6_SERVER_SDK "b59002ad3e6a9ae5864878730070f8916e43e5011acaa4be3504256185f24d97"
uint8_t ipv6_server_sdk[UEC_KEY_SIZE / 8] = { 0 };

void hex_to_uint8_array(char    *hex_string,
		        uint8_t *output,
		        size_t   output_size)
{
	size_t hex_len = strlen(hex_string);
	size_t byte_count = (hex_len / 2);
	int i, j;

	if (byte_count != output_size)
		return;

	for (i = 0, j = 0; i < hex_len; i += 2, j++) {
		char high_nibble = tolower(hex_string[i]);
		char low_nibble = (i + 1 < hex_len) ?
			              tolower(hex_string[i + 1]) : '0';
		uint8_t high = (high_nibble >= 'a') ?
			           (high_nibble - 'a' + 10) :
				   (high_nibble - '0');
		uint8_t low = (low_nibble >= 'a') ?
			           (low_nibble - 'a' + 10) :
				   (low_nibble - '0');

		output[j] = (high << 4) | low;
	}
}

static void print_bytes(uint8_t *data, int len)
{
	int i;

	for (i = 0; i < len; i++)
		printf("%02x", data[i]);
	printf("\n");
}

static void print_key_data(uint8_t  *context,
			   uint32_t  context_len,
			   uint8_t  *derived_key)
{
	printf("Context: ");
	print_bytes(context, context_len);
	printf("    KDF: ");
	print_bytes(derived_key, (UEC_KDF_KEY_SIZE / 8));
	printf("    SDK: ");
	print_bytes(derived_key, (UEC_KEY_SIZE / 8));
	printf("IV Mask: ");
	print_bytes((derived_key + (UEC_KEY_SIZE / 8)),
		    (UEC_IVMASK_SIZE / 8));
}

void test_uec_kdf(void)
{
	uint8_t derived_key[UEC_KDF_KEY_SIZE / 8];
	uint8_t *context;
	uint32_t rekey;
	uint16_t epoch;

	hex_to_uint8_array(KEY, key, sizeof(key));
	hex_to_uint8_array(IPV4, ipv4, sizeof(ipv4));
	hex_to_uint8_array(IPV6, ipv6, sizeof(ipv6));
	hex_to_uint8_array(IPV4_SDK, ipv4_sdk, sizeof(ipv4_sdk));
	hex_to_uint8_array(IPV6_SDK, ipv6_sdk, sizeof(ipv6_sdk));
	hex_to_uint8_array(IPV4_SERVER_SDK, ipv4_server_sdk, sizeof(ipv4_server_sdk));
	hex_to_uint8_array(IPV6_SERVER_SDK, ipv6_server_sdk, sizeof(ipv6_server_sdk));

	rekey = (uint32_t)((ts & ts_mask) >> ts_shift);
	rekey = htonl(rekey);

	epoch = (uint16_t)(ts >> epoch_shift);
	epoch = htons(epoch);

	/************************** Cluster v4 ******************************/

	memset(derived_key, 0, sizeof(derived_key));

	context = calloc(1, UEC_IPV4_CTX_SIZE);
	memcpy(context, (uint8_t *)&epoch, 2);
	memcpy((context + 2), (uint8_t *)&rekey, 4);
	memcpy((context + 6), ipv4, 4);

	kdf_ctr_cmac_aes(key,
			 UEC_KEY_SIZE,
			 UEC_CTR_SIZE,
			 (uint8_t *)clusterLabel,
			 strlen(clusterLabel), /* ignore delimiter */
			 context,
			 UEC_IPV4_CTX_SIZE,
			 derived_key,
			 UEC_KDF_KEY_SIZE);

	printf("UEC Cluster Mode KDF IPv4\n");
	print_key_data(context, UEC_IPV4_CTX_SIZE, derived_key);

	free(context);

	if (memcmp(ipv4_sdk, derived_key, (UEC_KEY_SIZE / 8)) != 0)
		printf("ERROR: IPv4 derived key mismatch\n");

	/************************** Cluster v6 ******************************/

	memset(derived_key, 0, sizeof(derived_key));

	context = calloc(1, UEC_IPV6_CTX_SIZE);
	memcpy((context + 4), (uint8_t *)&epoch, 2);
	memcpy((context + 6), (uint8_t *)&rekey, 4);
	memcpy((context + 10), ipv6, 16);

	kdf_ctr_cmac_aes(key,
			 UEC_KEY_SIZE,
			 UEC_CTR_SIZE,
			 (uint8_t *)clusterLabel,
			 strlen(clusterLabel), /* ignore delimiter */
			 context,
			 UEC_IPV6_CTX_SIZE,
			 derived_key,
			 UEC_KDF_KEY_SIZE);

	printf("\nUEC Cluster Mode KDF IPv6\n");
	print_key_data(context, UEC_IPV6_CTX_SIZE, derived_key);

	free(context);

	if (memcmp(ipv6_sdk, derived_key, (UEC_KEY_SIZE / 8)) != 0)
		printf("ERROR: IPv6 derived key mismatch\n");

	/************************** Server v4 *******************************/

	memset(derived_key, 0, sizeof(derived_key));

	context = calloc(1, UEC_IPV4_CTX_SIZE);
	memcpy(context, (uint8_t *)&epoch, 2);
	memcpy((context + 6), ipv4, 4);

	kdf_ctr_cmac_aes(key,
			 UEC_KEY_SIZE,
			 UEC_CTR_SIZE,
			 (uint8_t *)serverLabel,
			 strlen(serverLabel), /* ignore delimiter */
			 context,
			 UEC_IPV4_CTX_SIZE,
			 derived_key,
			 UEC_KDF_KEY_SIZE);

	printf("\nUEC Server Mode KDF IPv4\n");
	print_key_data(context, UEC_IPV4_CTX_SIZE, derived_key);

	free(context);

	if (memcmp(ipv4_server_sdk, derived_key, (UEC_KEY_SIZE / 8)) != 0)
		printf("ERROR: Server IPv4 mode derived key mismatch\n");

	/************************** Server v6 *******************************/

	memset(derived_key, 0, sizeof(derived_key));

	context = calloc(1, UEC_IPV6_CTX_SIZE);
	memcpy((context + 4), (uint8_t *)&epoch, 2);
	memcpy((context + 10), ipv6, 16);

	kdf_ctr_cmac_aes(key,
			 UEC_KEY_SIZE,
			 UEC_CTR_SIZE,
			 (uint8_t *)serverLabel,
			 strlen(serverLabel), /* ignore delimiter */
			 context,
			 UEC_IPV6_CTX_SIZE,
			 derived_key,
			 UEC_KDF_KEY_SIZE);

	printf("\nUEC Server Mode KDF IPv6\n");
	print_key_data(context, UEC_IPV6_CTX_SIZE, derived_key);

	free(context);

	if (memcmp(ipv6_server_sdk, derived_key, (UEC_KEY_SIZE / 8)) != 0)
		printf("ERROR: IPv6 derived key mismatch\n");

	printf("\n");
}

