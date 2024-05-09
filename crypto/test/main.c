/*
 * Copyright (c) 2024, Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

#include <stdio.h>

extern void do_aes_test(void);

extern void do_gcm_test(int inplace);
extern void do_gcm_test_updates(int inplace);

extern void test_cmac_aes_128(void);
extern void test_cmac_aes_192(void);
extern void test_cmac_aes_256(void);

extern void test_kdf(void);
extern void test_uec_kdf(void);

int main(int argc, char *argv[])
{
	printf("\n---------------------------------------\n\n");
	do_aes_test();
	printf("\n---------------------------------------\n\n");
	//do_gcm_test(0);
	do_gcm_test(1);
	printf("\n---------------------------------------\n\n");
	//do_gcm_test_updates(0);
	do_gcm_test_updates(1);
	printf("\n---------------------------------------\n\n");
	test_cmac_aes_128();
	printf("\n---------------------------------------\n\n");
	test_cmac_aes_192();
	printf("\n---------------------------------------\n\n");
	test_cmac_aes_256();
	printf("\n---------------------------------------\n\n");
	test_kdf();
	printf("\n---------------------------------------\n\n");
	test_uec_kdf();
	printf("\n---------------------------------------\n\n");
	return 0;
}

