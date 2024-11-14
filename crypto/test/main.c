/*
 * Copyright (c) 2024, Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

#include <stdio.h>
#include <getopt.h>
#include <stdbool.h>

extern void do_aes_test(void);

extern void do_gcm_test(int inplace);
extern void do_gcm_test_updates(int inplace);

extern void test_cmac_aes_128(void);
extern void test_cmac_aes_192(void);
extern void test_cmac_aes_256(void);

extern void test_kdf(void);
extern void test_uec_kdf(void);

void usage(char *cmd)
{
	printf("%s <args...>\n"
	       "  -a    Run all tests\n"
	       "  -g    Run GCM tests\n"
	       "  -k    Run KDF tests\n"
	       "  -c    Run CMAC tests\n"
	       "  -u    Run UEC KDF tests\n"
	       "  -h    Help usage\n",
	       cmd);
}

void run_gcm_tests(void)
{
	printf("\n----------------do_aes_test------------\n\n");
	do_aes_test();
	printf("\n----------------do_gcm_test------------\n\n");
	do_gcm_test(1); // Inline
	printf("\n----------------do_gcm_test_updates----\n\n");
	do_gcm_test_updates(1); // Inline
}

void run_kdf_tests(void)
{
	printf("\n----------------test_kdf---------------\n\n");
	test_kdf();
}

void run_cmac_tests(void)
{
	printf("\n----------------test_cmac_aes_256------\n\n");
	test_cmac_aes_256();
}

void run_uec_kdf_tests(void)
{
	printf("\n----------------test_uec_kdf-----------\n\n");
	test_uec_kdf();
}

int main(int argc, char *argv[])
{
	bool gcm = false, kdf = false, cmac = false, uec_kdf = false;
	char opt;

	if (argc == 1) {
		usage(argv[0]);
		return 1;
	}

	while ((opt = getopt(argc, argv, "agkcuh")) != -1) {
		switch (opt) {
		case 'a': gcm = kdf = cmac = uec_kdf = true; break;
		case 'g': gcm = true; break;
		case 'k': kdf = true; break;
		case 'c': cmac = true; break;
		case 'u': uec_kdf = true; break;
		case 'h':
		default: usage(argv[0]); break;
		}
	}

	if (gcm) run_gcm_tests();
	if (kdf) run_kdf_tests();
	if (cmac) run_cmac_tests();
	if (uec_kdf) run_uec_kdf_tests();

	return 0;
}

