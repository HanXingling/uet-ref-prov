/*
 * Copyright (c) 2024, Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

#include <stdio.h>
#include <getopt.h>

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
if (argc == 1) {
		goto out;		
	}

	for(int i=0; i<argc; i++){
		switch(getopt(argc, argv, "cghku")){
			case 'g':
				printf("\n----------------do_aes_tes-------------\n\n");
				do_aes_test();
				printf("\n----------------do_gcm_test------------\n\n");
				do_gcm_test(1); // Inline
				printf("\n----------------do_gcm_test_updates----\n\n");
				do_gcm_test_updates(1); // Inline
				continue;
			case 'c':
				printf("\n----------------test_cmac_aes_256------\n\n");
				test_cmac_aes_256();
				continue;
			case 'k':
				printf("\n-----------------test_kdf--------------\n\n");
				test_kdf();
				continue;
			case 'u':
				printf("\n-----------------test_uec_kdf----------\n\n");
				test_uec_kdf();
				continue;
			case 'h':
				goto out;
			default :
				continue;
		}
	}
	return 0;
out:
	printf("%s -hcgku\n\t -g gcm tests\n\t -k kdf tests\n\t -c cmac tests\n\t -u uec kdf tests\n\n\t To run full regression %s -cgku\n\n", argv[0], argv[0]);
	return -1;
}

