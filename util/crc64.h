
/*
 * Copyright (c) 2024, Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

#ifndef _CRC64_H_
#define _CRC64_H_

#include <stdint.h>
#include <unistd.h>

#define CRC64_LEN 8

void crc64_generate_table(void);
uint64_t crc64_be(const void *p, size_t len);

#endif /* _CRC64_H_ */
