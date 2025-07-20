/*
 * Copyright (c) 2024, Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

#ifndef _CRC32C_H_
#define _CRC32C_H_

#include <stdint.h>

#define CRC_LEN 4

uint32_t crc32c_init(void);

uint32_t crc32c_update(uint32_t crc,
		       const uint8_t *data,
		       uint32_t length);

uint32_t crc32c_finish(uint32_t crc);

uint32_t crc32c(const uint8_t *data,
		uint32_t length);

#endif /* _CRC32C_H_ */

