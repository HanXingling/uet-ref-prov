/*
 * Copyright (c) 2024, Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "uet_pkt_hdr.h"
#include "uet_log.h"
#include "uet_sec.h"
#include "kdf_ctr_cmac_aes.h"
#include "gcm.h"

#define UET_SEC_MAX_SD         8
#define UET_SEC_KEY_SIZE       32
#define UET_SEC_KDF_GEN_SIZE   44
#define UET_SEC_CTR_SIZE       8
#define UET_SEC_SMALL_CTX_SIZE 10
#define UET_SEC_LARGE_CTX_SIZE 26
#define UET_SEC_IV_SIZE        12

typedef enum {
	UET_SEC_ALG_NONE        = 0,
	UET_SEC_ALG_AES_GCM_256 = 1,
} uet_sec_alg_t;

typedef enum {
	UET_SEC_MODE_NONE    = 0,
	UET_SEC_MODE_DIRECT  = 1,
	UET_SEC_MODE_CLUSTER = 2,
	UET_SEC_MODE_SERVER  = 3,
} uet_sec_mode_t;

struct uet_sec_sd {
	bool           enabled;
	uint32_t       sdi;
	uet_sec_mode_t mode;
	bool           use_ssi;
	bool           rekey;
	uint64_t       rekey_mask;
	uint8_t        rekey_shift;
	int16_t        aoff;
	uint16_t       coff;
	uet_sec_alg_t  alg;
	uint16_t       epoch;
	uint8_t        an;
	uint8_t        key[2][UET_SEC_KDF_GEN_SIZE];
};

static struct uet_sec_sd sdkdb[UET_SEC_MAX_SD];

static char *uet_sec_label1 = "U1";
static char *uet_sec_label2 = "U2";

/**************************************************************************/
/* FIXME: Default fields used for the fixed SD... not yet configurable!   */

/* key generation: `dd if=/dev/urandom ibs=32 count=1 | xxd -i -c 8` */

static uint8_t def_key[2][UET_SEC_KDF_GEN_SIZE] = {
	{
		0x07, 0xe9, 0x72, 0x49, 0x58, 0xd9, 0xe1, 0xf7,
		0x10, 0xf5, 0x94, 0xe1, 0x8e, 0x11, 0xfd, 0x8d,
		0x4a, 0x35, 0x82, 0xc2, 0x56, 0xcc, 0xfe, 0xcf,
		0xc5, 0xeb, 0x19, 0x02, 0xe5, 0x56, 0xbe, 0xd4,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	},
	{
		0xd4, 0xc3, 0xa2, 0xcf, 0xb3, 0xc1, 0x06, 0x7f,
		0xdd, 0xcf, 0x9f, 0xe2, 0xe1, 0x42, 0x8a, 0x29,
		0xc8, 0xd3, 0x1b, 0xfb, 0x2a, 0x97, 0x02, 0x64,
		0x90, 0x0f, 0x16, 0xdf, 0x7c, 0x36, 0xdb, 0x6f,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	},
};

/* FIXME: support IPv6 for AOFF */
#define DEF_SDI         1
#define DEF_REKEY_MASK  0x0000FFFF00000000UL
#define DEF_REKEY_SHIFT 32
#define DEF_AOFF        -12 /* AAD includes source IPv4 address */
#define DEF_COFF        12 /* sizeof security header, +4 if using SSI */

static uint8_t fep_key[2][UET_SEC_KEY_SIZE] = {
	{
		0xa1, 0xbf, 0x74, 0xac, 0x7f, 0xf2, 0x35, 0x63,
		0xec, 0x59, 0x51, 0xaf, 0x99, 0x62, 0x68, 0xf0,
		0x02, 0xdb, 0x87, 0x82, 0x1c, 0xda, 0xab, 0x47,
		0x1e, 0x99, 0x1b, 0xd9, 0x96, 0xc4, 0xd7, 0xf1
	},
	{
		0x52, 0xf4, 0x95, 0x91, 0x76, 0xcd, 0xa4, 0x57,
		0x20, 0x65, 0xc3, 0x0f, 0xaa, 0x48, 0xeb, 0x01,
		0x5e, 0x62, 0x6e, 0xc8, 0x0b, 0x20, 0x0d, 0xe8,
		0xdb, 0x1f, 0x2f, 0xfb, 0x9d, 0x4a, 0xdc, 0x27
	},
};

/**************************************************************************/

int uet_sec_build_hdr(uint32_t sdi,
		      uint32_t ssi,
		      uint8_t *pkt_buf,
		      int pkt_buf_len,
		      uint8_t *pkt,
		      int pkt_len,
		      uint8_t **new_pkt,
		      int *new_pkt_len)
{
	struct uet_sec_sd *sd;
	struct uet_sec *sec;
	struct uet_sec_ssi *sec_ssi;
	uint64_t tsc;
	uint32_t tfs;
	int copy_len;
	char *client_ssi;

	if ((pkt == NULL) || (pkt_len <= 0) ||
	    (new_pkt == NULL) || (new_pkt_len == NULL)) {
		UET_TSS_ERR("invalid args to build security header\n");
		return -FI_EINVAL;
	}

	if (sdi >= UET_SEC_MAX_SD) {
		UET_TSS_ERR("invalid SDI %u\n", sdi);
		return -FI_EINVAL;
	}

	sd = &sdkdb[sdi];
	if (!sd->enabled) {
		UET_TSS_ERR("SDI %u is not enabled\n", sdi);
		return -FI_EINVAL;
	}

	/* TODO: IPv6 support and UDP support */
	copy_len = (sizeof(struct ethhdr) +
		    sizeof(struct iphdr) +
		    sizeof(struct uet_entropy));

	/* move the Ethernet and IP headers down */
	if (sd->use_ssi) {
		if ((pkt - sizeof(struct uet_sec_ssi)) < pkt_buf) {
			UET_TSS_ERR("no headroom for uet_sec_ssi header\n");
			return -FI_EINVAL;
		}

		*new_pkt     = (pkt - sizeof(struct uet_sec_ssi));
		*new_pkt_len = (pkt_len + sizeof(struct uet_sec_ssi));
		memcpy(*new_pkt, pkt, copy_len);
	} else {
		if ((pkt - sizeof(struct uet_sec)) < pkt_buf) {
			UET_TSS_ERR("no headroom for uet_sec header\n");
			return -FI_EINVAL;
		}

		*new_pkt     = (pkt - sizeof(struct uet_sec));
		*new_pkt_len = (pkt_len + sizeof(struct uet_sec));
		memcpy(*new_pkt, pkt, copy_len);
	}

	sec = (struct uet_sec *)(*new_pkt + copy_len);
	sec_ssi = (struct uet_sec_ssi *)sec;

	/* fill in the security header */

	tfs = (uint32_t)((UET_PDS_TYPE_SECURITY << UET_SEC_TYPE_SHIFT) |
			 ((sd->an << UET_SEC_AN_SHIFT) & UET_SEC_AN_MASK) |
			 ((sd->sdi << UET_SEC_SDI_SHIFT) & UET_SEC_SDI_MASK));
	if (sd->use_ssi)
		tfs |= (uint32_t)(UET_SEC_SP << UET_SEC_SP_SHIFT);

	sec->type_flags_sdi = htonl(tfs);

	uet_gettime((time_t *)&tsc);

	if (sd->use_ssi) {
		if (sd->mode == UET_SEC_MODE_SERVER) {
			/* for server mode the client SSI is always used */
			if (getenv(UET_SEC_SERVER)) {
				client_ssi = getenv(UET_SEC_CLIENT_SSI);
				sec_ssi->ssi = htonl(strtoul(client_ssi,
							     NULL, 10));
			} else {
				sec_ssi->ssi = htonl(ssi);
			}
		} else {
			sec_ssi->ssi = htonl(ssi);
		}

		sec_ssi->epoch_tsc =
			(uint64_t)(((uint64_t)sd->epoch <<
				    UET_SEC_EPOCH_SHIFT) |
				   (tsc & UET_SEC_TSC_MASK));
		sec_ssi->epoch_tsc = htonll(sec_ssi->epoch_tsc);
	} else {
		sec->epoch_tsc =
			(uint64_t)(((uint64_t)sd->epoch <<
				    UET_SEC_EPOCH_SHIFT) |
				   (tsc & UET_SEC_TSC_MASK));
		sec->epoch_tsc = htonll(sec->epoch_tsc);
	}

	return FI_SUCCESS;
}

int uet_sec_update_hdr_tsc(uint8_t *pkt)
{
	struct uet_sec *sec;
	struct uet_sec_ssi *sec_ssi;
	struct uet_sec_sd *sd;
	uint32_t sdi;
	uint64_t tsc;
	uint32_t tfs;

	/* TODO: IPv6 support and UDP support */
	sec = (struct uet_sec *)(pkt +
				 sizeof(struct ethhdr) +
				 sizeof(struct iphdr) +
				 sizeof(struct uet_entropy));
	sec_ssi = (struct uet_sec_ssi *)sec;

	tfs = ntohl(sec->type_flags_sdi);
	if (((tfs & UET_SEC_TYPE_MASK) >> UET_SEC_TYPE_SHIFT) !=
	     UET_PDS_TYPE_SECURITY) {
		UET_TSS_ERR("no security header present\n");
		return -FI_EINVAL;
	}

	/* get the sdi */
	sdi = ((tfs & UET_SEC_SDI_MASK) >> UET_SEC_SDI_SHIFT);

	if (sdi >= UET_SEC_MAX_SD) {
		UET_TSS_ERR("invalid SDI %u\n", sdi);
		return -FI_EINVAL;
	}

	/* get the SD to pull the latest epoch */
	sd = &sdkdb[sdi];
	if (!sd->enabled) {
		UET_TSS_ERR("SDI %u is not enabled\n", sdi);
		return -FI_EINVAL;
	}

	uet_gettime((time_t *)&tsc);

	if (tfs & UET_SEC_SP_MASK) {
		sec_ssi->epoch_tsc =
			(uint64_t)(((uint64_t)sd->epoch <<
				    UET_SEC_EPOCH_SHIFT) |
				   (tsc & UET_SEC_TSC_MASK));
		sec_ssi->epoch_tsc = htonll(sec_ssi->epoch_tsc);
	} else {
		sec->epoch_tsc =
			(uint64_t)(((uint64_t)sd->epoch <<
				    UET_SEC_EPOCH_SHIFT) |
				   (tsc & UET_SEC_TSC_MASK));
		sec->epoch_tsc = htonll(sec->epoch_tsc);
	}

	return FI_SUCCESS;
}

int uet_sec_enc_pkt(uint8_t *pkt_buf,
		    int pkt_buf_len,
		    uint8_t *pkt,
		    int pkt_len,
		    uint8_t **enc_pkt,
		    int *enc_pkt_len)
{
	uint8_t derived_key[UET_SEC_KDF_GEN_SIZE];
	uint8_t small_context[UET_SEC_SMALL_CTX_SIZE];
	//uint8_t large_context[UET_SEC_LARGE_CTX_SIZE];
	uint8_t iv[UET_SEC_IV_SIZE];
	uint8_t tag[UET_SEC_TAG_LEN];
	struct gcm_context gcm;
	struct uet_sec_sd *sd;
	struct iphdr *ip;
	uint8_t *sec_hdr, *aad;
	struct uet_sec *sec;
	struct uet_sec_ssi *sec_ssi;
	uint8_t *enc_out;
	uint8_t an;
	uint32_t sdi;
	uint32_t ssi;
	uint16_t epoch;
	uint64_t tsc;
	uint32_t tfs;
	uint32_t rekey;
	uint32_t tmp_val;
	uint64_t tmp_lval;
	int i, rc, clrtxt_len;

	/* TODO: IPv6 support (requires SSI) and UDP support */
	ip = (struct iphdr *)(pkt + sizeof(struct ethhdr));
	sec_hdr = (pkt +
		   sizeof(struct ethhdr) +
		   sizeof(struct iphdr) +
		   sizeof(struct uet_entropy));
	sec = (struct uet_sec *)sec_hdr;
	sec_ssi = (struct uet_sec_ssi *)sec_hdr;

	tfs = ntohl(sec->type_flags_sdi);
	if (((tfs & UET_SEC_TYPE_MASK) >> UET_SEC_TYPE_SHIFT) !=
	     UET_PDS_TYPE_SECURITY) {
		UET_TSS_ERR("no security header present\n");
		return -FI_EINVAL;
	}

	/* get the sdi/an */
	sdi = ((tfs & UET_SEC_SDI_MASK) >> UET_SEC_SDI_SHIFT);
	an  = !!(tfs & UET_SEC_AN_MASK);

	if (sdi >= UET_SEC_MAX_SD) {
		UET_TSS_ERR("invalid SDI %u\n", sdi);
		return -FI_EINVAL;
	}

	sd = &sdkdb[sdi];
	if (!sd->enabled) {
		UET_TSS_ERR("SDI %u is not enabled\n", sdi);
		return -FI_EINVAL;
	}

	/* if the SSI is being used, verify it's there in the header */
	if (sd->use_ssi && !(tfs & UET_SEC_SP_MASK)) {
		UET_TSS_ERR("security header is missing the SSI\n");
		return -FI_EINVAL;
	}

	/* get the epoch/tsc */
	tsc = (sd->use_ssi) ? ntohll(sec_ssi->epoch_tsc)
		            : ntohll(sec->epoch_tsc);
	epoch = (uint16_t)((tsc & UET_SEC_EPOCH_MASK) >> UET_SEC_EPOCH_SHIFT);
	tsc = ((tsc & UET_SEC_TSC_MASK) >> UET_SEC_TSC_SHIFT);

	/* crypto output is going in the upper half of the pkt_buf */
	enc_out = (pkt_buf + (pkt_buf_len / 2));

	/* make sure we're not going to overrun the cleartext or pkt_buf */
	if ((enc_out < (pkt + pkt_len)) ||
	    ((enc_out + pkt_len + UET_SEC_TAG_LEN) >
	     (pkt_buf + pkt_buf_len))) {
		UET_TSS_ERR("pkt buffer not large enough for crypto out\n");
		return -FI_EINVAL;
	}

	/* generate the key needed for encrypting the packet */

	memset(derived_key, 0, sizeof(derived_key));

	rekey = 0;
	if (sd->rekey) {
		rekey = (uint32_t)((tsc & sd->rekey_mask) >> sd->rekey_shift);
		rekey = htonl(rekey);
	}

	switch (sd->mode) {
	case UET_SEC_MODE_DIRECT:
		memcpy(derived_key, sd->key[an], UET_SEC_KEY_SIZE);
		break;

	case UET_SEC_MODE_CLUSTER:
		/* TODO: support IPv6 w/ large_context (requires SSI) */
		memset(small_context, 0, sizeof(small_context));
		memcpy(small_context, (uint8_t *)&epoch, 2);
		memcpy((small_context + 2), (uint8_t *)&rekey, 4);
		tmp_val = (sd->use_ssi) ? sec_ssi->ssi : ip->saddr;
		memcpy((small_context + 6), (uint8_t *)&tmp_val, 4);

		kdf_ctr_cmac_aes(sd->key[an],
				 (UET_SEC_KEY_SIZE * 8),
				 UET_SEC_CTR_SIZE,
				 (uint8_t *)uet_sec_label1,
				 strlen(uet_sec_label1), /* ignore delimiter */
				 small_context,
				 UET_SEC_SMALL_CTX_SIZE,
				 derived_key,
				 (UET_SEC_KDF_GEN_SIZE * 8));
		break;

	case UET_SEC_MODE_SERVER:
		if (!getenv(UET_SEC_SERVER)) {
			memcpy(derived_key, sd->key[an], UET_SEC_KDF_GEN_SIZE);
			break;
		}

		/* TODO: support IPv6 w/ large_context (requires SSI) */
		memset(small_context, 0, sizeof(small_context));
		memcpy(small_context, (uint8_t *)&epoch, 2);
		tmp_val = (sd->use_ssi) ? sec_ssi->ssi : ip->saddr;
		memcpy((small_context + 6), (uint8_t *)&tmp_val, 4);

		kdf_ctr_cmac_aes(sd->key[sd->an],
				 (UET_SEC_KEY_SIZE * 8),
				 UET_SEC_CTR_SIZE,
				 (uint8_t *)uet_sec_label2,
				 strlen(uet_sec_label2), /* ignore delimiter */
				 small_context,
				 UET_SEC_SMALL_CTX_SIZE,
				 derived_key,
				 (UET_SEC_KDF_GEN_SIZE * 8));
		break;

	default:
		UET_TSS_ERR("unknown mode\n");
		return -FI_EINVAL;
		break;
	}

	/* encrypt the packet */

	/* TODO: account for the entropy or UDP header */
	aad = (sec_hdr + sd->aoff); /* likely negative and moves backwards */

	/* TODO: support IPv6 (requires SSI) */
	tmp_val = (sd->use_ssi) ? sec_ssi->ssi : ip->saddr;
	memcpy(iv, (uint8_t *)&tmp_val, 4);
	tmp_lval = htonll(tsc);
	memcpy((iv + 4), (uint8_t *)&tmp_lval, 8);

	/* XOR in the IVMASK */
	if (sd->mode != UET_SEC_MODE_DIRECT) {
		for (i = 0; i < UET_SEC_IV_SIZE; i++)
			iv[i] ^= derived_key[UET_SEC_KEY_SIZE + i];
	}

	clrtxt_len = ((sec_hdr + sd->coff) - pkt);
	memcpy(enc_out, pkt, clrtxt_len);

	gcm_init(&gcm);
	gcm_setkey(&gcm, derived_key, (UET_SEC_KEY_SIZE * 8));
	rc = gcm_crypt_and_tag(&gcm,
			       GCM_ENCRYPT,
			       (pkt_len - clrtxt_len),
			       iv,
			       UET_SEC_IV_SIZE,
			       aad,
			       ((sec_hdr + sd->coff) - aad),
			       (pkt + clrtxt_len),
			       (enc_out + clrtxt_len),
			       UET_SEC_TAG_LEN,
			       tag);
	if (rc != 0) {
		UET_TSS_ERR("failed to encrypt packet\n");
		return -FI_EINVAL;
	}

	memcpy((enc_out + pkt_len), tag, UET_SEC_TAG_LEN);

	*enc_pkt = enc_out;
	*enc_pkt_len = (pkt_len + UET_SEC_TAG_LEN);

	return FI_SUCCESS;
}

int uet_sec_dec_pkt(uint8_t *pkt,
		    int pkt_len,
		    int *tag_len)
{
	uint8_t derived_key[UET_SEC_KDF_GEN_SIZE];
	uint8_t small_context[UET_SEC_SMALL_CTX_SIZE];
	//uint8_t large_context[UET_SEC_LARGE_CTX_SIZE];
	uint8_t iv[UET_SEC_IV_SIZE];
	struct gcm_context gcm;
	struct uet_sec_sd *sd;
	struct uet_sec *sec;
	struct uet_sec_ssi *sec_ssi;
	struct iphdr *ip;
	uint8_t *sec_hdr, *aad;
	uint32_t rekey;
	uint32_t tmp_val;
	uint64_t tmp_lval;
	uint16_t epoch;
	uint64_t tsc;
	uint8_t an;
	uint32_t sdi;
	uint32_t tfs;
	int i, rc, clrtxt_len;

	/* TODO: IPv6 support (requires SSI) and UDP support */
	ip = (struct iphdr *)(pkt + sizeof(struct ethhdr));
	sec_hdr = (pkt +
		   sizeof(struct ethhdr) +
		   sizeof(struct iphdr) +
		   sizeof(struct uet_entropy));
	sec = (struct uet_sec *)sec_hdr;
	sec_ssi = (struct uet_sec_ssi *)sec_hdr;

	tfs = ntohl(sec->type_flags_sdi);
	if (((tfs & UET_SEC_TYPE_MASK) >> UET_SEC_TYPE_SHIFT) !=
	     UET_PDS_TYPE_SECURITY) {
		*tag_len = 0;
		return FI_SUCCESS;
	}

	/* get the sdi/an */
	sdi = ((tfs & UET_SEC_SDI_MASK) >> UET_SEC_SDI_SHIFT);
	an  = !!(tfs & UET_SEC_AN_MASK);

	if (sdi >= UET_SEC_MAX_SD) {
		UET_TSS_ERR("invalid SDI %u\n", sdi);
		return -FI_EINVAL;
	}

	sd = &sdkdb[sdi];
	if (!sd->enabled) {
		UET_TSS_ERR("SDI %u is not enabled\n", sdi);
		return -FI_EINVAL;
	}

	/* if the SSI is being used, verify it's there in the header */
	if (sd->use_ssi && !(tfs & UET_SEC_SP_MASK)) {
		UET_TSS_ERR("security header is missing the SSI\n");
		return -FI_EINVAL;
	}

	/* get the epoch/tsc */
	tsc = (sd->use_ssi) ? ntohll(sec_ssi->epoch_tsc)
		            : ntohll(sec->epoch_tsc);
	epoch = (uint16_t)((tsc & UET_SEC_EPOCH_MASK) >> UET_SEC_EPOCH_SHIFT);
	tsc = ((tsc & UET_SEC_TSC_MASK) >> UET_SEC_TSC_SHIFT);

	/* generate the key needed for encrypting the packet */

	memset(derived_key, 0, sizeof(derived_key));

	rekey = 0;
	if (sd->rekey) {
		rekey = (uint32_t)((tsc & sd->rekey_mask) >> sd->rekey_shift);
		rekey = htonl(rekey);
	}

	switch (sd->mode) {
	case UET_SEC_MODE_DIRECT:
		memcpy(derived_key, sd->key[an], UET_SEC_KEY_SIZE);
		break;

	case UET_SEC_MODE_CLUSTER:
		/* TODO: support IPv6 w/ large_context (requires SSI) */
		memset(small_context, 0, sizeof(small_context));
		memcpy(small_context, (uint8_t *)&epoch, 2);
		memcpy((small_context + 2), (uint8_t *)&rekey, 4);
		tmp_val = (sd->use_ssi) ? sec_ssi->ssi : ip->saddr;
		memcpy((small_context + 6), (uint8_t *)&tmp_val, 4);

		kdf_ctr_cmac_aes(sd->key[an],
				 (UET_SEC_KEY_SIZE * 8),
				 UET_SEC_CTR_SIZE,
				 (uint8_t *)uet_sec_label1,
				 strlen(uet_sec_label1), /* ignore delimiter */
				 small_context,
				 UET_SEC_SMALL_CTX_SIZE,
				 derived_key,
				 (UET_SEC_KDF_GEN_SIZE * 8));
		break;

	case UET_SEC_MODE_SERVER:
		if (!getenv(UET_SEC_SERVER)) {
			memcpy(derived_key, sd->key[an], UET_SEC_KDF_GEN_SIZE);
			break;
		}

		/* TODO: support IPv6 w/ large_context (requires SSI) */
		memset(small_context, 0, sizeof(small_context));
		memcpy(small_context, (uint8_t *)&epoch, 2);
		tmp_val = (sd->use_ssi) ? sec_ssi->ssi : ip->saddr;
		memcpy((small_context + 6), (uint8_t *)&tmp_val, 4);

		kdf_ctr_cmac_aes(sd->key[sd->an],
				 (UET_SEC_KEY_SIZE * 8),
				 UET_SEC_CTR_SIZE,
				 (uint8_t *)uet_sec_label2,
				 strlen(uet_sec_label2), /* ignore delimiter */
				 small_context,
				 UET_SEC_SMALL_CTX_SIZE,
				 derived_key,
				 (UET_SEC_KDF_GEN_SIZE * 8));
		break;

	default:
		UET_TSS_ERR("unknown mode\n");
		return -FI_EINVAL;
		break;
	}

	/* decrypt the packet */

	/* TODO: account for the entropy or UDP header */
	aad = (sec_hdr + sd->aoff); /* likely negative and moves backwards */

	/* TODO: support IPv6 (requires SSI) */
	tmp_val = (sd->use_ssi) ? sec_ssi->ssi : ip->saddr;
	memcpy(iv, (uint8_t *)&tmp_val, 4);
	tmp_lval = htonll(tsc);
	memcpy((iv + 4), (uint8_t *)&tmp_lval, 8);

	/* XOR in the IVMASK */
	if (sd->mode != UET_SEC_MODE_DIRECT) {
		for (i = 0; i < UET_SEC_IV_SIZE; i++)
			iv[i] ^= derived_key[UET_SEC_KEY_SIZE + i];
	}

	clrtxt_len = ((sec_hdr + sd->coff) - pkt);

	gcm_init(&gcm);
	gcm_setkey(&gcm, derived_key, (UET_SEC_KEY_SIZE * 8));
	rc = gcm_auth_decrypt(&gcm,
			      (pkt_len - clrtxt_len - UET_SEC_TAG_LEN),
			      iv,
			      UET_SEC_IV_SIZE,
			      aad,
			      ((sec_hdr + sd->coff) - aad),
			      (pkt + pkt_len - UET_SEC_TAG_LEN),
			      UET_SEC_TAG_LEN,
			      (pkt + clrtxt_len),
			      (pkt + clrtxt_len));
	if (rc != 0) {
		UET_TSS_ERR("failed to decrypt packet\n");
		return -FI_EINVAL;
	}

	*tag_len = UET_SEC_TAG_LEN;

	return FI_SUCCESS;
}

static int uet_sec_init_sd(uint32_t sdi,
			   uet_sec_mode_t mode,
			   bool use_ssi,
			   bool rekey)
{
	uint8_t derived_key[UET_SEC_KDF_GEN_SIZE];
	uint8_t small_context[UET_SEC_SMALL_CTX_SIZE];
	//uint8_t large_context[UET_SEC_LARGE_CTX_SIZE];
	struct uet_sec_sd *sd;
	char *client_ssi;
	uint32_t tmp_val;

	if (sdi >= UET_SEC_MAX_SD) {
		UET_TSS_ERR("invalid SDI %u\n", sdi);
		return -FI_EINVAL;
	}

	sd = &sdkdb[sdi];
	memset(sd, 0, sizeof(*sd));

	sd->enabled     = true;
	sd->sdi         = sdi;
	sd->mode        = mode;
	sd->use_ssi     = use_ssi;
	sd->rekey       = rekey;
	sd->rekey_mask  = DEF_REKEY_MASK;
	sd->rekey_shift = DEF_REKEY_SHIFT;
	sd->aoff        = DEF_AOFF;
	sd->coff        = (use_ssi) ? (DEF_COFF + 4) : DEF_COFF;
	sd->alg         = UET_SEC_ALG_AES_GCM_256;
	sd->epoch       = 1; /* FIXME: init/roll epoch */
	sd->an          = 0;
	memcpy(sd->key, def_key, sizeof(def_key));

	/* for client side of server mode, do KDFs now */
	if ((mode == UET_SEC_MODE_SERVER) && !getenv(UET_SEC_SERVER)) {
		/* TODO: support both SSI and source IPv4 for server mode */
		if (!getenv(UET_SEC_SSI)) {
			UET_TSS_ERR("server mode requires SSI\n");
			memset(sd, 0, sizeof(*sd));
			return -FI_EINVAL;
		}

		/* TODO: support IPv6 w/ large_context (requires SSI) */
		memset(small_context, 0, sizeof(small_context));
		memcpy(small_context, (uint8_t *)&sd->epoch, 2);
		client_ssi = getenv(UET_SEC_SSI);
		tmp_val = htonl(strtoul(client_ssi, NULL, 10));
		memcpy((small_context + 6), (uint8_t *)&tmp_val, 4);

		kdf_ctr_cmac_aes(sd->key[0],
				 (UET_SEC_KEY_SIZE * 8),
				 UET_SEC_CTR_SIZE,
				 (uint8_t *)uet_sec_label2,
				 strlen(uet_sec_label2), /* ignore delimiter */
				 small_context,
				 UET_SEC_SMALL_CTX_SIZE,
				 derived_key,
				 (UET_SEC_KDF_GEN_SIZE * 8));

		memcpy(sd->key[0], derived_key, UET_SEC_KDF_GEN_SIZE);

		kdf_ctr_cmac_aes(sd->key[1],
				 (UET_SEC_KEY_SIZE * 8),
				 UET_SEC_CTR_SIZE,
				 (uint8_t *)uet_sec_label2,
				 strlen(uet_sec_label2), /* ignore delimiter */
				 small_context,
				 UET_SEC_SMALL_CTX_SIZE,
				 derived_key,
				 (UET_SEC_KDF_GEN_SIZE * 8));

		memcpy(sd->key[1], derived_key, UET_SEC_KDF_GEN_SIZE);
	}

	return FI_SUCCESS;
}

int uet_sec_init(void)
{
	char *sec, *sec_mode, *sec_ssi;
	int i, rc;

	memset(sdkdb, 0, sizeof(sdkdb));

	for (i = 0; i < UET_SEC_MAX_SD; i++)
		sdkdb[i].enabled = false;

	sec_mode = getenv(UET_SEC_MODE);
	sec_ssi  = getenv(UET_SEC_SSI);

	if (sec_mode == NULL)
		return FI_SUCCESS;

	/* FIXME: Only using SDI=0x1 AN=0x0 for now... */

	if ((sec_mode == NULL) || (strcmp(sec_mode, "direct") == 0)) {

		rc = uet_sec_init_sd(DEF_SDI, UET_SEC_MODE_DIRECT,
				     (sec_ssi != NULL), false);

	} else if (strcmp(sec_mode, "cluster") == 0) {

		rc = uet_sec_init_sd(DEF_SDI, UET_SEC_MODE_CLUSTER,
				     (sec_ssi != NULL), true);

	} else if (strcmp(sec_mode, "server") == 0) {

		if (sec_ssi == NULL) {
			UET_TSS_ERR("UET_SEC_SSI required for server mode");
			return -FI_EINVAL;
		}

		if (getenv(UET_SEC_SERVER) && !getenv(UET_SEC_CLIENT_SSI)) {
			UET_TSS_ERR("UET_SEC_CLIENT_SSI required on server "
				    "for server mode");
			return -FI_EINVAL;
		}

		rc = uet_sec_init_sd(DEF_SDI, UET_SEC_MODE_SERVER,
				     true, false);

	} else {

		UET_TSS_ERR("invalid UET_SEC_MODE environment variable");
		return -FI_EINVAL;

	}

	return rc;
}

