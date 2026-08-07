/*
 * Copyright (c) 2024,2025,2026 Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

/* Secure-domain database (SDKDB) management — the reference app's SDME
 * stand-in. Owns the SD table, key material, per-SD/port statistics, and the
 * AN key-rotation scheduler (SDMI stand-in). The per-packet crypto core
 * lives in uet_sec.c.
 */

/*
 * AN key-rotation design (the SDME stand-in)...
 *
 * A real deployment rotates per-SD keys out-of-band via an SDME. Here it is
 * faked with a scheme driven entirely by the shared wall clock, so both peers
 * rotate in lockstep with zero signaling and no dependence on process start
 * time. It is gated per run using the UET_SEC_KEY_ROTATION environment
 * variable, otherwise it's off.
 *
 * Rotation index is calculated using the absolute wall-clock time chopped
 * into fixed UET_SEC_ROT_INTERVAL_MS buckets numbered from the Unix epoch:
 *
 *     uet_gettime(&now_ms)
 *     rot = (now_ms / UET_SEC_ROT_INTERVAL_MS)
 *
 * rot ticks up by 1 every interval and both peers compute the same value from
 * their NTP-synced clocks. Everything derives from it (N = UET_SEC_ROT_N):
 *
 *     active AN  = (rot & 1)          the 1-bit AN on the wire
 *     pool slot  = (rot & (N - 1))    which of the N compiled in pool keys
 *     generation = (rot / N)          how many full wraps through the pool
 *
 * Fresh key every rotation. The pool holds only N keys so a key slot recurs
 * every N rotations. The counter/epoch is reset to 0 on each rotation, so
 * reusing a key slot's raw bytes would replay (key, IV) pairs which leads
 * to AES-GCM nonce reuse. Bad! The effective key is therefore folded in with
 * the generation:
 *
 *     effective_key = (pool[slot] XOR wrap_mix(generation))
 *
 * wrap_mix() is deterministic and distinct per generation, so each recurrence
 * of a slot is a different key and no (key, IV) pair ever repeats.
 *
 * Make-before-break. Clocks are not perfectly aligned, so near a boundary a
 * peer may still be sending with the previous AN or already with the next
 * one. The packet's AN/key is resolved against the local clock to pick rot,
 * rot-1 (previous key, kept for UET_SEC_ROT_GUARD_MS), or rot+1 (next
 * key), covering skew in both directions.
 *
 * TX bookkeeping. The Tx rotate function watches rot and, on each boundary,
 * resets the counter and epoch to 0. The epoch is only ever advanced by an
 * SDME on a FEP leave/rejoin (not modeled here), so it stays fixed at 0.
 */

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "uet_pkt_hdr.h"
#include "uet_log.h"
#include "uet_util.h"
#include "uet_sec_sd.h"
#include "kdf_ctr_cmac_aes.h"

static struct uet_sec_sd sdkdb[UET_SEC_MAX_SD];
struct uet_sec_port_stats uet_sec_port_stats;

char *uet_sec_label1 = "U1";
char *uet_sec_label2 = "U2";

/************************************************************************/
/* FIXME: Default fields used for the fixed SD... not yet configurable! */
/************************************************************************/

/* key generation: `dd if=/dev/urandom ibs=32 count=1 | xxd -i -c 8` */

/* The key pool. Slots 0/1 are the original two AN keys (used directly and
 * indexed by AN, when rotation is off). Slots 2/3 extend the pool to
 * UET_SEC_ROT_N so the AN key-rotation (SDME stand-in) has 4 keys to cycle
 * through.
 */
static uint8_t def_key[UET_SEC_ROT_N][UET_SEC_KDF_GEN_SIZE] = {
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
	{
		0x3b, 0x8f, 0x0d, 0x6a, 0xe4, 0x27, 0x91, 0xac,
		0x55, 0x1e, 0xc0, 0x74, 0x2d, 0xb9, 0x66, 0x08,
		0xf1, 0x4c, 0xaa, 0x93, 0x70, 0xd5, 0x3e, 0x82,
		0x19, 0xbb, 0x6f, 0x24, 0xce, 0x07, 0x41, 0x98,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	},
	{
		0xa7, 0x62, 0xf5, 0x11, 0x8c, 0x4b, 0x30, 0xde,
		0x09, 0x9a, 0x77, 0xe3, 0x5f, 0x21, 0xb8, 0xc6,
		0x74, 0x0e, 0xd2, 0x46, 0x99, 0x2b, 0xa5, 0x18,
		0xed, 0x53, 0x81, 0x6c, 0x3a, 0xf0, 0x27, 0xbd,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	},
};

/* Per-generation wrap-mix constant. When a pool slot recurs (every
 * UET_SEC_ROT_N rotations) its raw bytes would repeat. Folding in a
 * generation-derived mix built from this constant yields fresh key material
 * on every reuse. Compiled in, so both peers derive the identical effective
 * key.
 */
static const uint8_t uet_sec_wrap_const[UET_SEC_KEY_SIZE] = {
	0x9e, 0x37, 0x79, 0xb9, 0x7f, 0x4a, 0x7c, 0x15,
	0xf3, 0x9c, 0xc0, 0x60, 0x5c, 0xed, 0xc8, 0x34,
	0x10, 0x82, 0x27, 0x6b, 0xf3, 0xa2, 0x72, 0x51,
	0xec, 0xdd, 0x74, 0x35, 0x21, 0xf8, 0x8e, 0xa3,
};

#define DEF_SDI         1
/* Derive a new (implicit) rekey every 2^DEF_REKEY_SHIFT = 256 packets so the
 * automatic KDF rekey is exercised between the (much slower) AN key rotations.
 */
#define DEF_REKEY_MASK  0x000000000000FF00UL
#define DEF_REKEY_SHIFT 8
#define DEF_COFF        12 /* sizeof security header, +4 if using SSI */

#define DEF_RX_MAX_EPOCH_LIFETIME  16
#define DEF_AUTH_FAIL_THRESHOLD    1000
#define DEF_INVOKE_FATAL_THRESHOLD UET_SEC_TSC_MASK /* 48-bit counter max */

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

struct uet_sec_sd *uet_sec_sd_get(uint32_t sdi)
{
	if (sdi >= UET_SEC_MAX_SD)
		return NULL;

	return &sdkdb[sdi];
}

uint32_t uet_sec_sd_get_ini_start_psn(uint32_t sdi)
{
	struct uet_sec_sd *sd = uet_sec_sd_get(sdi);

	return (sd != NULL) ? sd->ini_start_psn : 0;
}

void uet_sec_sd_set_ini_start_psn(uint32_t sdi, uint32_t psn)
{
	struct uet_sec_sd *sd = uet_sec_sd_get(sdi);

	if (sd != NULL)
		sd->ini_start_psn = psn;
}

uint32_t uet_sec_sd_get_tgt_start_psn(uint32_t sdi)
{
	struct uet_sec_sd *sd = uet_sec_sd_get(sdi);

	return (sd != NULL) ? sd->tgt_start_psn : 0;
}

void uet_sec_sd_set_tgt_start_psn(uint32_t sdi, uint32_t psn)
{
	struct uet_sec_sd *sd = uet_sec_sd_get(sdi);

	if (sd != NULL)
		sd->tgt_start_psn = psn;
}

/* Current absolute rotation index (bucket number), and optionally the ms
 * elapsed time into that bucket. This is just division/modulo, the quotient
 * is the rotation index, the remainder is how far we are into the interval
 * (used by the make-before-break window).
 */
static uint64_t uet_sec_rot_now(uint64_t *into_ms)
{
	time_t now_ms = 0;
	uint64_t rot;

	uet_gettime(&now_ms); /* absolute wall-clock ms (CLOCK_REALTIME) */

	/* bucket index, which UET_SEC_ROT_INTERVAL_MS window we are in now */
	rot = ((uint64_t)now_ms / UET_SEC_ROT_INTERVAL_MS);

	if (into_ms != NULL) {
		/* time ms into the current window */
		*into_ms = ((uint64_t)now_ms -
			    (rot * UET_SEC_ROT_INTERVAL_MS));
	}

	return rot;
}

/* Generation-derived 32-byte wrap mix: deterministic (same gen + compiled in
 * key constant on both peers) and distinct per generation. A recurring pool
 * slot produces different key material each cycle. Every byte of gen is
 * folded in so consecutive generations differ.
 */
static void uet_sec_wrap_mix(uint64_t gen,
			     uint8_t *mix)
{
	int i;

	for (i = 0; i < UET_SEC_KEY_SIZE; i++) {
		mix[i] = /* fixed whitening constant */
			 (uet_sec_wrap_const[i] ^
			 /* spread gen's 8 bytes over the mix */
			  (uint8_t)(gen >> ((i & 7) * 8)) ^
			 /* per-byte ramp, flips on every gen++ */
			  (uint8_t)(gen + (uint64_t)i));
	}
}

uint8_t uet_sec_sd_tx_an(struct uet_sec_sd *sd)
{
	if (!sd->rotation_enabled)
		return sd->an;

	/* active association number is the low bit of the rotation index */
	return (uint8_t)(uet_sec_rot_now(NULL) & 1);
}

void uet_sec_sd_tx_rotate(struct uet_sec_sd *sd)
{
	uint64_t rot;

	if (!sd->rotation_enabled)
		return;

	rot = uet_sec_rot_now(NULL);

	/* edge-detect a bucket change since the last Tx packet */
	if (rot != sd->tx_rot) {
		/* crossed a rotation boundary = AN/key change */
		sd->tx_rot     = rot;
		sd->tx_counter = 0;
		sd->epoch      = 0;
	}
}

/* Generate one effective key, effective_key = pool[slot] XOR wrap_mix(gen),
 * into eff_key[*][which] for both families (slot = r mod N, gen = r / N). The
 * wrap mix is gen-only so it is computed once and applied to both families.
 */
static void uet_sec_sd_gen_key(struct uet_sec_sd *sd,
			       int64_t r,
			       int which)
{
	uint8_t mix[UET_SEC_KEY_SIZE];
	int slot = (int)(r & (UET_SEC_ROT_N - 1));
	uint64_t gen = (uint64_t)(r / UET_SEC_ROT_N);
	int fam, i;

	uet_sec_wrap_mix(gen, mix);

	for (fam = 0; fam < 2; fam++) {
		memcpy(sd->eff_key[fam][which], sd->key[fam][slot],
		       UET_SEC_KDF_GEN_SIZE);
		for (i = 0; i < UET_SEC_KEY_SIZE; i++)
			sd->eff_key[fam][which][i] ^= mix[i];
	}
}

/* Refresh the previous/current/next effective-key window for rotation 'rot'.
 * Common case (rot advanced by one): shift the window down (prev<-cur,
 * cur<-next) and generate only the new 'next'. First build or a multi-bucket
 * gap rebuilds all three. Runs only when rot changes (~once per interval).
 */
static void uet_sec_sd_refresh_keys(struct uet_sec_sd *sd, uint64_t rot)
{
	int fam;

	if (rot == (sd->cache_rot + 1)) {
		for (fam = 0; fam < 2; fam++) {
			memcpy(sd->eff_key[fam][UET_SEC_KEY_PREV],
			       sd->eff_key[fam][UET_SEC_KEY_CUR],
			       UET_SEC_KDF_GEN_SIZE);
			memcpy(sd->eff_key[fam][UET_SEC_KEY_CUR],
			       sd->eff_key[fam][UET_SEC_KEY_NEXT],
			       UET_SEC_KDF_GEN_SIZE);
		}
		uet_sec_sd_gen_key(sd, (int64_t)rot + 1, UET_SEC_KEY_NEXT);
	} else {
		uet_sec_sd_gen_key(sd, (int64_t)rot - 1, UET_SEC_KEY_PREV);
		uet_sec_sd_gen_key(sd, (int64_t)rot,     UET_SEC_KEY_CUR);
		uet_sec_sd_gen_key(sd, (int64_t)rot + 1, UET_SEC_KEY_NEXT);
	}

	sd->cache_rot = rot;
}

uint8_t *uet_sec_sd_key(struct uet_sec_sd *sd,
			int fam,
			uint8_t an)
{
	uint64_t rot, into;
	int which;

	if (!sd->rotation_enabled)
		return sd->key[fam][an];

	rot = uet_sec_rot_now(&into);

	/* (re)build the effective-key window only when the rotation advances */
	if (rot != sd->cache_rot)
		uet_sec_sd_refresh_keys(sd, rot);

	/* Make-before-break selection. The active slot (an=rot&1) uses the
	 * current key. The non-active slot uses the retiring previous key
	 * during the guard window (a skew-behind peer), then the pre-loaded
	 * next key (a skew-ahead peer). Returns a pointer into the cache.
	 */
	if (an == (uint8_t)(rot & 1))
		which = UET_SEC_KEY_CUR;  /* AN matches our bucket */
	else if (into < UET_SEC_ROT_GUARD_MS)
		which = UET_SEC_KEY_PREV; /* just after a boundary */
	else
		which = UET_SEC_KEY_NEXT; /* peer rotated ahead */

	return sd->eff_key[fam][which];
}

/* Derive the client-side server-mode keys for one address family. Each
 * family's keys are derived from that family's local address (IPv4) or the
 * SSI, so a dual-stack SD derives both families' key material independently
 * into sd->key[fam][an].
 */
static void uet_sec_derive_family_keys(struct uet_sec_sd *sd,
				       int fam,
				       const struct uet_fa *local_ip)
{
	uint8_t derived_key[UET_SEC_KDF_GEN_SIZE];
	uint8_t small_context[UET_SEC_SMALL_CTX_SIZE];
	uint8_t large_context[UET_SEC_LARGE_CTX_SIZE];
	char *client_ssi;
	uint32_t tmp_val;
	int an;
	uint16_t epoch = htons(sd->epoch);

	for (an = 0; an < 2; an++) {
		if (fam == UET_SEC_FAM_V6) {
			memset(large_context, 0, sizeof(large_context));
			memcpy((large_context + 4), (uint8_t *)&epoch, 2);
			memcpy((large_context + 10), local_ip->v6, 16);

			kdf_ctr_cmac_aes(sd->key[fam][an],
					 (UET_SEC_KEY_SIZE * 8),
					 UET_SEC_CTR_SIZE,
					 (uint8_t *)uet_sec_label2,
					 strlen(uet_sec_label2), /* ignore delimiter */
					 large_context,
					 UET_SEC_LARGE_CTX_SIZE,
					 derived_key,
					 (UET_SEC_KDF_GEN_SIZE * 8));
		} else {
			memset(small_context, 0, sizeof(small_context));
			memcpy(small_context, (uint8_t *)&epoch, 2);
			/* use SSI if available, otherwise use IPv4 */
			client_ssi = getenv(UET_SEC_SSI);
			tmp_val = (client_ssi)
				? htonl(strtoul(client_ssi, NULL, 10))
				: htonl(local_ip->v4);
			memcpy((small_context + 6), (uint8_t *)&tmp_val, 4);

			kdf_ctr_cmac_aes(sd->key[fam][an],
					 (UET_SEC_KEY_SIZE * 8),
					 UET_SEC_CTR_SIZE,
					 (uint8_t *)uet_sec_label2,
					 strlen(uet_sec_label2), /* ignore delimiter */
					 small_context,
					 UET_SEC_SMALL_CTX_SIZE,
					 derived_key,
					 (UET_SEC_KDF_GEN_SIZE * 8));
		}

		memcpy(sd->key[fam][an], derived_key, UET_SEC_KDF_GEN_SIZE);
	}
}

static int uet_sec_init_sd(uint32_t sdi,
			   uet_sec_mode_t mode,
			   bool use_ssi,
			   bool rekey,
			   struct uet_nic *nic)
{
	struct uet_sec_sd *sd;

	sd = uet_sec_sd_get(sdi);
	if (sd == NULL) {
		UET_TSS_ERR("invalid SDI %u\n", sdi);
		return -EINVAL;
	}

	memset(sd, 0, sizeof(*sd));

	sd->enabled     = true;
	sd->sdi         = sdi;
	sd->mode        = mode;
	sd->use_ssi     = use_ssi;
	sd->rekey       = rekey;
	sd->rekey_mask  = DEF_REKEY_MASK;
	sd->rekey_shift = DEF_REKEY_SHIFT;
	sd->coff        = (use_ssi) ? (DEF_COFF + 4) : DEF_COFF;
	sd->alg         = UET_SEC_ALG_AES_GCM_256;
	sd->epoch       = 0;
	sd->an          = 0;
	sd->tx_counter  = 0;

	sd->epoch_based_rejection  = true; /* fixed as default */
	sd->rx_max_epoch_lifetime  = DEF_RX_MAX_EPOCH_LIFETIME;
	sd->auth_fail_threshold    = DEF_AUTH_FAIL_THRESHOLD;
	sd->invoke_fatal_threshold = DEF_INVOKE_FATAL_THRESHOLD;
	sd->domain_dropping        = false;

	/* AN key rotation is gated per run. Both peers rotate off the shared
	 * wall clock (no signaling). Not supported in server mode (its client
	 * keys are KDF-derived).
	 */

	if ((getenv(UET_SEC_KEY_ROTATION) != NULL) &&
	    (mode == UET_SEC_MODE_SERVER)) {
		UET_TSS_ERR("SDI %u AN key rotation not supported in "
			     "server mode", sdi);
		return -EINVAL;
	}

	sd->rotation_enabled = (getenv(UET_SEC_KEY_ROTATION) != NULL);
	sd->tx_rot = 0;

	if (sd->rotation_enabled) {
		/* seed tx_rot with the current rotation index */
		sd->tx_rot = uet_sec_rot_now(NULL);

		UET_TSS_INFO("SDI %u AN key rotation enabled "
			     "(%u keys, %u ms interval, %u ms guard)",
			     sdi, UET_SEC_ROT_N, UET_SEC_ROT_INTERVAL_MS,
			     UET_SEC_ROT_GUARD_MS);
	}

	/* seed both families with the default key pool */
	memcpy(sd->key[UET_SEC_FAM_V4], def_key, sizeof(def_key));
	memcpy(sd->key[UET_SEC_FAM_V6], def_key, sizeof(def_key));

	/* IPv6 with direct or client/server mode requires the SSI. Under
	 * dual-stack this is a per-family limitation, not a fatal error: warn
	 * and leave IPv6 security unavailable so IPv4 is unaffected.
	 */
	if (nic->has_ipv6 && !use_ssi &&
	    ((mode == UET_SEC_MODE_DIRECT) || (mode == UET_SEC_MODE_SERVER)))
		UET_TSS_WARN("IPv6 secure mode requires SSI; IPv6 security "
			     "unavailable (IPv4 unaffected)\n");

	/* For the client side of server mode, do the KDFs now (no exchange).
	 * Normally for client/server mode the server key is hidden on the
	 * server and there is an exchange where the server gives each client
	 * a key to use in direct mode which is a derivation from the server
	 * key using the client's SSI.
	 *
	 * Dual-stack: derive each available family's keys independently from
	 * that family's local address. IPv6 requires the SSI.
	 */
	if ((mode == UET_SEC_MODE_SERVER) && !getenv(UET_SEC_SERVER)) {
		if (nic->has_ipv4) {
			struct uet_fa fa;
			memset(&fa, 0, sizeof(fa));
			fa.v4 = nic->ipv4_addr;
			uet_sec_derive_family_keys(sd, UET_SEC_FAM_V4, &fa);
		}

		if (nic->has_ipv6 && use_ssi) {
			struct uet_fa fa;
			memset(&fa, 0, sizeof(fa));
			memcpy(fa.v6, nic->ipv6_addr, 16);
			uet_sec_derive_family_keys(sd, UET_SEC_FAM_V6, &fa);
		}
	}

	return 0;
}

int uet_sec_init(struct uet_nic *nic)
{
	char *sec_mode, *sec_ssi;
	int i, rc;

	memset(sdkdb, 0, sizeof(sdkdb));
	memset(&uet_sec_port_stats, 0, sizeof(uet_sec_port_stats));

	for (i = 0; i < UET_SEC_MAX_SD; i++)
		sdkdb[i].enabled = false;

	sec_mode = getenv(UET_SEC_MODE);
	sec_ssi  = getenv(UET_SEC_SSI);

	if (sec_mode == NULL)
		return 0;

	if (strcmp(sec_mode, "direct") == 0) {

		rc = uet_sec_init_sd(DEF_SDI, UET_SEC_MODE_DIRECT,
				     (sec_ssi != NULL), false, nic);

	} else if (strcmp(sec_mode, "cluster") == 0) {

		rc = uet_sec_init_sd(DEF_SDI, UET_SEC_MODE_CLUSTER,
				     (sec_ssi != NULL), true, nic);

	} else if (strcmp(sec_mode, "server") == 0) {

		/* this implementation requires the SSI for IPv4 and IPv6 */

		if (sec_ssi == NULL) {
			UET_TSS_ERR("UET_SEC_SSI required for server mode");
			return -EINVAL;
		}

		if (getenv(UET_SEC_SERVER) && !getenv(UET_SEC_CLIENT_SSI)) {
			UET_TSS_ERR("UET_SEC_CLIENT_SSI required on server "
				    "for server mode");
			return -EINVAL;
		}

		rc = uet_sec_init_sd(DEF_SDI, UET_SEC_MODE_SERVER,
				     true, false, nic);

	} else {

		UET_TSS_ERR("invalid UET_SEC_MODE environment variable");
		return -EINVAL;

	}

	return rc;
}

void uet_sec_dump_stats(void)
{
	struct uet_sec_sd *sd;
	uint32_t sdi;

	for (sdi = 0; sdi < UET_SEC_MAX_SD; sdi++) {
		sd = &sdkdb[sdi];
		if (!sd->enabled)
			continue;

		UET_TSS_INFO("SDI %u stats:", sdi);
		UET_TSS_INFO("    %-30s : %llu", "in_auth_pkts",
			     (unsigned long long)sd->stats.in_auth_pkts);
		UET_TSS_INFO("    %-30s : %llu", "in_auth_fail_pkts",
			     (unsigned long long)sd->stats.in_auth_fail_pkts);
		UET_TSS_INFO("    %-30s : %llu", "in_invalid",
			     (unsigned long long)sd->stats.in_invalid);
		UET_TSS_INFO("    %-30s : %llu", "in_invalid_sa",
			     (unsigned long long)sd->stats.in_invalid_sa);
		UET_TSS_INFO("    %-30s : %llu", "in_late_pkts",
			     (unsigned long long)sd->stats.in_late_pkts);
		UET_TSS_INFO("    %-30s : %llu", "out_invoke_fail",
			     (unsigned long long)sd->stats.out_invoke_fail);
		UET_TSS_INFO("    %-30s : %llu", "out_auth_pkts",
			     (unsigned long long)sd->stats.out_auth_pkts);
		UET_TSS_INFO("    %-30s : %llu", "in_binding_failure_pkts",
			     (unsigned long long)sd->stats.in_binding_failure_pkts);
		UET_TSS_INFO("    %-30s : %s", "domain_dropping",
			     sd->domain_dropping ? "yes" : "no");
	}

	UET_TSS_INFO("PORT stats:");
	UET_TSS_INFO("    %-30s : %llu", "in_errored_pkts",
		     (unsigned long long)uet_sec_port_stats.in_errored_pkts);
	UET_TSS_INFO("    %-30s : %llu", "out_errored_pkts",
		     (unsigned long long)uet_sec_port_stats.out_errored_pkts);
	UET_TSS_INFO("    %-30s : %llu", "in_rx_encryption_bypass_pkts",
		     (unsigned long long)uet_sec_port_stats.in_rx_encryption_bypass_pkts);
	UET_TSS_INFO("    %-30s : %llu", "out_rx_encryption_bypass_pkts",
		     (unsigned long long)uet_sec_port_stats.out_rx_encryption_bypass_pkts);
}

void uet_sec_finalize(void)
{
	uet_sec_dump_stats();
}

