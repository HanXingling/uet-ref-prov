/*
 * Copyright (c) 2024,2025,2026 Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

#ifndef UET_SEC_SD_H
#define UET_SEC_SD_H

#include <stdint.h>
#include <stdbool.h>

#include "uet_api_private.h"

/* Secure-domain configuration env vars (SDME stand-in inputs). */
#define UET_SEC_MODE       "UET_SEC_MODE"
#define UET_SEC_SSI        "UET_SEC_SSI"
#define UET_SEC_SERVER     "UET_SEC_SERVER"
#define UET_SEC_CLIENT_SSI "UET_SEC_CLIENT_SSI"

/* Secure-domain database (SDKDB) and its lifecycle.
 *
 * This module is the reference app's stand-in for an SDME (Security Domain
 * Management Entity): it owns the SD table, the key material, the per-SD/port
 * statistics, and the AN key-rotation scheduler. Real deployments drive all of
 * this out of band; here it is compiled in and (for rotation) wall-clock
 * driven. The spec-defined per-packet crypto core (header build, encrypt,
 * decrypt) lives in uet_sec.c and consumes the services declared below.
 */

#define UET_SEC_MAX_SD         8
#define UET_SEC_FAM_V4         0
#define UET_SEC_FAM_V6         1
#define UET_SEC_FAM(is_ipv6)   ((is_ipv6) ? UET_SEC_FAM_V6 : UET_SEC_FAM_V4)
#define UET_SEC_KEY_SIZE       32
#define UET_SEC_KDF_GEN_SIZE   44
#define UET_SEC_CTR_SIZE       8
#define UET_SEC_SMALL_CTX_SIZE 10
#define UET_SEC_LARGE_CTX_SIZE 26

/* AN key rotation: wall-clock driven (SDME stand-in!)
 *
 * Gated per run via an env knob so the existing short secured tests are
 * unaffected. Both peers derive the rotation index from the absolute wall
 * clock time, so they stay synchronized with zero signaling and no
 * dependence on process start time.
 */
#define UET_SEC_KEY_ROTATION    "UET_SEC_KEY_ROTATION" /* env gate */
#define UET_SEC_ROT_N           4     /* rotating key pool (power of 2) */
#define UET_SEC_ROT_INTERVAL_MS 10000 /* rotation interval (wall clock) */
#define UET_SEC_ROT_GUARD_MS    2000  /* make-before-break guard window */

/* For key rotation, at any rotation only three effective keys are live,
 * previous/current/next (r = rot-1/rot/rot+1). The SD caches exactly these,
 * indexed by this enum.
 */
enum {
	UET_SEC_KEY_PREV = 0,
	UET_SEC_KEY_CUR,
	UET_SEC_KEY_NEXT,
	UET_SEC_KEY_SLOTS
};

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

struct uet_sec_sd_stats {
	uint64_t in_auth_pkts;
	uint64_t in_auth_fail_pkts;
	uint64_t in_invalid;
	uint64_t in_invalid_sa;
	uint64_t in_late_pkts;
	uint64_t out_invoke_fail;
	uint64_t out_auth_pkts;
	uint64_t in_binding_failure_pkts;
};

struct uet_sec_port_stats {
	uint64_t in_errored_pkts;
	uint64_t out_errored_pkts;
	uint64_t in_rx_encryption_bypass_pkts;
	uint64_t out_rx_encryption_bypass_pkts;
};

struct uet_sec_sd {
	bool           enabled;
	uint32_t       sdi;
	uet_sec_mode_t mode;
	bool           use_ssi;
	bool           rekey;
	uint64_t       rekey_mask;
	uint8_t        rekey_shift;
	uint16_t       coff;
	uet_sec_alg_t  alg;
	/* Key epoch: starts at 0, reset to 0 on key rotation, only advanced
	 * by an SDME on a FEP leave/rejoin.
	 * NOTE: No SDME or rejoin modeled, it stays 0 for the whole run.
	 */
	uint16_t       epoch;
	uint8_t        an;
	/* Strictly-increasing 48b packet Tx counter. Reset to 0 on an
	 * association (AN/key) change — see uet_sec_sd_tx_rotate.
	 */
	uint64_t       tx_counter;
	/* Epoch-based rejection
	 * NOTE: Kept for spec completeness but dormant here as the epoch
	 * is static (0).
	 */
	bool           epoch_based_rejection;
	uint16_t       rx_max_epoch_lifetime;
	/* Invoke/auth-fail limits. The domain_dropping field latches once
	 * in_auth_fail_pkts exceeds auth_fail_threshold, after which ALL
	 * packets for the SD are dropped.
	 */
	uint64_t       invoke_fatal_threshold;
	uint64_t       auth_fail_threshold;
	bool           domain_dropping;
	struct uet_sec_sd_stats stats; /* per-SD stats */
	/* AN key rotation (SDME stand-in). When enabled, the active AN, the
	 * epoch/counter, and the key are all derived from the shared
	 * wall clock.
	 */
	bool           rotation_enabled;
	uint64_t       tx_rot;
	/* [family-ipv4/ipv6][slot] key pool.
	 * NOTE: Non-rotation uses slots 0/1 (indexed by AN). Rotation cycles
	 * over all UET_SEC_ROT_N slots off the wall clock.
	 */
	uint8_t        key[2][UET_SEC_ROT_N][UET_SEC_KDF_GEN_SIZE];
	/* Effective-key cache. When key rotation is enabled, eff_key holds
	 * the previous/current/next effective keys per address family, valid
	 * for cache_rot. When rot advances by one, the keys shift down and
	 * only the new 'next' is generated. cache_rot == 0 means unbuilt.
	 */
	uint64_t       cache_rot;
	uint8_t        eff_key[2][UET_SEC_KEY_SLOTS][UET_SEC_KDF_GEN_SIZE];
};

/* KDF labels — shared by the crypto core (enc/dec) and server-mode key
 * derivation.
 */
extern char *uet_sec_label1;
extern char *uet_sec_label2;

/* Per-port stats. Defined by this module and incremented from the crypto
 * core for bad-SDI / encryption-bypass events.
 */
extern struct uet_sec_port_stats uet_sec_port_stats;

/* Initialize the security domain(s). Dual-stack: the SD holds per-family key
 * material (keyed on each of the NIC's local v4/v6 addresses) selected per
 * packet at enc/dec time, so a single wire SDI serves both families.
 */
int uet_sec_init(struct uet_nic *nic);

/* Teardown the security domain(s). */
void uet_sec_finalize(void);

/* Dump per-SD and per-port security counters. */
void uet_sec_dump_stats(void);

/* SDKDB lookup: returns the SD for an sdi, or NULL if out of range. */
struct uet_sec_sd *uet_sec_sd_get(uint32_t sdi);

/* Active Tx AN right now: clock-derived when rotation is on, else sd->an. */
uint8_t uet_sec_sd_tx_an(struct uet_sec_sd *sd);

/* Tx-side association-change bookkeeping. On a rotation boundary (AN/key
 * change) this resets the per-packet counter and epoch to 0. No-op when
 * rotation is off. Call once per transmitted packet before reading the
 * counter/epoch.
 */
void uet_sec_sd_tx_rotate(struct uet_sec_sd *sd);

/* Effective key for (family, an). When rotation is on, selects the pool slot
 * from the shared clock + an (make-before-break, both skew directions) and
 * folds in the per-generation wrap mix; otherwise returns sd->key[fam][an].
 * The returned pointer is valid until the next call (single-threaded path).
 */
uint8_t *uet_sec_sd_key(struct uet_sec_sd *sd, int fam, uint8_t an);

#endif /* UET_SEC_SD_H */

