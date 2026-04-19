/*
 * Copyright (c) 2026, Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

/*
 * Impairment Shim (imp_shim)
 *
 * Tx queuing module layered between the PDS/TSS and the NIC shim. Supports
 * random packet dropping and random packet delaying to enable testing
 * of out-of-order packet processing with RUD.
 *
 * The transmit thread processes Tx queues (i.e., planes) in random or
 * round-robin fashion, pulling packets from the front of each queue and
 * sending them to the NIC shim when the current time >= the packet's
 * calculated transmit time.
 *
 * Enabled via the UET_IMPAIRMENT_SHIM environment variable which points
 * to a TOML configuration file. See the example 'imp_shim.toml' file for
 * configuration details.
 */

#ifndef _IMP_SHIM_H_
#define _IMP_SHIM_H_

#include <stdint.h>
#include <stdbool.h>

#include "uet_nic.h"

#define UET_IMPAIRMENT_SHIM "UET_IMPAIRMENT_SHIM"

/*
 * Initialize the impairment shim.
 *
 * Reads the TOML configuration file specified by the UET_IMPAIRMENT_SHIM
 * environment variable, allocates Tx queues, and spawns the transmit thread.
 *
 * params:
 *   nic - ptr to the NIC control block used for packet transmission
 *
 * returns:
 *   0 on success
 *   negative value corresponding to errno on error
 */
int imp_shim_init(struct uet_nic *nic);

/*
 * Finalize the impairment shim.
 *
 * Stops the transmit thread, drains and frees all queues, and releases
 * all resources.
 */
void imp_shim_finalize(void);

/*
 * Transmit a packet through the impairment shim.
 *
 * The packet is either randomly dropped or enqueued with a random delay.
 * The transmit thread will send the packet to the NIC shim when the
 * calculated transmit time has been reached.
 *
 * params:
 *   nic      - ptr to the NIC control block
 *   pkt      - ptr to the packet buffer
 *   iphdr    - ptr to the IP header within the packet
 *   pkt_size - total size of the packet in bytes
 *
 * returns:
 *   0 on success
 *   negative value corresponding to errno on error
 */
int imp_shim_tx_pkt(struct uet_nic *nic,
		    void *pkt,
		    void *iphdr,
		    size_t pkt_size);

/*
 * Returns true if the impairment shim is enabled (i.e., UET_IMPAIRMENT_SHIM
 * environment variable is set and imp_shim_init() has already been called
 * successfully).
 */
bool imp_shim_is_enabled(void);

#endif /* _IMP_SHIM_H_ */

