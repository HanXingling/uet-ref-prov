/*
 * Copyright (c) 2024, Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

#include <stdbool.h>

#include "uet_api_private.h"

/*
 * parse and validate received packet as follows:
 *   - validate dest mac address
 *   - validate ethertype
 *   - validate ip header version
 *   - validate ip header len
 *   - validate ip header total length
 *   - validate ip header checksum
 *   - validate ip protocol
 *   - validate uet packet type
 *
 * parms:
 *      uet           - ptr to uet instance struct
 *      pkt           - ptr to received packet
 *      pkt_size      - size of received packet in bytes
 *      pkt_is_ack    - set to true when packet is an ack packet
 *      pkt_is_rd_rsp - set to true when packet is a read response packet
 *      pkt_is_ctrl   - set to true when packet is a control packet
 *
 * returns:
 *      true  => packet passed validation checks
 *      false => packet did not pass validation checks
 */
bool uet_pds_rx_pkt_chk(struct uet_instance *uet,
			uint8_t *pkt,
			size_t pkt_size,
			bool *pkt_is_ack,
			bool *pkt_is_rd_rsp,
			bool *pkt_is_ctrl);

