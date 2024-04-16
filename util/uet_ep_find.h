/*
 * Copyright (c) 2024, Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

#include <stdbool.h>

#include "uet_api_private.h"

/* find the endpoint a packet is destined for */
struct uet_ep *uet_pds_find_dst_ep(struct uet_instance *uet,
				   union uet_pkt *pkt,
				   bool pkt_is_ack,
				   bool pkt_is_rd_rsp,
				   struct uet_msg_match_info *match_info);

