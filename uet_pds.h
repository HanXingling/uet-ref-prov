/*
 * Copyright (c) 2024, Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

/* Definitions for SES-PDS APIs */

#ifndef _UET_PDS_H_
#define _UET_PDS_H_

#include <stdint.h>
#include <stdbool.h>

#include <ofi_list.h>

#include "uet_pkt_hdr.h"
#include "uet_api.h"

#define UET_DEFAULT_TX_TIMEOUT     100  /* in millisecs */
#define UET_DEFAULT_MAX_TX_RETRIES 19
#define UET_DEFAULT_MSL            2000 /* max seg lifetime in msecs */

struct uet_ep;     /* forward references */
struct uet_instance;
struct uet_av_entry;
struct uet_tx_desc;

/* pds delivery modes */
typedef enum {
	UET_PDS_MODE_UUD,
	UET_PDS_MODE_ROD,
	UET_PDS_MODE_RUD,
	UET_PDS_MODE_RUDI,
} uet_pds_mode_t;

/* pds error codes */
typedef enum {
	UET_PDS_ERR_NONE,
} uet_pds_err_code_t;

#define UET_PDS_FLAG_NONE 0

/* pds tx flags */
typedef enum {
	UET_PDS_FLAG_SOM        = 0x01, /* start of message */
	UET_PDS_FLAG_EOM        = 0x02, /* end of message */
	UET_PDS_FLAG_EAGER_REQ  = 0x04, /* request eager length predition */
	UET_PDS_FLAG_RETRANSMIT = 0x08, /* retransmit of pkt  */
} uet_pds_tx_flags_t;

/* pds tx som flags */
typedef enum {
	UET_PDS_FLAG_PDC_ID_V = 0x01,  /* pdc id valid */
	UET_PDS_FLAG_BUSY     = 0x02,  /* pdc could not accept pkt */
} uet_pds_tx_som_flags_t;

/* info that pds may need on transmit requests                           */
/*   - the info is only needed when read data is being transmitted       */
/*   - pds provides the info to ses when the read request is received    */
/*   - ses echoes the data back to pds when the read data is transmitted */
struct uet_pds_info {
	uint32_t opsn;  /* original psn from initiator of req */
	uint16_t pdcid;
};

/* function ptr's for pds upcalls to ses */
typedef void *uet_pkt_handle_t;

struct uet_pds_to_ses_funcs {
	int (*build_ses_hdr)(uet_pkt_handle_t tx_pkt_handle, size_t pkt_len,
			     void *ses_hdr, uint32_t eager_len);
	int (*rx_req)(uet_pkt_handle_t rx_pkt_handle, struct uet_ep *uet_ep,
		      void *pkt, size_t pkt_len, struct uet_pds_info pds_info,
		      uet_next_hdr_t req_next_hdr, uet_next_hdr_t *rsp_next_hdr,
		      void *rsp_ses_hdr, size_t *rsp_ses_hdr_len,
		      bool *gtd_del);
	int (*rx_rsp)(uet_pkt_handle_t tx_pkt_handle, void *rsp,
		      size_t rsp_len);
	int (*pds_err)(uet_pkt_handle_t tx_pkt_handle,
		       uet_pds_err_code_t reason);
};

/* pds control block structure - embedded in uet_instance struct */
struct uet_pds {
	struct uet_pds_to_ses_funcs upcall;       /* ptr's to ses functions */
	time_t tx_timeout;               /* retry after this amount of time */
	int    max_tx_retries;             /* max tx retries before failing */
	time_t msl;                    /* max segment lifetime in millisecs */
	uint8_t ack_ip_tos;                             /* ip tos for ack's */
};

/* pds transmit state */
struct uet_pds_tx_state {
	bool tx_active;      /* transmit in progress */
	uint32_t psn;        /* next pkt sequence number */
	time_t start_time;   /* tx start time for detecting timeout */
	int    retry_cnt;    /* number of tx retransmissions */
	struct {             /* parms needed for pkt retransmit */
		uet_pkt_handle_t tx_pkt_handle;
		uet_addr_handle_t dst_addr_handle;
		uet_pds_mode_t mode;
		uet_pds_tx_flags_t flags;
		bool pds_info_valid;
		struct uet_pds_info pds_info;
		uint16_t msg_id;
		uet_next_hdr_t next_hdr;
		void *pkt;
		size_t pkt_len;
		bool dma_rdy;
	} pkt_parms;
};

/*
 * overlay struct for fields in pds headers
 *
 * the stop-and-go reliability layer is simpler if the sequence number
 * state is maintained between libfabric endpoints (rather than between
 * FEPs as is done in the real pds reliability layer), so to enable that
 * a couple of fields in the pds headers are repurposed as follows:
 *
 *   - the spdcid field is repurposed to carry the pid_on_fep of the
 *     source endpoint that sent the request
 *   - the dpdcid field is repurposed to carry the index of the
 *     source endpoint that sent the request
 *
 * the fields are repurposed in both the pds request and the pds ack headers
 */
struct UET_PACKED uet_pds_hdr_overlay {
	uint16_t pid_on_fep;
	uint16_t index;
};

/* pds ack state */
struct uet_pds_ack_state {
	struct dlist_entry list_entry; /* for list of ack's sent */
	time_t ack_time;               /* time ack was sent */
	struct uet_std_rsp_pkt ack;    /* ack packet that was sent */
};

/* pds state structure                                                 */
/*   - embedded in uet_ep struct                                       */
/*   - will be removed from uet_ep struct when real pds is implemented */
struct uet_pds_state {
	struct dlist_entry ack_state_list_head;
	struct uet_pds_tx_state tx;
};

/*********************************************************************
 * SES-PDS APIs
 *********************************************************************/

/*
 * initialize pds resources for uet_instance
 *
 * parms:
 *      uet - ptr to uet instance struct that pds is being initialized for
 *
 * returns:
 *      FI_SUCCESS on success
 *      negative value corresponding to fabric errno on error
 */
int uet_pds_initialize(struct uet_instance *uet);

/*
 * free pds resources for uet instance
 *
 * parms:
 *      uet_dom - ptr to uet instance struct that pds resources are
 *                associated with
 */
void uet_pds_finalize(struct uet_instance *uet);

/*
 * initialize pds resources for endpoint
 *
 * parms:
 *      uet_ep - ptr to uet endpoint struct that pds resources are
 *               being initialized for
 *
 * returns:
 *      FI_SUCCESS on success
 *      negative value corresponding to fabric errno on error
 *
 * NOTE: this function will be removed when real pds is implemented,
 *       since pds resources will no longer be associated with endpoints
 */
int uet_pds_ep_initialize(struct uet_ep *uet_ep);

/*
 * free pds resources for endpoint
 *
 * parms:
 *      uet_ep - ptr to uet endpoint struct that pds resources are
 *               associated with
 *
 * NOTE: this function will be removed when real pds is implemented,
 *       since pds resources will no longer be associated with endpoints
 */
void uet_pds_ep_finalize(struct uet_ep *uet_ep);

/*
 * initiate pds transmission of packet
 *
 * parms:
 *      tx_pkt_handle   - handle for packet to be transmitted,
 *                        assigned by caller
 *      uet_ep          - ptr to uet endpoint struct that packet is
 *                        associated with
 *      dst_addr_handle - handle of uet addr that packet is destined for
 *      mode            - packet delivery mode to be used for packet tx
 *      flags           - flags for tx operation
 *        UET_PDS_FLAG_SOM - pkt is start of message
 *        UET_PDS_FLAG_EOM - pkt is end of message
 *        UET_PDS_FLAG_EAGER_REQ  - request eager length predition,
 *                                  provided in build_ses_hdr upcall
 *                                  from pds to ses
 *        UET_PDS_FLAG_RETRANSMIT - this is retransmission of the packet
 *      pds_info_valid  - true => use contents of pds_info
 *      pds_info        - pds info echoed back from read request
 *      msg_id          - id of message
 *      next_hdr        - identifies next header following pds header
 *      pkt             - ptr to msg payload to be sent
 *      pkt_len         - length of msg payload to be sent in bytes
 *      dma_rdy         - true => msg payload buffer can be DMA'ed
 *
 * returns:
 *      FI_SUCCESS on success
 *      negative value corresponding to fabric errno on error
 *        -FI_AGAIN indicates caller should queue packet and retry later
 */
int uet_pds_tx_pkt(uet_pkt_handle_t tx_pkt_handle, struct uet_ep *uet_ep,
		   uet_addr_handle_t dst_addr_handle, uet_pds_mode_t mode,
		   uet_pds_tx_flags_t flags, bool pds_info_valid,
		   struct uet_pds_info pds_info, uint16_t msg_id,
		   uet_next_hdr_t next_hdr, void *pkt, size_t pkt_len,
		   bool dma_rdy);

/*
 * progress tx operations for endpoint
 *
 * parms:
 *      ep             - ptr to uet endpoint struct
 *      err_pkt_handle - addr of location where packet handle is
 *                       returned in err case
 *
 * returns:
 *      FI_SUCCESS on success
 *      negative value corresponding to fabric errno on error
 *        -FI_ENODATA indicates pds can accept more packets to transmit
 */
int uet_pds_progress_tx(struct uet_ep *uet_ep,
			uet_pkt_handle_t *err_pkt_handle);

/*
 * progress rx operations
 *
 * parms:
 *      uet - ptr to uet instance struct
 *
 * returns:
 *      FI_SUCCESS to indicate no error
 *      negative value corresponding to fabric errno on error
 */
int uet_pds_progress_rx(struct uet_instance *uet);

/*
 * implement endpoint close wait state
 *
 * parms:
 *      uet_ep - ptr to uet endpoint struct for endpoint that is being closed
 */
void uet_pds_ep_close_wait(struct uet_ep *uet_ep);

#endif /* _UET_PDS_H_ */
