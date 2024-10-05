-- UltraEthernet wireshark dissector
-- Copyright Keysight Technologies 2024
--
-- To use this dissector, make it available in the wireshark plugins
-- directory, for example:
--
-- ln -sf $(pwd)/uet.lua ~/.config/wireshark/plugins/

p_uet = Proto("uet", "UltraEthernet Transport")
p_uet.prefs["ip_proto"] = Pref.uint("IP protocol#", 253, "IP protocol number for UET")
p_uet.prefs["track"] = Pref.bool("Track requests and responses", true,
	"Enable to track request/response/ACK packet relationships (at the expense of memory and/or CPU usage)")

-- LIST
local UET_EXPECTED = 0  -- 0x0
local UET_OVERFLOW = 1  -- 0x1
local LIST_STR_MAP = {
	[UET_EXPECTED] = "UET_EXPECTED",
	[UET_OVERFLOW] = "UET_OVERFLOW",
}
local LIST_DESC_MAP = {
	[UET_EXPECTED] = "EXPECTED - Operation matched the expected list",
	[UET_OVERFLOW] = "OVERFLOW - Operation was buffered in the overflow buffer space and tracked an unexpected header",
}
-- PDS_NEXT_HDR
local UET_HDR_NONE = 0  -- 0x0
local UET_HDR_REQUEST_SMALL = 1  -- 0x1
local UET_HDR_REQUEST_MEDIUM = 2  -- 0x2
local UET_HDR_REQUEST_STD = 3  -- 0x3
local UET_HDR_RESPONSE = 4  -- 0x4
local UET_HDR_RESPONSE_DATA = 5  -- 0x5
local UET_HDR_RESPONSE_DATA_SMALL = 6  -- 0x6
local UET_HDR_PDS = 15  -- 0xf
local PDS_NEXT_HDR_STR_MAP = {
	[UET_HDR_NONE] = "UET_HDR_NONE",
	[UET_HDR_PDS] = "UET_HDR_PDS",
	[UET_HDR_REQUEST_MEDIUM] = "UET_HDR_REQUEST_MEDIUM",
	[UET_HDR_REQUEST_SMALL] = "UET_HDR_REQUEST_SMALL",
	[UET_HDR_REQUEST_STD] = "UET_HDR_REQUEST_STD",
	[UET_HDR_RESPONSE] = "UET_HDR_RESPONSE",
	[UET_HDR_RESPONSE_DATA] = "UET_HDR_RESPONSE_DATA",
	[UET_HDR_RESPONSE_DATA_SMALL] = "UET_HDR_RESPONSE_DATA_SMALL",
}
local PDS_NEXT_HDR_DESC_MAP = {
	[UET_HDR_NONE] = "NONE",
	[UET_HDR_PDS] = "PDS",
	[UET_HDR_REQUEST_MEDIUM] = "REQUEST_MEDIUM",
	[UET_HDR_REQUEST_SMALL] = "REQUEST_SMALL",
	[UET_HDR_REQUEST_STD] = "REQUEST_STD",
	[UET_HDR_RESPONSE] = "RESPONSE",
	[UET_HDR_RESPONSE_DATA] = "RESPONSE_DATA",
	[UET_HDR_RESPONSE_DATA_SMALL] = "RESPONSE_DATA_SMALL",
}
-- PDS_TYPE
local TYPE_UET_ENCR = 1  -- 0x1
local TYPE_RUD_REQ = 2  -- 0x2
local TYPE_ROD_REQ = 3  -- 0x3
local TYPE_RUDI_REQ = 4  -- 0x4
local TYPE_RUDI_RESP = 5  -- 0x5
local TYPE_UUD_REQ = 6  -- 0x6
local TYPE_ACK = 7  -- 0x7
local TYPE_ACK_CC = 8  -- 0x8
local TYPE_ACK_CCX = 9  -- 0x9
local TYPE_NACK = 10  -- 0xa
local TYPE_CTRL = 11  -- 0xb
local PDS_TYPE_STR_MAP = {
	[TYPE_ACK] = "TYPE_ACK",
	[TYPE_ACK_CC] = "TYPE_ACK_CC",
	[TYPE_ACK_CCX] = "TYPE_ACK_CCX",
	[TYPE_CTRL] = "TYPE_CTRL",
	[TYPE_NACK] = "TYPE_NACK",
	[TYPE_ROD_REQ] = "TYPE_ROD_REQ",
	[TYPE_RUDI_REQ] = "TYPE_RUDI_REQ",
	[TYPE_RUDI_RESP] = "TYPE_RUDI_RESP",
	[TYPE_RUD_REQ] = "TYPE_RUD_REQ",
	[TYPE_UET_ENCR] = "TYPE_UET_ENCR",
	[TYPE_UUD_REQ] = "TYPE_UUD_REQ",
}
local PDS_TYPE_DESC_MAP = {
	[TYPE_ACK] = "ACK - Acknowledge",
	[TYPE_ACK_CC] = "ACK_CC - ACK w/ Congestion Control",
	[TYPE_ACK_CCX] = "ACK_CCX - ACK w/ Congestion Control Extended ",
	[TYPE_CTRL] = "CTRL - Control",
	[TYPE_NACK] = "NACK - Negative acknowledge",
	[TYPE_ROD_REQ] = "ROD_REQ - ROD Request",
	[TYPE_RUDI_REQ] = "RUDI_REQ - RUDI Request",
	[TYPE_RUDI_RESP] = "RUDI_RESP - RUDI Response",
	[TYPE_RUD_REQ] = "RUD_REQ - RUD Request",
	[TYPE_UET_ENCR] = "UET_ENCR - UET Encryption header",
	[TYPE_UUD_REQ] = "UUD_REQ - UUD Request",
}
-- REQ_OPCODE
local UET_NO_OP = 0  -- 0x0
local UET_WRITE = 1  -- 0x1
local UET_READ = 2  -- 0x2
local UET_ATOMIC = 3  -- 0x3
local UET_FETCHING_ATOMIC = 4  -- 0x4
local UET_SEND = 5  -- 0x5
local UET_RENDEZVOUS_SEND = 6  -- 0x6
local UET_DATAGRAM_SEND = 7  -- 0x7
local UET_DEFERRABLE_SEND = 8  -- 0x8
local UET_TAGGED_SEND = 9  -- 0x9
local UET_RENDEZVOUS_TSEND = 10  -- 0xa
local UET_DEFERRABLE_TSEND = 11  -- 0xb
local UET_DEFERRABLE_RTR = 12  -- 0xc
local UET_TSEND_ATOMIC = 13  -- 0xd
local UET_TSEND_FETCH_ATOMIC = 14  -- 0xe
local UET_MSG_ERROR = 15  -- 0xf
local UET_INC_PUSH = 16  -- 0x10
local UET_OP_EXTENDED = 63  -- 0x3f
local REQ_OPCODE_STR_MAP = {
	[UET_ATOMIC] = "UET_ATOMIC",
	[UET_DATAGRAM_SEND] = "UET_DATAGRAM_SEND",
	[UET_DEFERRABLE_RTR] = "UET_DEFERRABLE_RTR",
	[UET_DEFERRABLE_SEND] = "UET_DEFERRABLE_SEND",
	[UET_DEFERRABLE_TSEND] = "UET_DEFERRABLE_TSEND",
	[UET_FETCHING_ATOMIC] = "UET_FETCHING_ATOMIC",
	[UET_INC_PUSH] = "UET_INC_PUSH",
	[UET_MSG_ERROR] = "UET_MSG_ERROR",
	[UET_NO_OP] = "UET_NO_OP",
	[UET_OP_EXTENDED] = "UET_OP_EXTENDED",
	[UET_READ] = "UET_READ",
	[UET_RENDEZVOUS_SEND] = "UET_RENDEZVOUS_SEND",
	[UET_RENDEZVOUS_TSEND] = "UET_RENDEZVOUS_TSEND",
	[UET_SEND] = "UET_SEND",
	[UET_TAGGED_SEND] = "UET_TAGGED_SEND",
	[UET_TSEND_ATOMIC] = "UET_TSEND_ATOMIC",
	[UET_TSEND_FETCH_ATOMIC] = "UET_TSEND_FETCH_ATOMIC",
	[UET_WRITE] = "UET_WRITE",
}
local REQ_OPCODE_DESC_MAP = {
	[UET_ATOMIC] = "ATOMIC",
	[UET_DATAGRAM_SEND] = "DATAGRAM_SEND - Only legal when used with UUD PDS type.",
	[UET_DEFERRABLE_RTR] = "DEFERRABLE_RTR - A deferred send is ready to restart",
	[UET_DEFERRABLE_SEND] = "DEFERRABLE_SEND - A send operation where the payload transfer may be deferred by the target.",
	[UET_DEFERRABLE_TSEND] = "DEFERRABLE_TSEND - A deferrable version of the tagged send",
	[UET_FETCHING_ATOMIC] = "FETCHING_ATOMIC - Includes compare and swap",
	[UET_INC_PUSH] = "INC_PUSH - INC push",
	[UET_MSG_ERROR] = "MSG_ERROR - Used to terminate an in-progress message ID. Can be sent as an “early” final packet of a message for an in-flight message that encounters an error.",
	[UET_NO_OP] = "NO_OP - May or may not be needed/useful. It always seems to wind up being included.",
	[UET_OP_EXTENDED] = "OP_EXTENDED - Reserved for opcode space expansion",
	[UET_READ] = "READ - RMA Read",
	[UET_RENDEZVOUS_SEND] = "RENDEZVOUS_SEND - Incorporated to allow Send over ROD (for ordering) with bulk payload over RUD.",
	[UET_RENDEZVOUS_TSEND] = "RENDEZVOUS_TSEND - A rendezvous version of the tagged send.",
	[UET_SEND] = "SEND - (non-matching) send operation",
	[UET_TAGGED_SEND] = "TAGGED_SEND - A tagged send operation using match bits for buffer selection.",
	[UET_TSEND_ATOMIC] = "TSEND_ATOMIC - Atomic operations with tagged send addressing semantics.",
	[UET_TSEND_FETCH_ATOMIC] = "TSEND_FETCH_ATOMIC - Fetching atomic operations (including compare and swap) using tagged send addressing semantics",
	[UET_WRITE] = "WRITE - RMA Write",
}
-- RET_CODE
local RC_NULL = 0  -- 0x0
local RC_OK = 1  -- 0x1
local RC_BAD_GENERATION = 2  -- 0x2
local RC_DISABLED = 3  -- 0x3
local RC_DISABLED_GEN = 4  -- 0x4
local RC_NO_MATCH = 5  -- 0x5
local RC_UNSUPPORTED_OP = 6  -- 0x6
local RC_UNSUPPORTED_SIZE = 7  -- 0x7
local RC_AT_INVALID = 8  -- 0x8
local RC_AT_PERM = 9  -- 0x9
local RC_AT_ATS_ERROR = 10  -- 0xa
local RC_AT_NO_TRANS = 11  -- 0xb
local RC_AT_OUT_OF_RANGE = 12  -- 0xc
local RC_HOST_POISONED = 13  -- 0xd
local RC_HOST_UNSUCCESS_CMPL = 14  -- 0xe
local RC_AMO_UNSUPPORTED_OP = 15  -- 0xf
local RC_AMO_UNSUPPORTED_DT = 16  -- 0x10
local RC_AMO_UNSUPPORTED_SIZE = 17  -- 0x11
local RC_AMO_UNALIGNED = 18  -- 0x12
local RC_AMO_FP_NAN = 19  -- 0x13
local RC_AMO_FP_UNDERFLOW = 20  -- 0x14
local RC_AMO_FP_OVERFLOW = 21  -- 0x15
local RC_AMO_FP_INEXACT = 22  -- 0x16
local RC_PERM_VIOLATION = 23  -- 0x17
local RC_OP_VIOLATION = 24  -- 0x18
local RC_BAD_INDEX = 25  -- 0x19
local RC_BAD_PID = 26  -- 0x1a
local RC_BAD_JOB_ID = 27  -- 0x1b
local RC_BAD_MKEY = 28  -- 0x1c
local RC_BAD_ADDR = 29  -- 0x1d
local RC_CANCELLED = 30  -- 0x1e
local RC_UNDELIVERABLE = 31  -- 0x1f
local RC_UNCOR = 32  -- 0x20
local RC_UNCOR_TRNSNT = 33  -- 0x21
local RC_TOO_LONG = 34  -- 0x22
local RC_INITIATOR_ERR = 35  -- 0x23
local RC_DROPPED = 36  -- 0x24
local RET_CODE_STR_MAP = {
	[RC_AMO_FP_INEXACT] = "RC_AMO_FP_INEXACT",
	[RC_AMO_FP_NAN] = "RC_AMO_FP_NAN",
	[RC_AMO_FP_OVERFLOW] = "RC_AMO_FP_OVERFLOW",
	[RC_AMO_FP_UNDERFLOW] = "RC_AMO_FP_UNDERFLOW",
	[RC_AMO_UNALIGNED] = "RC_AMO_UNALIGNED",
	[RC_AMO_UNSUPPORTED_DT] = "RC_AMO_UNSUPPORTED_DT",
	[RC_AMO_UNSUPPORTED_OP] = "RC_AMO_UNSUPPORTED_OP",
	[RC_AMO_UNSUPPORTED_SIZE] = "RC_AMO_UNSUPPORTED_SIZE",
	[RC_AT_ATS_ERROR] = "RC_AT_ATS_ERROR",
	[RC_AT_INVALID] = "RC_AT_INVALID",
	[RC_AT_NO_TRANS] = "RC_AT_NO_TRANS",
	[RC_AT_OUT_OF_RANGE] = "RC_AT_OUT_OF_RANGE",
	[RC_AT_PERM] = "RC_AT_PERM",
	[RC_BAD_ADDR] = "RC_BAD_ADDR",
	[RC_BAD_GENERATION] = "RC_BAD_GENERATION",
	[RC_BAD_INDEX] = "RC_BAD_INDEX",
	[RC_BAD_JOB_ID] = "RC_BAD_JOB_ID",
	[RC_BAD_MKEY] = "RC_BAD_MKEY",
	[RC_BAD_PID] = "RC_BAD_PID",
	[RC_CANCELLED] = "RC_CANCELLED",
	[RC_DISABLED] = "RC_DISABLED",
	[RC_DISABLED_GEN] = "RC_DISABLED_GEN",
	[RC_DROPPED] = "RC_DROPPED",
	[RC_HOST_POISONED] = "RC_HOST_POISONED",
	[RC_HOST_UNSUCCESS_CMPL] = "RC_HOST_UNSUCCESS_CMPL",
	[RC_INITIATOR_ERR] = "RC_INITIATOR_ERR",
	[RC_NO_MATCH] = "RC_NO_MATCH",
	[RC_NULL] = "RC_NULL",
	[RC_OK] = "RC_OK",
	[RC_OP_VIOLATION] = "RC_OP_VIOLATION",
	[RC_PERM_VIOLATION] = "RC_PERM_VIOLATION",
	[RC_TOO_LONG] = "RC_TOO_LONG",
	[RC_UNCOR] = "RC_UNCOR",
	[RC_UNCOR_TRNSNT] = "RC_UNCOR_TRNSNT",
	[RC_UNDELIVERABLE] = "RC_UNDELIVERABLE",
	[RC_UNSUPPORTED_OP] = "RC_UNSUPPORTED_OP",
	[RC_UNSUPPORTED_SIZE] = "RC_UNSUPPORTED_SIZE",
}
local RET_CODE_DESC_MAP = {
	[RC_AMO_FP_INEXACT] = "AMO_FP_INEXACT",
	[RC_AMO_FP_NAN] = "AMO_FP_NAN",
	[RC_AMO_FP_OVERFLOW] = "AMO_FP_OVERFLOW",
	[RC_AMO_FP_UNDERFLOW] = "AMO_FP_UNDERFLOW",
	[RC_AMO_UNALIGNED] = "AMO_UNALIGNED",
	[RC_AMO_UNSUPPORTED_DT] = "AMO_UNSUPPORTED_DT",
	[RC_AMO_UNSUPPORTED_OP] = "AMO_UNSUPPORTED_OP",
	[RC_AMO_UNSUPPORTED_SIZE] = "AMO_UNSUPPORTED_SIZE",
	[RC_AT_ATS_ERROR] = "AT_ATS_ERROR",
	[RC_AT_INVALID] = "AT_INVALID",
	[RC_AT_NO_TRANS] = "AT_NO_TRANS",
	[RC_AT_OUT_OF_RANGE] = "AT_OUT_OF_RANGE",
	[RC_AT_PERM] = "AT_PERM",
	[RC_BAD_ADDR] = "BAD_ADDR",
	[RC_BAD_GENERATION] = "BAD_GENERATION",
	[RC_BAD_INDEX] = "BAD_INDEX",
	[RC_BAD_JOB_ID] = "BAD_JOB_ID",
	[RC_BAD_MKEY] = "BAD_MKEY",
	[RC_BAD_PID] = "BAD_PID",
	[RC_CANCELLED] = "CANCELLED",
	[RC_DISABLED] = "DISABLED",
	[RC_DISABLED_GEN] = "DISABLED_GEN",
	[RC_DROPPED] = "DROPPED",
	[RC_HOST_POISONED] = "HOST_POISONED",
	[RC_HOST_UNSUCCESS_CMPL] = "HOST_UNSUCCESS_CMPL",
	[RC_INITIATOR_ERR] = "INITIATOR_ERR",
	[RC_NO_MATCH] = "NO_MATCH",
	[RC_NULL] = "NULL",
	[RC_OK] = "OK",
	[RC_OP_VIOLATION] = "OP_VIOLATION",
	[RC_PERM_VIOLATION] = "PERM_VIOLATION",
	[RC_TOO_LONG] = "TOO_LONG",
	[RC_UNCOR] = "UNCOR",
	[RC_UNCOR_TRNSNT] = "UNCOR_TRNSNT",
	[RC_UNDELIVERABLE] = "UNDELIVERABLE",
	[RC_UNSUPPORTED_OP] = "UNSUPPORTED_OP",
	[RC_UNSUPPORTED_SIZE] = "UNSUPPORTED_SIZE",
}
-- RSP_OPCODE
local UET_DEFAULT_RESPONSE = 0  -- 0x0
local UET_RESPONSE = 1  -- 0x1
local UET_RESPONSE_W_DATA = 2  -- 0x2
local UET_NO_RESPONSE = 3  -- 0x3
local UET_INC_ERROR_RESPONSE = 4  -- 0x4
local RSP_OPCODE_STR_MAP = {
	[UET_DEFAULT_RESPONSE] = "UET_DEFAULT_RESPONSE",
	[UET_INC_ERROR_RESPONSE] = "UET_INC_ERROR_RESPONSE",
	[UET_NO_RESPONSE] = "UET_NO_RESPONSE",
	[UET_RESPONSE] = "UET_RESPONSE",
	[UET_RESPONSE_W_DATA] = "UET_RESPONSE_W_DATA",
}
local RSP_OPCODE_DESC_MAP = {
	[UET_DEFAULT_RESPONSE] = "DEFAULT_RESPONSE",
	[UET_INC_ERROR_RESPONSE] = "INC_ERROR_RESPONSE",
	[UET_NO_RESPONSE] = "NO_RESPONSE",
	[UET_RESPONSE] = "RESPONSE",
	[UET_RESPONSE_W_DATA] = "RESPONSE_W_DATA",
}


local yes_no = {"Yes", "No"}
local fld = p_uet.fields
fld.pds		= ProtoField.none("uet.pds",			"PDS")
fld.entropy	= ProtoField.uint16("uet.entropy",		"Entropy",				base.DEC)
fld.type	= ProtoField.uint16("uet.type",			"Type",					base.HEX, PDS_TYPE_DESC_MAP, 0xf800)
fld.next_hdr	= ProtoField.uint16("uet.next_hdr",		"Next Header",				base.HEX, PDS_NEXT_HDR_DESC_MAP, 0x780)
fld.flags	= ProtoField.uint16("uet.flags",		"Flags",				base.HEX, nil, 0x07f)
fld.clr_psn_off	= ProtoField.int16("uet.clear_psn_offset",	"Clear PSN offset",			base.DEC)
fld.clear_psn	= ProtoField.uint32("uet.clear_psn",		"Clear PSN",				base.DEC)
fld.psn		= ProtoField.uint32("uet.psn",			"Packet Sequence Number",		base.DEC)
fld.spdcid	= ProtoField.uint16("uet.spdcid",		"Source PDC ID",			base.DEC)
fld.dpdcid	= ProtoField.uint16("uet.dpdcid",		"Destination PDC ID",			base.DEC)
fld.ack_psn_off	= ProtoField.int16("uet.ack_psn_offset",	"ACK PSN offset",			base.DEC)
fld.req_in	= ProtoField.framenum("uet.request_in",		"Request in",				base.NONE, frametype.REQUEST)
fld.ack_in	= ProtoField.framenum("uet.ack_in",		"ACK in",				base.NONE, frametype.ACK)
fld.resp_in	= ProtoField.framenum("uet.response_in",	 "Response in",				base.NONE, frametype.RESPONSE)

-- ROD/RUD request flags
fld.flag_rreq_crc	= ProtoField.bool("uet.flags.rreq.crc",		"CRC",			16, yes_no, 0x40)
fld.flag_rreq_rsv5	= ProtoField.bool("uet.flags.rreq.rsv5",	"RSV",			16, nil, 0x20)
fld.flag_rreq_cc	= ProtoField.bool("uet.flags.rreq.cc",		"CC state present",	16, yes_no, 0x10)
fld.flag_rreq_syn	= ProtoField.bool("uet.flags.rreq.syn",		"SYN",			16, yes_no, 0x08)
fld.flag_rreq_ar	= ProtoField.bool("uet.flags.rreq.ar",		"AR (ACK Request)",	16, yes_no, 0x04)
fld.flag_rreq_retx	= ProtoField.bool("uet.flags.rreq.retx",	"RETX (is retransmit)",	16, yes_no, 0x02)
fld.flag_rreq_rsv0	= ProtoField.bool("uet.flags.rreq.rsv0",	"RSV",			16, nil, 0x01)

-- ACK flags
fld.flag_ack_crc		= ProtoField.bool("uet.flags.ack.crc",			"CRC",			16, yes_no, 0x40)
fld.flag_ack_m			= ProtoField.bool("uet.flags.ack.m",			"M (ECN marked)",	16, yes_no, 0x20)
fld.flag_ack_ax			= ProtoField.bool("uet.flags.ack.ax",			"AX (ACK Extension)",	16, yes_no, 0x10)
fld.flag_ack_req		= ProtoField.uint16("uet.flags.ack.req",		"Requests",		base.DEC, nil, 0x0c)
fld.flag_ack_probe		= ProtoField.bool("uet.flags.ack.probe",		"Probe",		16, yes_no, 0x02)
fld.flag_ack_rsv		= ProtoField.bool("uet.flags.ack.rsv",			"RSV",			16, nil, 0x01)

fld.ses_req			= ProtoField.none("uet.ses.req",			"SES request") -- FIXME: Proto()?
fld.ses_req_rsv			= ProtoField.uint8("uet.ses.req.rsv",			"Reserved",			base.HEX, nil, 0xc0)
fld.ses_req_opcode		= ProtoField.uint8("uet.ses.req.opcode",		"Opcode",			base.HEX, REQ_OPCODE_DESC_MAP, 0x3f)
fld.ses_req_ver			= ProtoField.uint8("uet.ses.req.version",		"Version",			base.HEX, nil, 0xc0)
fld.ses_req_flag_dc		= ProtoField.bool("uet.ses.req.flags.dc",		"Delivery Complete (DC)",	8, yes_no, 0x20)
fld.ses_req_flag_ie		= ProtoField.bool("uet.ses.req.flags.ie",		"Initiator Error (IE)",		8, yes_no, 0x10)
fld.ses_req_flag_relative	= ProtoField.bool("uet.ses.req.flags.relative",		"Relative",			8, yes_no, 0x08)
fld.ses_req_flag_hd		= ProtoField.bool("uet.ses.req.flags.hd",		"Header Data (HD)",		8, yes_no, 0x04)
fld.ses_req_flag_eom		= ProtoField.bool("uet.ses.req.flags.eom",		"End of Message (EOM)",		8, yes_no, 0x02)
fld.ses_req_flag_som		= ProtoField.bool("uet.ses.req.flags.som",		"Start of Message (SOM)",	8, yes_no, 0x01)
fld.ses_index_gen		= ProtoField.uint8("uet.ses.index_gen",			"Index generation",		base.DEC)
fld.ses_job_id			= ProtoField.uint24("uet.ses.job_id",			"Job ID",			base.DEC)
fld.ses_req_rsv2		= ProtoField.uint16("uet.ses.req.rsv2",			"Reserved",			base.HEX, nil, 0xf000)
fld.ses_index			= ProtoField.uint16("uet.ses.index",			"Index",			base.DEC, nil, 0x0fff)
fld.ses_req_rsv3		= ProtoField.uint16("uet.ses.req.rsv3",			"Reserved",			base.HEX, nil, 0xf000)
fld.ses_req_pidonfep		= ProtoField.uint16("uet.ses.req.pid_on_fep",		"PID on FEP",			base.DEC, nil, 0x0fff)
fld.ses_msgid			= ProtoField.uint16("uet.ses.message_id",		"Message ID",			base.DEC)
fld.ses_req_buff_offs		= ProtoField.uint64("uet.ses.req.buffer_offset",	"Buffer offset",		base.DEC_HEX)
fld.ses_req_initiator		= ProtoField.uint32("uet.ses.req.initiator",		"Initiator",			base.HEX)
fld.ses_req_match_bits		= ProtoField.uint64("uet.ses.req.match_bits",		"Match bits",			base.HEX)
fld.ses_req_hdr_data		= ProtoField.uint64("uet.ses.req.header_data",		"Header data",			base.HEX)
fld.ses_req_len			= ProtoField.uint64("uet.ses.req.len",			"Request length",		base.DEC_HEX)
fld.ses_req_msg_offset		= ProtoField.uint32("uet.ses.req.msg_offset",		"Message offset",		base.DEC_HEX)
fld.ses_req_payload_len_rsvd	= ProtoField.uint32("uet.ses.req.payload_len_rsvd",	"Reserved",			base.HEX,     nil, 0xffffc000)
fld.ses_req_payload_len		= ProtoField.uint32("uet.ses.req.payload_len",		"Payload length",		base.DEC_HEX, nil, 0x00003fff)

fld.ses_resp			= ProtoField.none("uet.ses.resp",			"SES response") -- FIXME: Proto()?
fld.ses_resp_data		= ProtoField.none("uet.ses.resp_data",			"SES response w/ data") -- FIXME: Proto()?
fld.ses_resp_list		= ProtoField.uint8("uet.ses.resp.list",			"List",				base.DEC, LIST_DESC_MAP, 0xc0)
fld.ses_resp_opcode		= ProtoField.uint8("uet.ses.resp.opcode",		"Opcode",			base.HEX, RSP_OPCODE_DESC_MAP, 0x3f)
fld.ses_resp_ver		= ProtoField.uint8("uet.ses.resp.version",		"Version",			base.DEC, nil, 0xc0)
fld.ses_resp_retcode		= ProtoField.uint8("uet.ses.resp.retcode",		"Return code",			base.HEX, RET_CODE_DESC_MAP, 0x3f)
-- ses_msgid
-- index_gen
-- job_id
fld.ses_resp_rreq_msgid		= ProtoField.uint16("uet.ses.resp.req_message_id",	"Read Request Message ID",	base.DEC)
fld.ses_resp_mod_len		= ProtoField.uint32("uet.ses.resp.mod_length",		"Modified length",		base.DEC_HEX)
fld.ses_resp_msg_offset		= ProtoField.uint32("uet.ses.resp.msg_offset",		"Message offset",		base.DEC_HEX)
-- TODO?
fld.ses_resp_rsvd		= ProtoField.uint16("uet.ses.resp.reserved",		"Reserved",			base.HEX,     nil, 0xc000)
fld.ses_resp_payload_len	= ProtoField.uint16("uet.ses.resp.payload_len",		"Payload length",		base.DEC_HEX, nil, 0x3fff)

local dissect_data	= Dissector.get("data")

local pds_req_map = {} -- <IP, PDCID, PSN> -> framenum
local pds_frame_info = {} -- framenum -> table

function track_key(net_addr, pdcid_tvb, psn_tvb)
	-- TODO: anything more efficient than strings?
	return tostring(net_addr) .. "--" .. tostring(pdcid_tvb:uint()) .. "--" .. tostring(psn_tvb:uint())
end

function p_uet.dissector(buf, pinfo, root)
	pinfo.cols.protocol = p_uet.name

	local proto_tree = root:add(p_uet, buf:range(0))
	local subtree = proto_tree:add(fld.pds, buf:range(0))
	subtree:add(fld.entropy, buf(0, 2))
	subtree:add(fld.type, buf(2, 2))
	local h_type = buf(2, 1):bitfield(0, 5)
	local type_str = PDS_TYPE_STR_MAP[h_type]
	local summary = ""
	local offset = 4
	if type_str ~= nil then
		summary = type_str
	end

	local do_track = p_uet.prefs.track and not pinfo.visited and not pinfo.in_error_pkt
	if do_track then
		pds_frame_info[pinfo.number] = {}
	end

	if h_type == TYPE_RUD_REQ or h_type == TYPE_ROD_REQ then
		subtree:add(fld.next_hdr, buf(2, 2))
		local flags_tree = subtree:add(fld.flags, buf(2, 2))
		flags_tree:add(fld.flag_rreq_crc, buf(2, 2))
		flags_tree:add(fld.flag_rreq_rsv5, buf(2, 2))
		flags_tree:add(fld.flag_rreq_cc, buf(2, 2))
		flags_tree:add(fld.flag_rreq_syn, buf(2, 2))
		flags_tree:add(fld.flag_rreq_ar, buf(2, 2))
		flags_tree:add(fld.flag_rreq_retx, buf(2, 2))
		flags_tree:add(fld.flag_rreq_rsv0, buf(2, 2))


		local b_clr_psn_off = buf(4, 2)
		local b_psn = buf(6, 4)
		local b_spdcid = buf(10, 2)
		local b_dpdcid = buf(12, 2)
		subtree:add(fld.clr_psn_off, b_clr_psn_off)
		-- TODO: absolute clear PSN (calculated)
		subtree:add(fld.psn, b_psn)
		subtree:add(fld.spdcid, b_spdcid)
		-- TODO: info&offset for SYN
		subtree:add(fld.dpdcid, b_dpdcid)
		offset = 14
		subtree:set_len(offset)
		-- TODO: cc_state

		if do_track then
			local key = track_key(pinfo.net_src, b_spdcid, b_psn)
			pds_req_map[key] = pinfo.number

			-- TODO: only if "response"? how? what about Clear?
			local fkey = track_key(pinfo.net_dst, b_dpdcid, b_fwd_psn)
			local fw = pds_req_map[fkey]
			if fw ~= nil then
				pds_frame_info[pinfo.number].req_in = fw
				pds_frame_info[fw].resp_in = pinfo.number
			end
		end
	end if h_type == TYPE_ACK then
		subtree:add(fld.next_hdr, buf(2, 2))
		local flags_tree = subtree:add(fld.flags, buf(2, 2))
		flags_tree:add(fld.flag_ack_crc, buf(2, 2))
		flags_tree:add(fld.flag_ack_m, buf(2, 2))
		flags_tree:add(fld.flag_ack_ax, buf(2, 2))
		flags_tree:add(fld.flag_ack_req, buf(2, 2))
		flags_tree:add(fld.flag_ack_probe, buf(2, 2))
		flags_tree:add(fld.flag_ack_rsv, buf(2, 2))

		local b_ack_psn_off = buf(4, 2)
		local b_psn = buf(6, 4)
		local b_spdcid = buf(10, 2)
		local b_dpdcid = buf(12, 2)
		subtree:add(fld.ack_psn_off, b_ack_psn_off)
		-- TODO: absolute ACK PSN (calculated)
		subtree:add(fld.psn, b_psn) -- TODO: cack_psn?
		subtree:add(fld.spdcid, b_spdcid)
		subtree:add(fld.dpdcid, b_dpdcid)
		offset = 14
		subtree:set_len(offset)

		if do_track then
			-- TODO: use ack_psn_off
			local key = track_key(pinfo.net_dst, b_dpdcid, b_psn)
			local req = pds_req_map[key]
			if req ~= nil then
				pds_frame_info[pinfo.number].req_in = req
				pds_frame_info[req].ack_in = pinfo.number
			end
		end
	end

	local fi = pds_frame_info[pinfo.number]
	if fi ~= nil then
		if fi.req_in ~= nil then
			subtree:add(fld.req_in, fi.req_in):set_generated()
		end
		if fi.ack_in ~= nil then
			subtree:add(fld.ack_in, fi.ack_in):set_generated()
		end
		if fi.resp_in ~= nil then
			subtree:add(fld.resp_in, fi.resp_in):set_generated()
		end
	end

	-- TODO: TYPE_CTRL
	if h_type ~= TYPE_CTRL then
		local h_next = buf(2, 2):bitfield(5, 4)
		-- TODO: distinct Proto()
		if h_next == UET_HDR_REQUEST_STD then
			local opcode = buf(offset, 1):bitfield(2, 6)
			local opcode_str = REQ_OPCODE_STR_MAP[opcode]
			if opcode_str ~= nil then
				summary = summary .. " " .. opcode_str
			end

			local req_tree = proto_tree:add(fld.ses_req, buf(offset, 44))
			req_tree:add(fld.ses_req_rsv, buf(offset, 1))
			req_tree:add(fld.ses_req_opcode, buf(offset, 1))
			req_tree:add(fld.ses_req_ver, buf(offset+1, 1))
			req_tree:add(fld.ses_req_flag_dc, buf(offset+1, 1))
			req_tree:add(fld.ses_req_flag_ie, buf(offset+1, 1))
			req_tree:add(fld.ses_req_flag_relative, buf(offset+1, 1))
			req_tree:add(fld.ses_req_flag_hd, buf(offset+1, 1))
			req_tree:add(fld.ses_req_flag_eom, buf(offset+1, 1))
			req_tree:add(fld.ses_req_flag_som, buf(offset+1, 1))
			local is_som = buf(offset+1, 1):bitfield(7, 1)
			req_tree:add(fld.ses_msgid, buf(offset+2, 2))
			req_tree:add(fld.ses_index_gen, buf(offset+4, 1))
			req_tree:add(fld.ses_job_id, buf(offset+5, 3))
			req_tree:add(fld.ses_req_rsv2, buf(offset+8, 2))
			req_tree:add(fld.ses_req_pidonfep, buf(offset+8, 2))
			req_tree:add(fld.ses_req_rsv3, buf(offset+10, 2))
			req_tree:add(fld.ses_index, buf(offset+10, 2))
			req_tree:add(fld.ses_req_buff_offs, buf(offset+12, 8))
			req_tree:add(fld.ses_req_initiator, buf(offset+20, 4))
			req_tree:add(fld.ses_req_match_bits, buf(offset+24, 8))
			if is_som == 1 then
				req_tree:add(fld.ses_req_hdr_data, buf(offset+32, 8))
			else
				req_tree:add(fld.ses_req_payload_len_rsvd, buf(offset+32, 4))
				req_tree:add(fld.ses_req_payload_len, buf(offset+32, 4))
				req_tree:add(fld.ses_req_msg_offset, buf(offset+36, 4))
			end
			req_tree:add(fld.ses_req_len, buf(offset+40, 4))
			offset = offset + 44
		end if h_next == UET_HDR_RESPONSE then
			local opcode = buf(offset, 1):bitfield(2, 6)
			local opcode_str = RSP_OPCODE_STR_MAP[opcode]
			if opcode_str ~= nil then
				summary = summary .. " " .. opcode_str
			end
			local resp_tree = proto_tree:add(fld.ses_resp, buf(offset, 12))
			resp_tree:add(fld.ses_resp_list, buf(offset, 1))
			resp_tree:add(fld.ses_resp_opcode, buf(offset, 1))
			resp_tree:add(fld.ses_resp_ver, buf(offset+1, 1))
			resp_tree:add(fld.ses_resp_retcode, buf(offset+1, 1))
			resp_tree:add(fld.ses_msgid, buf(offset+2, 2))
			resp_tree:add(fld.ses_index_gen, buf(offset+4, 1))
			resp_tree:add(fld.ses_job_id, buf(offset+5, 3))
			resp_tree:add(fld.ses_resp_mod_len, buf(offset+8, 4))
			offset = offset + 12
		end if h_next == UET_HDR_RESPONSE_DATA then
			local opcode = buf(offset, 1):bitfield(2, 6)
			local opcode_str = RSP_OPCODE_STR_MAP[opcode]
			if opcode_str ~= nil then
				summary = summary .. " " .. opcode_str
			end
			local resp_tree = proto_tree:add(fld.ses_resp_data, buf(offset, 20))
			resp_tree:add(fld.ses_resp_list, buf(offset, 1))
			resp_tree:add(fld.ses_resp_opcode, buf(offset, 1))
			resp_tree:add(fld.ses_resp_ver, buf(offset+1, 1))
			resp_tree:add(fld.ses_resp_retcode, buf(offset+1, 1))
			resp_tree:add(fld.ses_msgid, buf(offset+2, 2)) -- of itself
			resp_tree:add(fld.ses_index_gen, buf(offset+4, 1)) -- FIXME: reserved in HDR_RSP_DATA
			resp_tree:add(fld.ses_job_id, buf(offset+5, 3))
			resp_tree:add(fld.ses_resp_rreq_msgid, buf(offset+8, 2))
			resp_tree:add(fld.ses_resp_rsvd, buf(offset+10, 2))
			resp_tree:add(fld.ses_resp_payload_len, buf(offset+10, 2))
			resp_tree:add(fld.ses_resp_mod_len, buf(offset+12, 4))
			resp_tree:add(fld.ses_resp_msg_offset, buf(offset+16, 4))
			offset = offset + 20
		end
	end

	if summary ~= "" then
		pinfo.cols.info = summary
	end

	proto_tree:set_len(offset)
	local pktlen = buf:len() - offset
	local data_buf = buf(offset, pktlen)
	dissect_data:call(data_buf:tvb(), pinfo, root)
end

function p_uet:init()
	local ip_table = DissectorTable.get("ip.proto")
	local udp_table = DissectorTable.get("udp.port")
	ip_table:add(p_uet.prefs["ip_proto"], p_uet)
	udp_table:add_for_decode_as(p_uet)
	pds_req_map = {}
	pds_frame_info = {}
end
