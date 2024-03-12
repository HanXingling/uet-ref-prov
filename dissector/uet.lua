-- UltraEthernet wireshark dissector
-- Copyright Keysight Technologies 2024
--
-- To use this dissector, make it available in the wireshark plugins
-- directory, for example:
--
-- ln -sf $(pwd)/uet.lua ~/.config/wireshark/plugins/

p_uet = Proto("uet", "UltraEthernet Transport")
p_uet.prefs["ip_proto"] = Pref.uint("IP protocol#", 253, "IP protocol number for UET")

local
	TYPE_UET_ENCR,
	TYPE_RUD_REQ,
	TYPE_ROD_REQ,
	TYPE_RUDI_REQ,
	TYPE_UUD_REQ,
	TYPE_RUDI_RESP,
	TYPE_PDS_ACK,
	TYPE_CTRL = 1, 2, 3, 4, 5, 6, 7, 8
local types = {
	[0]			= "Reserved",
	[TYPE_UET_ENCR]		= "UET Encryption header",
	[TYPE_RUD_REQ]		= "RUD Request",
	[TYPE_ROD_REQ]		= "ROD Request",
	[TYPE_RUDI_REQ]		= "RUDI Request",
	[TYPE_UUD_REQ]		= "UUD Request",
	[TYPE_RUDI_RESP]	= "RUDI Response",
	[TYPE_PDS_ACK]		= "PDS ACK",
	[TYPE_CTRL]		= "Control",
}

local
	HDR_REQ_STD,
	HDR_RSP = 2, 3
local hdr_types = {
	[HDR_REQ_STD]		= "Standard SES request",
	[HDR_RSP]		= "SES response",
}

local yes_no = {"Yes", "No"}
local fld = p_uet.fields
fld.entropy	= ProtoField.uint16("uet.entropy",	"Entropy",			base.DEC)
fld.type	= ProtoField.uint16("uet.type",		"Type",				base.HEX, types, 0xf000)
fld.flags	= ProtoField.uint16("uet.flags",	"Flags",			base.HEX, nil, 0x0fe0)
fld.next_hdr	= ProtoField.uint16("uet.next_hdr",	"Next Header",			base.HEX, hdr_types, 0x001f)
fld.ack_code	= ProtoField.uint16("uet.ack.code",	"ACK code",			base.HEX, nil, 0x001f)
fld.psn		= ProtoField.uint32("uet.psn",		"Packet Sequence Number",	base.DEC)
fld.spdcid	= ProtoField.uint16("uet.spdcid",	"Source PDC ID",		base.DEC)
fld.dpdcid	= ProtoField.uint16("uet.dpdcid",	"Destination PDC ID",		base.DEC)

-- N.B. masks shifted left by 5 bits (for next_hdr)
fld.flag_rreq_syn	= ProtoField.bool("uet.flags.rreq.syn",		"SYN",			16, yes_no, 0x800)
fld.flag_rreq_clr	= ProtoField.uint16("uet.flags.rreq.clr",	"CLR",			base.DEC, nil, 0x0600)
fld.flag_rreq_cc	= ProtoField.bool("uet.flags.rreq.cc",		"CC",			16, yes_no, 0x0100)
fld.flag_rreq_ar	= ProtoField.bool("uet.flags.rreq.ar",		"AR (ACK Requested)",	16, yes_no, 0x0080)
fld.flag_rreq_retx	= ProtoField.bool("uet.flags.rreq.retx",	"RETX (is retransmit)",	16, yes_no, 0x0040)
fld.flag_rreq_rsv	= ProtoField.bool("uet.flags.rreq.rsv",		"RSV",			16, yes_no, 0x0020)

-- N.B. masks shifted left by 5 bits (for ack_code)
fld.flag_ack_m			= ProtoField.bool("uet.flags.ack.m",			"M (ECN marked)",	16, yes_no, 0x0800)
fld.flag_ack_ax			= ProtoField.bool("uet.flags.ack.ax",			"AX (ACK Extension)",	16, yes_no, 0x0400)
fld.flag_ack_req		= ProtoField.uint16("uet.flags.ack.req",		"Requests",		base.DEC, nil, 0x0300)
fld.flag_ack_retry_delay	= ProtoField.uint16("uet.flags.ack.retry_delay",	"Retry Delay",		base.DEC, nil, 0x00c0)
fld.flag_ack_rsv		= ProtoField.bool("uet.flags.ack.rsv",			"RSV",			16, yes_no, 0x0020)

fld.ses_req			= ProtoField.none("uet.ses.req",			"SES request") -- FIXME: Proto()?
fld.ses_req_rsv			= ProtoField.uint8("uet.ses.req.rsv",			"Reserved",			base.DEC, nil, 0xc0)
fld.ses_req_opcode		= ProtoField.uint8("uet.ses.req.opcode",		"Opcode",			base.HEX, nil, 0x3f)
fld.ses_req_ver			= ProtoField.uint8("uet.ses.req.version",		"Version",			base.HEX, nil, 0xc0)
fld.ses_req_flag_dc		= ProtoField.bool("uet.ses.req.flags.dc",		"Delivery Complete (DC)",	8, yes_no, 0x20)
fld.ses_req_flag_ie		= ProtoField.bool("uet.ses.req.flags.ie",		"Initiator Error (IE)",		8, yes_no, 0x10)
fld.ses_req_flag_relative	= ProtoField.bool("uet.ses.req.flags.relative",		"Relative",			8, yes_no, 0x08)
fld.ses_req_flag_response	= ProtoField.bool("uet.ses.req.flags.response",		"Response requested",		8, yes_no, 0x04)
fld.ses_req_flag_hd		= ProtoField.bool("uet.ses.req.flags.hd",		"Header Data (HD)",		8, yes_no, 0x02)
fld.ses_req_flag_som		= ProtoField.bool("uet.ses.req.flags.som",		"Start of Message (SOM)",	8, yes_no, 0x01)
fld.ses_req_rsv2		= ProtoField.uint16("uet.ses.req.rsv2",			"Reserved",			base.HEX, nil, 0xf000)
fld.ses_req_index		= ProtoField.uint16("uet.ses.req.index",		"Index",			base.DEC, nil, 0x0fff)
fld.ses_req_index_gen		= ProtoField.uint8("uet.ses.req.index_gen",		"Index generation",		base.DEC)
fld.ses_req_job_id		= ProtoField.uint8("uet.ses.req.job_id",		"Job ID",			base.HEX)
fld.ses_req_rsv3		= ProtoField.uint16("uet.ses.req.rsv3",			"Reserved",			base.HEX, nil, 0xf000)
fld.ses_req_pidonfep		= ProtoField.uint16("uet.ses.req.pid_on_fep",		"PID on FEP",			base.DEC, nil, 0x0fff)
fld.ses_req_msgid		= ProtoField.uint16("uet.ses.req.message_id",		"Message ID",			base.DEC)
fld.ses_req_rsv4		= ProtoField.uint64("uet.ses.req.rsv4",			"Reserved",			base.HEX, nil, 0xfe00000000000000)
fld.ses_req_buff_offs		= ProtoField.uint64("uet.ses.req.buffer_offset",	"Buffer offset",		base.HEX, nil, 0x01ffffffffffffff)
fld.ses_req_initiator		= ProtoField.uint32("uet.ses.req.initiator",		"Initiator",			base.HEX)
fld.ses_req_match_bits		= ProtoField.uint64("uet.ses.req.match_bits",		"Match bits",			base.HEX)
fld.ses_req_hdr_data		= ProtoField.uint64("uet.ses.req.header_data",		"Header data",			base.HEX)
fld.ses_req_len			= ProtoField.uint64("uet.ses.req.len",			"Request length",		base.DEC)
fld.ses_req_payload_offs	= ProtoField.uint32("uet.ses.req.packet_offset",	"Packet offset",		base.DEC)
fld.ses_req_payload_len		= ProtoField.uint32("uet.ses.req.packet_len",		"Packet length",		base.DEC) -- FIXME: 14 bits?

local dissect_data	= Dissector.get("data")

function p_uet.dissector(buf, pinfo, root)
	pinfo.cols.protocol = p_uet.name

	local subtree = root:add(p_uet, buf)
	subtree:add(fld.entropy, buf(0, 2))
	subtree:add(fld.type, buf(2, 2))
	local h_type = buf(2, 1):bitfield(0, 4)
	local type_str = types[h_type]
	local summary = ""
	local offset = 4
	if type_str ~= nil then
		summary = type_str
	end

	if h_type == TYPE_RUD_REQ or h_type == TYPE_ROD_REQ then
		local flags_tree = subtree:add(fld.flags, buf(2, 2))
		subtree:add(fld.next_hdr, buf(2, 2))
		flags_tree:add(fld.flags, buf(2, 2)) -- FIXME? helps eyeballing the bits for now.
		flags_tree:add(fld.flag_rreq_syn, buf(2, 2))
		flags_tree:add(fld.flag_rreq_clr, buf(2, 2))
		flags_tree:add(fld.flag_rreq_cc, buf(2, 2))
		flags_tree:add(fld.flag_rreq_ar, buf(2, 2))
		flags_tree:add(fld.flag_rreq_retx, buf(2, 2))
		flags_tree:add(fld.flag_rreq_rsv, buf(2, 2))

		subtree:add(fld.psn, buf(4, 4))
		subtree:add(fld.spdcid, buf(8, 2))
		-- TODO: mode&offset for SYN
		subtree:add(fld.dpdcid, buf(10, 2))
		offset = offset + 8
		-- TODO: clear
		-- TODO: cc_state

		local h_next = buf(3, 1):bitfield(3, 5)
		summary = summary .. " " .. h_next
		-- TODO: distinct Proto()
		if h_next == HDR_REQ_STD then
			local req_tree = subtree:add(fld.ses_req, buf(offset, 44))
			req_tree:add(fld.ses_req_rsv, buf(offset, 1))
			req_tree:add(fld.ses_req_opcode, buf(offset, 1))
			req_tree:add(fld.ses_req_ver, buf(offset+1, 1))
			req_tree:add(fld.ses_req_flag_dc, buf(offset+1, 1))
			req_tree:add(fld.ses_req_flag_ie, buf(offset+1, 1))
			req_tree:add(fld.ses_req_flag_relative, buf(offset+1, 1))
			req_tree:add(fld.ses_req_flag_response, buf(offset+1, 1))
			req_tree:add(fld.ses_req_flag_hd, buf(offset+1, 1))
			req_tree:add(fld.ses_req_flag_som, buf(offset+1, 1))
			local is_som = buf(offset+1, 1):bitfield(7, 1)
			req_tree:add(fld.ses_req_rsv2, buf(offset+2, 2))
			req_tree:add(fld.ses_req_index, buf(offset+2, 2))
			req_tree:add(fld.ses_req_index_gen, buf(offset+4, 1))
			req_tree:add(fld.ses_req_job_id, buf(offset+5, 3))
			req_tree:add(fld.ses_req_rsv3, buf(offset+8, 2))
			req_tree:add(fld.ses_req_pidonfep, buf(offset+8, 2))
			req_tree:add(fld.ses_req_msgid, buf(offset+10, 2))
			req_tree:add(fld.ses_req_rsv4, buf(offset+12, 8))
			req_tree:add(fld.ses_req_buff_offs, buf(offset+12, 8)) -- TODO: deferrable send
			req_tree:add(fld.ses_req_initiator, buf(offset+20, 4))
			req_tree:add(fld.ses_req_match_bits, buf(offset+24, 8))
			if is_som == 1 then
				req_tree:add(fld.ses_req_hdr_data, buf(offset+32, 8))
			else
				req_tree:add(fld.ses_req_payload_offs, buf(offset+32, 4))
				req_tree:add(fld.ses_req_payload_len, buf(offset+36, 4))
			end
			req_tree:add(fld.ses_req_len, buf(offset+40, 4))
			offset = offset + 44
		end
	end if h_type == TYPE_PDS_ACK then
		local flags_tree = subtree:add(fld.flags, buf(2, 2))
		subtree:add(fld.ack_code, buf(2, 2))
		flags_tree:add(fld.flags, buf(2, 2)) -- FIXME? helps eyeballing the bits for now.
		flags_tree:add(fld.flag_ack_m, buf(2, 2))
		flags_tree:add(fld.flag_ack_ax, buf(2, 2))
		flags_tree:add(fld.flag_ack_req, buf(2, 2))
		flags_tree:add(fld.flag_ack_retry_delay, buf(2, 2))
		flags_tree:add(fld.flag_ack_rsv, buf(2, 2))

		subtree:add(fld.psn, buf(4, 4)) -- TODO: ack_psn?
		subtree:add(fld.spdcid, buf(8, 2))
		subtree:add(fld.dpdcid, buf(10, 2))
		offset = offset + 8
	end

	if summary ~= "" then
		pinfo.cols.info = summary
	end

	local pktlen = buf:len() - offset
	local data_buf = buf(offset, pktlen)
	dissect_data:call(data_buf:tvb(), pinfo, subtree)
end

function p_uet:init()
	local ip_table = DissectorTable.get("ip.proto")
	ip_table:add(p_uet.prefs["ip_proto"], p_uet)
end
