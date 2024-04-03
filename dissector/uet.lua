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

local req_opcodes = {
	[0]			= "UET_NO_OP",
	[0x01]			= "UET_WRITE - RMA Write",
	[0x05]			= "UET_SEND - (non-matching) send operation",
	[0x09]			= "UET_TAGGED_SEND",
}
local resp_opcodes = {
	[0]			= "UET_DEFAULT_RESPONSE",
	[1]			= "UET_RESPONSE",
	[2]			= "UET_RESPONSE_W_DATA",
}

local yes_no = {"Yes", "No"}
local fld = p_uet.fields
fld.entropy	= ProtoField.uint16("uet.entropy",	"Entropy",				base.DEC)
fld.type	= ProtoField.uint16("uet.type",		"Type",					base.HEX, types, 0xf000)
fld.next_hdr	= ProtoField.uint16("uet.next_hdr",	"Next Header",				base.HEX, hdr_types, 0xf80)
fld.flags	= ProtoField.uint16("uet.flags",	"Flags",				base.HEX, nil, 0x07f)
fld.psn		= ProtoField.uint32("uet.psn",		"Packet Sequence Number",		base.DEC)
fld.spdcid	= ProtoField.uint16("uet.spdcid",	"Source PDC ID",			base.DEC)
fld.dpdcid	= ProtoField.uint16("uet.dpdcid",	"Destination PDC ID",			base.DEC)
fld.forward_psn	= ProtoField.uint32("uet.forward_psn",	"Forward Packet Sequence Number",	base.DEC)

-- ROD/RUD request flags
fld.flag_rreq_syn	= ProtoField.bool("uet.flags.rreq.syn",		"SYN",			16, yes_no, 0x40)
fld.flag_rreq_clr	= ProtoField.bool("uet.flags.rreq.clr",		"CLR (Clear)",		16, {"Specific PSN", "Cumulative"}, 0x20)
fld.flag_rreq_cc	= ProtoField.bool("uet.flags.rreq.cc",		"CC state present",	16, yes_no, 0x10)
fld.flag_rreq_ar	= ProtoField.bool("uet.flags.rreq.ar",		"AR (ACK Request)",	16, yes_no, 0x08)
fld.flag_rreq_retx	= ProtoField.bool("uet.flags.rreq.retx",	"RETX (is retransmit)",	16, yes_no, 0x04)
fld.flag_rreq_rsv	= ProtoField.bool("uet.flags.rreq.rsv",		"RSV",			16, nil, 0x03)

-- ACK flags
fld.flag_ack_m			= ProtoField.bool("uet.flags.ack.m",			"M (ECN marked)",	16, yes_no, 0x40)
fld.flag_ack_ax			= ProtoField.bool("uet.flags.ack.ax",			"AX (ACK Extension)",	16, yes_no, 0x20)
fld.flag_ack_req		= ProtoField.uint16("uet.flags.ack.req",		"Requests",		base.DEC, nil, 0x18)
fld.flag_ack_probe		= ProtoField.bool("uet.flags.ack.probe",		"Probe",		16, yes_no, 0x04)
fld.flag_ack_rsv		= ProtoField.bool("uet.flags.ack.rsv",			"RSV",			16, nil, 0x03)

fld.ses_req			= ProtoField.none("uet.ses.req",			"SES request") -- FIXME: Proto()?
fld.ses_req_flag_eom		= ProtoField.bool("uet.ses.req.flags.eom",		"End of Message (EOM)",		8, yes_no, 0x80)
fld.ses_req_rsv			= ProtoField.uint8("uet.ses.req.rsv",			"Reserved",			base.HEX, nil, 0x40)
fld.ses_req_opcode		= ProtoField.uint8("uet.ses.req.opcode",		"Opcode",			base.HEX, req_opcodes, 0x3f)
fld.ses_req_ver			= ProtoField.uint8("uet.ses.req.version",		"Version",			base.HEX, nil, 0xc0)
fld.ses_req_flag_dc		= ProtoField.bool("uet.ses.req.flags.dc",		"Delivery Complete (DC)",	8, yes_no, 0x20)
fld.ses_req_flag_ie		= ProtoField.bool("uet.ses.req.flags.ie",		"Initiator Error (IE)",		8, yes_no, 0x10)
fld.ses_req_flag_relative	= ProtoField.bool("uet.ses.req.flags.relative",		"Relative",			8, yes_no, 0x08)
fld.ses_req_flag_response	= ProtoField.bool("uet.ses.req.flags.response",		"Response requested",		8, yes_no, 0x04)
fld.ses_req_flag_hd		= ProtoField.bool("uet.ses.req.flags.hd",		"Header Data (HD)",		8, yes_no, 0x02)
fld.ses_req_flag_som		= ProtoField.bool("uet.ses.req.flags.som",		"Start of Message (SOM)",	8, yes_no, 0x01)
fld.ses_index_gen		= ProtoField.uint8("uet.ses.index_gen",			"Index generation",		base.DEC)
fld.ses_job_id			= ProtoField.uint24("uet.ses.job_id",			"Job ID",			base.DEC)
fld.ses_req_rsv2		= ProtoField.uint16("uet.ses.req.rsv2",			"Reserved",			base.HEX, nil, 0xf000)
fld.ses_index			= ProtoField.uint16("uet.ses.index",			"Index",			base.DEC, nil, 0x0fff)
fld.ses_req_rsv3		= ProtoField.uint16("uet.ses.req.rsv3",			"Reserved",			base.HEX, nil, 0xf000)
fld.ses_req_pidonfep		= ProtoField.uint16("uet.ses.req.pid_on_fep",		"PID on FEP",			base.DEC, nil, 0x0fff)
fld.ses_msgid			= ProtoField.uint16("uet.ses.message_id",		"Message ID",			base.DEC, nil, 0xfe00000000000000)
fld.ses_req_buff_offs		= ProtoField.uint64("uet.ses.req.buffer_offset",	"Buffer offset",		base.HEX)
fld.ses_req_initiator		= ProtoField.uint32("uet.ses.req.initiator",		"Initiator",			base.HEX)
fld.ses_req_match_bits		= ProtoField.uint64("uet.ses.req.match_bits",		"Match bits",			base.HEX)
fld.ses_req_hdr_data		= ProtoField.uint64("uet.ses.req.header_data",		"Header data",			base.HEX)
fld.ses_req_len			= ProtoField.uint64("uet.ses.req.len",			"Request length",		base.DEC)
fld.ses_req_payload_offs	= ProtoField.uint32("uet.ses.req.packet_offset",	"Packet offset",		base.DEC)
fld.ses_req_payload_len		= ProtoField.uint32("uet.ses.req.packet_len",		"Packet length",		base.DEC)

fld.ses_resp			= ProtoField.none("uet.ses.resp",			"SES response") -- FIXME: Proto()?
fld.ses_resp_list		= ProtoField.uint16("uet.ses.resp.list",		"List",				base.DEC, nil, 0xc000)
fld.ses_resp_opcode		= ProtoField.uint16("uet.ses.resp.opcode",		"Opcode",			base.HEX, resp_opcodes, 0x3fff)
fld.ses_resp_ver		= ProtoField.uint8("uet.ses.resp.version",		"Version",			base.DEC, nil, 0xc)
fld.ses_resp_retcode		= ProtoField.uint8("uet.ses.resp.retcode",		"Return code",			base.HEX, nil, 0x3f)
-- ses_msgid
-- index_gen
-- job_id
fld.ses_resp_mod_len		= ProtoField.uint32("uet.ses.resp.mod_length",		"Modified length",		base.DEC)

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
		subtree:add(fld.next_hdr, buf(2, 2))
		local flags_tree = subtree:add(fld.flags, buf(2, 2))
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
		-- TODO: clear
		subtree:add(fld.forward_psn, buf(12, 2))
		offset = offset + 12
		-- TODO: cc_state
	end if h_type == TYPE_PDS_ACK then
		subtree:add(fld.next_hdr, buf(2, 2))
		local flags_tree = subtree:add(fld.flags, buf(2, 2))
		flags_tree:add(fld.flag_ack_m, buf(2, 2))
		flags_tree:add(fld.flag_ack_ax, buf(2, 2))
		flags_tree:add(fld.flag_ack_req, buf(2, 2))
		flags_tree:add(fld.flag_ack_probe, buf(2, 2))
		flags_tree:add(fld.flag_ack_rsv, buf(2, 2))

		subtree:add(fld.psn, buf(4, 4)) -- TODO: ack_psn?
		subtree:add(fld.spdcid, buf(8, 2))
		subtree:add(fld.dpdcid, buf(10, 2))
		offset = offset + 8
	end

	-- TODO: TYPE_CTRL
	if h_type ~= TYPE_CTRL then
		local h_next = buf(2, 2):bitfield(4, 5)
		-- TODO: distinct Proto()
		if h_next == HDR_REQ_STD then
			local opcode = buf(offset, 1):bitfield(2, 6)
			local opcode_str = req_opcodes[opcode]
			if opcode_str ~= nil then
				summary = summary .. " " .. opcode_str
			end

			local req_tree = subtree:add(fld.ses_req, buf(offset, 44))
			req_tree:add(fld.ses_req_flag_eom, buf(offset, 1))
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
				req_tree:add(fld.ses_req_payload_offs, buf(offset+32, 4))
				req_tree:add(fld.ses_req_payload_len, buf(offset+36, 4))
			end
			req_tree:add(fld.ses_req_len, buf(offset+40, 4))
			offset = offset + 44
		end if h_next == HDR_RSP then
			local opcode = buf(offset, 1):bitfield(2, 6)
			local opcode_str = resp_opcodes[opcode]
			if opcode_str ~= nil then
				summary = summary .. " " .. opcode_str
			end
			local resp_tree = subtree:add(fld.ses_resp, buf(offset, 12))
			resp_tree:add(fld.ses_resp_list, buf(offset, 1))
			resp_tree:add(fld.ses_resp_opcode, buf(offset, 1))
			resp_tree:add(fld.ses_resp_ver, buf(offset+1, 1))
			resp_tree:add(fld.ses_resp_retcode, buf(offset+1, 1))
			resp_tree:add(fld.ses_msgid, buf(offset+2, 2))
			resp_tree:add(fld.ses_index_gen, buf(offset+4, 1))
			resp_tree:add(fld.ses_job_id, buf(offset+5, 3))
			resp_tree:add(fld.ses_resp_mod_len, buf(offset+8, 4))
			offset = offset + 12
		end
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
