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

local fld = p_uet.fields
fld.entropy = ProtoField.uint16("uet.entropy", "Entropy", base.DEC)
fld.type = ProtoField.uint16("uet.type", "Type", base.HEX, types, 0xf000)
fld.flags = ProtoField.uint16("uet.flags", "Flags", base.HEX, nil, 0x0fe0)
fld.next_hdr = ProtoField.uint16("uet.next_hdr", "Next Header", base.HEX, nil, 0x001f)
fld.ack_code = ProtoField.uint16("uet.ack.code", "ACK code", base.HEX, nil, 0x001f)
fld.psn = ProtoField.uint32("uet.psn", "Packet Sequence Number", base.DEC)
fld.spdcid = ProtoField.uint16("uet.spdcid", "Source PDC ID", base.DEC)
fld.dpdcid = ProtoField.uint16("uet.dpdcid", "Destination PDC ID", base.DEC)

-- N.B. masks shifted left by 5 bits (for next_hdr)
fld.flag_rreq_syn = ProtoField.bool("uet.flags.rreq.syn", "SYN", 16, {"Yes", "No"}, 0x800)
fld.flag_rreq_clr = ProtoField.uint16("uet.flags.rreq.clr", "CLR", base.DEC, nil, 0x0600)
fld.flag_rreq_cc = ProtoField.bool("uet.flags.rreq.cc", "CC", 16, {"Yes - Congestion Control State present", "No"}, 0x0100)
fld.flag_rreq_ar = ProtoField.bool("uet.flags.rreq.ar", "AR (ACK Requested)", 16, {"Yes", "No"}, 0x0080)
fld.flag_rreq_retx = ProtoField.bool("uet.flags.rreq.retx", "RETX (is retransmit)", 16, {"Yes", "No"}, 0x0040)
fld.flag_rreq_rsv = ProtoField.bool("uet.flags.rreq.rsv", "RSV", 16, {"Yes", "No"}, 0x0020)

local dissect_data = Dissector.get("data")

function p_uet.dissector(buf, pinfo, root)
	pinfo.cols.protocol = p_uet.name

	local subtree = root:add(p_uet, buf)
	subtree:add(fld.entropy, buf(0, 2))
	subtree:add(fld.type, buf(2, 2))
	local h_type = buf(2, 1):bitfield(0, 4)
	local type_str = types[h_type]
	local summary = ""
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
		-- TODO: clear
		-- TODO: cc_state
	end if h_type == TYPE_PDS_ACK then
		local flags_tree = subtree:add(fld.flags, buf(2, 2))
		subtree:add(fld.ack_code, buf(2, 2))
		flags_tree:add(fld.flags, buf(2, 2)) -- FIXME? helps eyeballing the bits for now.
	end

	if summary ~= "" then
		pinfo.cols.info = summary
	end

	local offset = 12
	local pktlen = buf:len() - offset
	local data_buf = buf(offset, pktlen)
	dissect_data:call(data_buf:tvb(), pinfo, subtree)
end

function p_uet:init()
	local ip_table = DissectorTable.get("ip.proto")
	ip_table:add(p_uet.prefs["ip_proto"], p_uet)
end
