-- UltraEthernet wireshark dissector
-- Copyright Keysight Technologies 2024
--
-- To use this dissector, make it available in the wireshark plugins
-- directory, for example:
--
-- ln -sf $(pwd)/uet.lua ~/.config/wireshark/plugins/

p_uet = Proto("uet", "UltraEthernet Transport")
p_uet.prefs["ip_proto"] = Pref.uint("IP protocol#", 253, "IP protocol number for UET")

local types = {
	[0]	= "Reserved",
	[1]	= "UET Encryption header",
	[2]	= "RUD Request",
	[3]	= "ROD Request",
	[4]	= "RUDI Request",
	[5]	= "UUD Request",
	[6]	= "RUDI Response",
	[7]	= "PDS ACK",
	[8]	= "Control",
}

local fld = p_uet.fields
fld.entropy = ProtoField.uint16("uet.entropy", "Entropy", base.DEC)
fld.type = ProtoField.uint16("uet.type", "Type", base.HEX, types, 0xf000)
fld.flags = ProtoField.uint16("uet.flags", "Flags", base.HEX, nil, 0x0fe0)
fld.next_hdr = ProtoField.uint16("uet.next_hdr", "Next Header", base.HEX, nil, 0x001f)
fld.psn = ProtoField.uint32("uet.psn", "Packet Sequence Number", base.DEC)
fld.spdcid = ProtoField.uint16("uet.spdcid", "Source PDC ID", base.DEC)
fld.dpdcid = ProtoField.uint16("uet.dpdcid", "Destination PDC ID", base.DEC)

-- N.B. masks shifted left by 5 bits (for next_hdr)
fld.flag_syn = ProtoField.bool("uet.flags.syn", "SYN", 16, {"Yes", "No"}, 0x800)
fld.flag_clr = ProtoField.uint16("uet.flags.clr", "CLR", base.DEC, nil, 0x0600)
fld.flag_cc = ProtoField.bool("uet.flags.cc", "CC", 16, {"Yes - Congestion Control State present", "No"}, 0x0100)
fld.flag_ar = ProtoField.bool("uet.flags.ar", "AR (ACK Requested)", 16, {"Yes", "No"}, 0x0080)
fld.flag_retx = ProtoField.bool("uet.flags.retx", "RETX (is retransmit)", 16, {"Yes", "No"}, 0x0040)
fld.flag_rsv = ProtoField.bool("uet.flags.rsv", "RSV", 16, {"Yes", "No"}, 0x0020)

local dissect_data = Dissector.get("data")

function p_uet.dissector(buf, pinfo, root)
	pinfo.cols.protocol = p_uet.name

	local subtree = root:add(p_uet, buf)
	subtree:add(fld.entropy, buf(0, 2))
	subtree:add(fld.type, buf(2, 2))
	local flags_tree = subtree:add(fld.flags, buf(2, 2))
	subtree:add(fld.next_hdr, buf(2, 2))
	-- TODO: per-type
	flags_tree:add(fld.flags, buf(2, 2)) -- FIXME? helps eyeballing the bits for now.
	flags_tree:add(fld.flag_syn, buf(2, 2))
	flags_tree:add(fld.flag_clr, buf(2, 2))
	flags_tree:add(fld.flag_cc, buf(2, 2))
	flags_tree:add(fld.flag_ar, buf(2, 2))
	flags_tree:add(fld.flag_retx, buf(2, 2))
	flags_tree:add(fld.flag_rsv, buf(2, 2))

	subtree:add(fld.psn, buf(4, 4))
	subtree:add(fld.spdcid, buf(8, 2))
	-- TODO: mode&offset for SYN
	subtree:add(fld.dpdcid, buf(10, 2))

	-- TODO: clear
	-- TODO: cc_state

	local h_type = buf(2, 1):bitfield(0, 4)
	local type_str = types[h_type]
	if type_str ~= nil then
		pinfo.cols.info = type_str
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
