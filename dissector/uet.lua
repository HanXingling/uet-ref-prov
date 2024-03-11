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

local dissect_data = Dissector.get("data")

function p_uet.dissector(buf, pinfo, root)
	pinfo.cols.protocol = p_uet.name

	local subtree = root:add(p_uet, data_buf)
	subtree:add(fld.entropy, buf(0, 2))
	subtree:add(fld.type, buf(2, 2))
	subtree:add(fld.flags, buf(2, 2))
	subtree:add(fld.next_hdr, buf(2, 2))

	local h_type = buf(2, 1):bitfield(0, 4)
	local type_str = types[h_type]
	if type_str ~= nil then
		pinfo.cols.info = type_str
	end

	local offset = 0
	local pktlen = buf:len()
	local data_buf = buf(offset, pktlen)
	dissect_data:call(data_buf:tvb(), pinfo, subtree)
end

function p_uet:init()
	local ip_table = DissectorTable.get("ip.proto")
	ip_table:add(p_uet.prefs["ip_proto"], p_uet)
end
