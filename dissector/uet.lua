-- UltraEthernet wireshark dissector
-- Copyright Keysight Technologies 2024
--
-- To use this dissector, make it available in the wireshark plugins
-- directory, for example:
--
-- ln -sf $(pwd)/uet.lua ~/.config/wireshark/plugins/

p_uet = Proto("uet", "UltraEthernet Transport")
p_uet.prefs["ip_proto"] = Pref.uint("IP protocol#", 253, "IP protocol number for UET")

local dissect_data = Dissector.get("data")

function p_uet.dissector(buf, pinfo, root)
	pinfo.cols.protocol = p_uet.name

	local offset = 0
	local pktlen = buf:len()
	local data_buf = buf(offset, pktlen)
	local subtree = root:add(p_uet, data_buf)
	dissect_data:call(data_buf:tvb(), pinfo, subtree)
end

function p_uet:init()
	local ip_table = DissectorTable.get("ip.proto")
	ip_table:add(p_uet.prefs["ip_proto"], p_uet)
end
