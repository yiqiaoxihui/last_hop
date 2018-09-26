local bin = require "bin"
local coroutine = require "coroutine"
local dhcp = require "dhcp"
local ipOps = require "ipOps"
local math = require "math"
local nmap = require "nmap"
local packet = require "packet"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
-- The Head Section --
-- The Rule Section --
--prerule=function()
--	print("prerule()")
--end
hostrule=function(host)
	print("hostrule()")
return true
end
--portrule = function(host, port)
--return true
--print("portrule()")
--return port.state=="closed" 
--end
-- The Action Section --
action = function(host, port)
print(host.ip)
local ss=nmap.new_socket("udp")
local sr=nmap.new_socket()
sr:pcap_open("eno2",70,false,"(icmp[0]=3) and (icmp[1]=3)")

ss:sendto(host.ip,65534,"")
local status,len,l2,l3,time=sr:pcap_receive()
sr:close()
ss:close()
if status then
	print(len)
	local p = packet.Packet:new(l3, #l3)
	print(type(p))
	for k,v in pairs(p) do
		--print(k)
		--print(v)
	end
	--print("parse ip header")
	local ip_h=p:ip_parse()
	for k,v in pairs(p) do
		--print(k)
		--print(v)
	end	
	print("try to get in icmp ip")
	local in_icmp_ip=l3:sub(p.icmp_payload_offset+1)
	print("l2 len:",#l2)
	print("l3 len:",#l3)

	print("in_icmp_ip",#in_icmp_ip)
	local p1=packet.Packet:new(in_icmp_ip,#in_icmp_ip)

	local left_ttl=0
	if p1.ip_ttl>64
	then
		if p1.ip_ttl>128
		then
			left_ttl=256-p1.ip_ttl
		else
			left_ttl=128-p1.ip_ttl
		end
	else
		left_ttl=64-p1.ip_ttl
	end
	print("left_ttl:",left_ttl)
	p1:ip_set_ttl(left_ttl)
	for k,v in pairs(p1) do
		--print(k)
		--print(v)
	end
	print("packet.buf:",#p1.buf)
	local raw_sock = nmap.new_dnet()
	local sr=nmap.new_socket()
	local capture_rule="(icmp[0]=11) and (icmp[1]=0)"
	sr:pcap_open("eno2",128,false,capture_rule)

	raw_sock:ip_open()
	raw_sock:ip_send(p1.buf)
	local status,len,l2,l3,time=sr:pcap_receive()
	raw_sock:ip_close()
	sr:close()
	local last_hop_packet = packet.Packet:new(l3, #l3)

	for k,v in pairs(last_hop_packet) do
		print(k)
		print(v)
	end
	--local p2=packet.Packet:build_ip_packet(p1.ip_src,p1.ip_dst,"123",0,0xbeef,0,left_ttl,"1")
end


return status
end
