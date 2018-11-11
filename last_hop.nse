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
description = [[
	send udp packet with big port to get network distance(ttl) from source to target.
	using the ttl to get last hop of the traget.
]]

---
-- @usage
-- sudo nmap --script last_hop --script-args='ip_file=ip.filename.path'
-- 
-- @output
-- | get last hop: 
-- |   network distance: ttl value
-- |_  last hop : ip address 
--
--

-- Version 0.01
-- Created 09/25/2018 - v0.01 - created by Liu Yang

author = "Liu Yang"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}
-- The Head Section --

prerule=function()
	return true
end
-- The Rule Section --
hostrule=function(host)
	--print("hostrule()")
return true
end
--portrule = function(host, port)
--return true
--print("portrule()")
--return port.state=="closed" 
--end
--建立监听线程
--用于接受icmp生存时间过期报文
--从中提取末跳路由器信息
local function icmp_tole_listener(signal)
	print("\nbegin icmp time to live exceeded packet listener...")
	local icmp_tole_rec_socket=nmap.new_socket()
	local capture_rule="(icmp[0]=11) and (icmp[1]=0)"
	icmp_tole_rec_socket:pcap_open("eno2",128,false,capture_rule)
	icmp_tole_rec_socket:set_timeout(15000)
	local status,len,l2_icmp_t_l,l3_icmp_tol,time
	status=true
	local condvar=nmap.condvar(signal)
	local get_last_hop_count=0
	while signal['status']==0  do
		status,len,l2_icmp_t_l,l3_icmp_tol,time=icmp_tole_rec_socket:pcap_receive()
		if status then
			--stdnse.sleep(5)
			get_last_hop_count=get_last_hop_count+1
			--print("\n\n\nreceive icmp time to live exceeded packet...")
			--print("parse packet...")
			local last_hop_packet = packet.Packet:new(l3_icmp_tol, #l3_icmp_tol)
			local raw_sender_data_in_l3_icmp_tol_packet=l3_icmp_tol:sub(last_hop_packet.icmp_payload_offset+1)
			local raw_sender_packet_in_l3_icmp_tol_packet=packet.Packet:new(raw_sender_data_in_l3_icmp_tol_packet,#raw_sender_data_in_l3_icmp_tol_packet)
			local dst_ip=raw_sender_packet_in_l3_icmp_tol_packet.ip_dst
			
			for k,v in pairs(last_hop_packet) do
				if k=="ip_ttl" then
					--print(k,v)
				end
				if k=="ip_src" then
					--print(dst_ip,v)
				end
			end
		else
			print("no icmp ttl exceeded packet back!")
		end
	end
	print("get_last_hop_count:",get_last_hop_count)
	icmp_tole_rec_socket:close()
	condvar("signal")
end
--建立监听线程
--用于接受icmp端口不可达包
--
-- @param icmp_pu_listener function name
-- @param send_l3_sock l3 layer raw socket
local function icmp_pu_listener(send_l3_sock,signal)
	print("\nbegin icmp port unreachable listener...")
	local icmp_pu_rec_socket=nmap.new_socket()
	icmp_pu_rec_socket:pcap_open("eno2",70,false,"(icmp[0]=3) and (icmp[1]=3) and (icmp[30]=0xff) and (icmp[31]=0xfe)")
	icmp_pu_rec_socket:set_timeout(15000)
	local condvar = nmap.condvar(signal)
	local icmp_pu_count=0
	local status,len,l2_icmp_pu_data,l3_icmp_pu_data,time
	status=true
	while signal['status']==0 do
		--pcap_receive()方法似乎不会因收包后的解析产生的延迟而错过网络中到达的数据包
		--使用stdnse.sleep(10)故意延迟，仍然未遗漏数据包
		status,len,l2_icmp_pu_data,l3_icmp_pu_data,time=icmp_pu_rec_socket:pcap_receive()
		if status then
			icmp_pu_count=icmp_pu_count+1
			--print("\n\nreceive icmp port unreachable packet...")
			--stdnse.sleep(10)
			--print("parse for getting left ttl in packet...")
			local l3_icmp_pu_packet = packet.Packet:new(l3_icmp_pu_data, #l3_icmp_pu_data)
			--print(l3_icmp_pu_packet.ip_src)
			local raw_sender_data_in_l3_icmp_pu_packet=l3_icmp_pu_data:sub(l3_icmp_pu_packet.icmp_payload_offset+1)
			--print("icmp payload size:",#raw_sender_data_in_l3_icmp_pu_packet)
			local raw_sender_packet_in_l3_icmp_pu_packet=packet.Packet:new(raw_sender_data_in_l3_icmp_pu_packet,#raw_sender_data_in_l3_icmp_pu_packet)

			local left_ttl=0
			if raw_sender_packet_in_l3_icmp_pu_packet.ip_ttl>64
			then
				if raw_sender_packet_in_l3_icmp_pu_packet.ip_ttl>128
				then
					left_ttl=256-raw_sender_packet_in_l3_icmp_pu_packet.ip_ttl
				else
					left_ttl=128-raw_sender_packet_in_l3_icmp_pu_packet.ip_ttl
				end
			else
				left_ttl=64-raw_sender_packet_in_l3_icmp_pu_packet.ip_ttl
			end
			--print("icmp pu:",l3_icmp_pu_packet.ip_src,l3_icmp_pu_packet.ip_dst)
			--print("get left_ttl value:",raw_sender_packet_in_l3_icmp_pu_packet.ip_ttl)
			--print("set new ttl:",left_ttl)
			--print("send new packet for sniffer last hop...")
			raw_sender_packet_in_l3_icmp_pu_packet:ip_set_ttl(left_ttl)
			---print("packet.buf len:",#raw_sender_packet_in_l3_icmp_pu_packet.buf)
			send_l3_sock:ip_send(raw_sender_packet_in_l3_icmp_pu_packet.buf)
		else
			--print("no icmp port unreachable packet back!")
		---local p2=packet.Packet:build_ip_packet(p1.ip_src,p1.ip_dst,"123",0,0xbeef,0,left_ttl,"1")
		end
	end
	print("get icmp_pu_count:",icmp_pu_count)
	icmp_pu_rec_socket:close()
	condvar("signal")
end
-- The Action Section --
--action = function(host, port)
action = function()

host_ip="213.42.193.165"
--print("target:",host_ip)
print("**************************************************")
--建立发送l3层报文的raw socket
--用于发送设置了ttl的探测末跳报文
local send_l3_sock = nmap.new_dnet()
send_l3_sock:ip_open()
local icmp_pu_listener_signal={}
local icmp_pu_listener_condvar = nmap.condvar(icmp_pu_listener_signal)
icmp_pu_listener_signal['status']=0
--建立监听线程
--用于接受icmp端口不可达包
--
-- @param icmp_pu_listener function name
-- @param send_l3_sock l3 layer raw socket
-- @param icmp_pu_listener_signal listener stop signal
local icmp_pu_listener_handler=stdnse.new_thread(icmp_pu_listener,send_l3_sock,icmp_pu_listener_signal)

local icmp_tole_listener_signal={}
local icmp_tole_listener_condvar = nmap.condvar(icmp_tole_listener_signal)
icmp_tole_listener_signal['status']=0
--建立监听线程，用于接收icmp生存时间过期报文
--
-- @param icmp_pu_listener function name
-- @param icmp_tole_listener_signal listener stop signal
local icmp_tole_listener_handler=stdnse.new_thread(icmp_tole_listener,icmp_tole_listener_signal)

stdnse.sleep(1)
--建立基于udp的socket
--用于发送udp大端口报文
local send_udp_socket=nmap.new_socket("udp")
--3.live.ttl64.pcap.left_ttl

local ip_file=stdnse.get_script_args("last_hop.ip_file")
--ip_file="ip10wt"
local ip_count=0
for line in io.lines(ip_file) do
	local ip=stdnse.strsplit(" ", line)
	--print(ip[1])
	--print(line,":send udp packet, port:65534")
	send_udp_socket:sendto(ip[1],65534,"")
	ip_count=ip_count+1
	if ip_count % 101==0 then
		--print("send upd sleep 10s...")
		stdnse.sleep(4)
	end
end
send_udp_socket:close()
stdnse.sleep(5)
icmp_tole_listener_signal['status']=1
icmp_pu_listener_signal['status']=1
repeat
	if coroutine.status(icmp_tole_listener_handler)=="dead" then
		icmp_tole_listener_handler=nil
	else
		print("wait icmp time to live exceeded listener end...")
		icmp_tole_listener_condvar("wait")
		--print("wait icmp test...")
	end
until icmp_tole_listener_handler==nil
repeat
	if coroutine.status(icmp_pu_listener_handler)=="dead" then
		icmp_pu_listener_handler=nil
	else 
		print("wait for icmp port unreachable listener end...")
		icmp_pu_listener_condvar("wait")
	end
until icmp_pu_listener_handler==nil


send_l3_sock:ip_close()
print("**************************************************")
return true
end
