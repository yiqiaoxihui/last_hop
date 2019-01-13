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

-- prerule=function()
-- 	return true
-- end
-- The Rule Section --
hostrule=function(host)
	--print("hostrule:",host.ip)
	return true
end
portrule = function(host)
--return true
	print("portrule:",host.ip)
--return port.state=="closed" 
end
local function set_ttl_to_ping(iface,send_l3_sock,dst_ip,ttl)
	local ip=packet.Packet:new()
	ip.ip_bin_dst=ipOps.ip_to_str(dst_ip)
	ip.ip_bin_src = ipOps.ip_to_str(iface.address)
	ip:build_icmp_echo_request()
	ip:build_icmp_header()
	ip:build_ip_packet()
	ip.echo_data = "a"
	ip.ip_offset=0
	ip:ip_set_ttl(ttl)
	send_l3_sock:ip_send(ip.buf)
end
--建立监听线程
--用于接受icmp生存时间过期报文
--从中提取末跳路由器信息
local function icmp_tole_listener(signal,ip,iface)
	--print("\nbegin icmp time to live exceeded packet listener...")
	local icmp_tole_rec_socket=nmap.new_socket()
	local str_hex_ip=ipOps.todword(ip)
	--print("str hex ip:",str_hex_ip)
	local capture_rule="(icmp[0]=11) and (icmp[1]=0) and icmp[24:4]="..str_hex_ip
	icmp_tole_rec_socket:pcap_open(iface.device,128,false,capture_rule)
	icmp_tole_rec_socket:set_timeout(5000)
	local status,len,l2_icmp_t_l,l3_icmp_tol,time
	local condvar=nmap.condvar(signal)
	while signal['status']==0 do
		status,len,l2_icmp_t_l,l3_icmp_tol,time=icmp_tole_rec_socket:pcap_receive()
		if status then
			--print("\n\n\nreceive icmp time to live exceeded packet...")
			--print("parse packet...")
			signal['last_hop']=1
			signal['status']=1
			local last_hop_packet = packet.Packet:new(l3_icmp_tol, #l3_icmp_tol)
			local raw_sender_data_in_l3_icmp_tol_packet=l3_icmp_tol:sub(last_hop_packet.icmp_payload_offset+1)
			local raw_sender_packet_in_l3_icmp_tol_packet=packet.Packet:new(raw_sender_data_in_l3_icmp_tol_packet,#raw_sender_data_in_l3_icmp_tol_packet)
			local dst_ip=raw_sender_packet_in_l3_icmp_tol_packet.ip_dst
			
			for k,v in pairs(last_hop_packet) do
				if k=="ip_ttl" then
					--print(k,v)
				end
				if k=="ip_src" then
					print("#",ip,dst_ip,v)
				end
			end
		else
			--print("no icmp ttl exceeded packet back!")
		end
	end
	icmp_tole_rec_socket:close()
	condvar("signal")
end
--建立监听线程
--用于接受icmp端口不可达包
--
-- @param icmp_pu_listener function name
-- @param send_l3_sock l3 layer raw socket
local function icmp_pu_listener(send_l3_sock,signal,ip,iface)
	--print("\nbegin icmp port unreachable listener...")
	local icmp_pu_rec_socket=nmap.new_socket()
	local capture_rule="(icmp[0]=3) and (icmp[1]=3) and host "..ip
	icmp_pu_rec_socket:pcap_open(iface.device,70,false,capture_rule)
	icmp_pu_rec_socket:set_timeout(5000)
	local condvar = nmap.condvar(signal)
	local status,len,l2_icmp_pu_data,l3_icmp_pu_data,time
	--pcap_receive()方法似乎不会因收包后的解析产生的延迟而错过网络中到达的数据包
	--使用stdnse.sleep(10)故意延迟，仍然未遗漏数据包
	while signal['status']==0 do
		status,len,l2_icmp_pu_data,l3_icmp_pu_data,time=icmp_pu_rec_socket:pcap_receive()
		if status then
			--print("\n\nreceive icmp port unreachable packet...")
			--stdnse.sleep(10)
			--print("parse for getting left ttl in packet...")
			signal['status']=1
			local l3_icmp_pu_packet = packet.Packet:new(l3_icmp_pu_data, #l3_icmp_pu_data)
			print("icmp pu:",ip,l3_icmp_pu_packet.ip_src,l3_icmp_pu_packet.ip_dst)
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
			--print("get left_ttl value:",raw_sender_packet_in_l3_icmp_pu_packet.ip_ttl)
			--print("set new ttl:",left_ttl)
			--print("send new packet for sniffer last hop...")

			--raw_sender_packet_in_l3_icmp_pu_packet:ip_set_ttl(left_ttl)
			---print("packet.buf len:",#raw_sender_packet_in_l3_icmp_pu_packet.buf)
			set_ttl_to_ping(iface,send_l3_sock,ip,left_ttl)
			--send_l3_sock:ip_send(raw_sender_packet_in_l3_icmp_pu_packet.buf)
		else
			--print("no icmp port unreachable packet back!")
		---local p2=packet.Packet:build_ip_packet(p1.ip_src,p1.ip_dst,"123",0,0xbeef,0,left_ttl,"1")
		end
	end
	icmp_pu_rec_socket:close()
	condvar("signal")
end
-- The Action Section --
--action = function(host, port)

action = function(host)
local ifname = nmap.get_interface() or host.interface
if ( not(ifname) ) then
	return fail("Failed to determine the network interface name")
end
local iface = nmap.get_interface_info(ifname)
print("action:",host.ip)
--print("**************************************************")
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
local icmp_pu_listener_handler=stdnse.new_thread(icmp_pu_listener,send_l3_sock,icmp_pu_listener_signal,host.ip,iface)

local icmp_tole_listener_signal={}
local icmp_tole_listener_condvar = nmap.condvar(icmp_tole_listener_signal)
icmp_tole_listener_signal['status']=0
icmp_tole_listener_signal['last_hop']=0
--建立监听线程，用于接收icmp生存时间过期报文
--
-- @param icmp_pu_listener function name
-- @param icmp_tole_listener_signal listener stop signal
local icmp_tole_listener_handler=stdnse.new_thread(icmp_tole_listener,icmp_tole_listener_signal,host.ip,iface)

stdnse.sleep(2) 	--test,需要缓冲时间，保证线程全部启动
--建立基于udp的socket
--用于发送udp大端口报文
print("\n\nsend upd big port packet")
local send_udp_socket=nmap.new_socket("udp")
send_udp_socket:sendto(host.ip,65534,"")

-- stdnse.sleep(2) 	--test,
-- if icmp_tole_listener_signal['last_hop']==1 then
-- 	print("#get_last_hop:",host.ip)
-- end
icmp_tole_listener_signal['status']=1
icmp_pu_listener_signal['status']=1
repeat
	if coroutine.status(icmp_pu_listener_handler)=="dead" then
		icmp_pu_listener_handler=nil
	else
		--print("wait for icmp port unreachable listener end...")
		icmp_pu_listener_condvar("wait")
	end
until icmp_pu_listener_handler==nil
repeat
	if coroutine.status(icmp_tole_listener_handler)=="dead" then
		icmp_tole_listener_handler=nil
	else
		--print("wait icmp time to live exceeded listener end...")
		icmp_tole_listener_condvar("wait")
		--print("wait icmp test...")
	end
until icmp_tole_listener_handler==nil
send_l3_sock:ip_close()
send_udp_socket:close()

--print("**************************************************")
return true
end
