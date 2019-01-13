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
local dns = require "dns"
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


--建立监听线程
--用于接受icmp echo 响应报文
local function icmp_echo_listener(signal,ip,iface)
	print("begin icmp ping packet listener...")
	local icmp_echo_rec_socket=nmap.new_socket()
	local capture_rule="(icmp[0]=0) and (icmp[1]=0) and host "..ip
	icmp_echo_rec_socket:pcap_open(iface.device,128,false,capture_rule)
	icmp_echo_rec_socket:set_timeout(30000)
	local status,len,l2_icmp_e_r,l3_icmp_echo_reply,time
	local condvar=nmap.condvar(signal)
	local get_last_hop_count=0
	while signal['status']==0 do
		status,len,l2_icmp_e_r,l3_icmp_echo_reply,time=icmp_echo_rec_socket:pcap_receive()
		--signal['receive']=nil
		if status then
			signal['receive']=true
			local echo_reply_packet = packet.Packet:new(l3_icmp_echo_reply, #l3_icmp_echo_reply)
			signal['left_ttl']=echo_reply_packet.ip_ttl
		else
			print(ip,"no echo reply back!!!!!!")
			signal['receive']=nil
			signal['left_ttl']=0
		end		
	end
	
	--print("get_last_hop_count:",get_last_hop_count)
	icmp_echo_rec_socket:close()
	condvar("signal")
end


local function fail(err) return ("\n  ERROR: %s"):format(err or "") end

--猜测到目标的网络距离
--
-- @param iface
-- @param send_l3_sock: l3 layer raw socket
-- @param icmp_echo_listener_signal:receive echo reply signal
-- @param icmp_tole_listener_signal:receive time limit signal
-- @param ip:target ip
function guest_network_distance(iface,send_l3_sock,icmp_echo_listener_signal,ip)
	local pp=packet.Packet:new()
	local ttl_from_target_to_source=0
	local max_ttl = 30
	local min_ttl=1
	local mid_ttl
	local status=true
	local times=0
	local deviation_right,deviation_left
	local deviation_distance = 6	--or 5
	pp.ip_bin_dst=packet.iptobin(ip)
	pp.ip_bin_src = packet.iptobin(iface.address)
	--pp.echo_id = 12
	pp.echo_data = "a"
	pp.ip_offset=0
	pp:build_icmp_echo_request()
	pp:build_icmp_header()
	pp:build_ip_packet()
	--根据目标到源的剩余ttl，初步估计源到目标的网络距离
	pp:ip_set_ttl(64)
	send_l3_sock:ip_send(pp.buf)
	print("first predict,send ping packet")
	stdnse.sleep(2) 	--test, 当并行量增大时，需要等待监听线程全部启动
	if icmp_echo_listener_signal['receive']==true then
		print(ip,"first predict ttl by ping success,receive reply!")
	else
		print(ip,"first predict ttl by ping fail,no receive reply!")
	end

	return mid_ttl
end

-- The Action Section --
--action = function(host, port)

action = function(host)
	print("\n\n**************************************************")
	local ifname = nmap.get_interface() or host.interface
	if ( not(ifname) ) then
		return fail("Failed to determine the network interface name")
	end
	local iface = nmap.get_interface_info(ifname)
	print("action:",host.ip)
	host_ip=host.ip
	--建立发送l3层报文的raw socket
	--用于发送设置了ttl的探测末跳报文
	local send_l3_sock = nmap.new_dnet()
	send_l3_sock:ip_open()

	local icmp_echo_listener_signal={}
	local icmp_echo_listener_condvar = nmap.condvar(icmp_echo_listener_signal)
	icmp_echo_listener_signal['status']=0
	icmp_echo_listener_signal['left_ttl']=0
	local icmp_echo_listener_handler=stdnse.new_thread(icmp_echo_listener,icmp_echo_listener_signal,host.ip,iface)

	stdnse.sleep(2)  --test,必须等待，否则线程未启动完成，可能已经发送了探测包
	local guest_ttl=guest_network_distance(iface,send_l3_sock,icmp_echo_listener_signal,host.ip)

	repeat
		if coroutine.status(icmp_echo_listener_handler)=="dead" then
			icmp_echo_listener_handler=nil
		else 
			--send again udp
			print("wait for icmp echo listener end...")
			icmp_echo_listener_signal['status']=1
			icmp_echo_listener_condvar("wait")
		end
	until icmp_echo_listener_handler==nil


	send_l3_sock:ip_close()

	print("**************************************************\n\n")
	return true
end





