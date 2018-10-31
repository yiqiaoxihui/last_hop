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
--用于接受icmp端口不可达包
--
-- @param icmp_pu_listener function name
-- @param send_l3_sock l3 layer raw socket
local function icmp_pu_listener(send_l3_sock,signal,ip)
	--print("\nbegin icmp port unreachable listener...")
	local icmp_pu_rec_socket=nmap.new_socket()
	local capture_rule="(icmp[0]=3) and (icmp[1]=3) and host "..ip
	icmp_pu_rec_socket:pcap_open("eno2",70,false,capture_rule)
	icmp_pu_rec_socket:set_timeout(25000)
	local condvar = nmap.condvar(signal)
	local icmp_pu_count=0
	local status,len,l2_icmp_pu_data,l3_icmp_pu_data,time
	--pcap_receive()方法似乎不会因收包后的解析产生的延迟而错过网络中到达的数据包
	--使用stdnse.sleep(10)故意延迟，仍然未遗漏数据包
	status,len,l2_icmp_pu_data,l3_icmp_pu_data,time=icmp_pu_rec_socket:pcap_receive()
	if status then
		icmp_pu_count=icmp_pu_count+1
		--print("\n\nreceive icmp port unreachable packet...")
		--stdnse.sleep(10)
		--print("parse for getting left ttl in packet...")
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
		raw_sender_packet_in_l3_icmp_pu_packet:ip_set_ttl(left_ttl)
		---print("packet.buf len:",#raw_sender_packet_in_l3_icmp_pu_packet.buf)
		send_l3_sock:ip_send(raw_sender_packet_in_l3_icmp_pu_packet.buf)
	else
		--print("no icmp port unreachable packet back!")
	---local p2=packet.Packet:build_ip_packet(p1.ip_src,p1.ip_dst,"123",0,0xbeef,0,left_ttl,"1")
	end
	--print("get icmp_pu_count:",icmp_pu_count)
	icmp_pu_rec_socket:close()
	condvar("signal")
end
--建立监听线程
--用于接受icmp echo 响应报文
local function icmp_echo_listener(signal,ip)
	--print("\nbegin icmp time to live exceeded packet listener...")
	local icmp_echo_rec_socket=nmap.new_socket()
	local capture_rule="(icmp[0]=0) and (icmp[1]=0) and host "..ip
	icmp_echo_rec_socket:pcap_open("eno2",128,false,capture_rule)
	icmp_echo_rec_socket:set_timeout(6000)
	local status,len,l2_icmp_e_r,l3_icmp_echo_reply,time
	local condvar=nmap.condvar(signal)
	local get_last_hop_count=0
	while signal['status']==0 do
		status,len,l2_icmp_e_r,l3_icmp_echo_reply,time=icmp_echo_rec_socket:pcap_receive()
		--signal['receive']=nil
		if status then
			signal['receive']=true
			--print("receive ping reply")
			local echo_reply_packet = packet.Packet:new(l3_icmp_echo_reply, #l3_icmp_echo_reply)
			signal['left_ttl']=echo_reply_packet.ip_ttl
		else
			signal['receive']=nil
			signal['left_ttl']=0
		end		
	end
	
	--print("get_last_hop_count:",get_last_hop_count)
	icmp_echo_rec_socket:close()
	condvar("signal")
end

--建立监听线程
--用于接受icmp生存时间过期报文
--从中提取末跳路由器信息
local function icmp_tole_listener(signal,ip)
	--print("\nbegin icmp time to live exceeded packet listener...")
	local icmp_tole_rec_socket=nmap.new_socket()
	local str_hex_ip=ipOps.todword(ip)
	--print("str hex ip:",str_hex_ip)
	local capture_rule="(icmp[0]=11) and (icmp[1]=0) and icmp[24:4]="..str_hex_ip
	icmp_tole_rec_socket:pcap_open("eno2",128,false,capture_rule)
	icmp_tole_rec_socket:set_timeout(5000)
	local status,len,l2_icmp_t_l,l3_icmp_tol,time
	local condvar=nmap.condvar(signal)
	--local get_last_hop_count=0
	while signal['status']==0 do
		status,len,l2_icmp_t_l,l3_icmp_tol,time=icmp_tole_rec_socket:pcap_receive()
		--signal['receive']=nil
		if status then
			if signal['guest']==1 then	--猜ttl
				--print("receive time limit")
				signal['receive']=true
			else
				--stdnse.sleep(5)
				--get_last_hop_count=get_last_hop_count+1
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
						print("#get last hop",ip,dst_ip,v)
					end
				end				
			end
		else
			print(ip,"no icmp ttl exceeded packet back!")
		end
	end
	
	--print(ip,"get_last_hop_count:")
	icmp_tole_rec_socket:close()
	condvar("signal")
end
local function fail(err) return ("\n  ERROR: %s"):format(err or "") end


local function send_to_last_hop(iface,send_l3_sock,dst_ip,ttl)
	local ip=packet.Packet:new()
	ip.ip_bin_dst=packet.iptobin(dst_ip)
	ip.ip_bin_src = packet.iptobin(iface.address)
	ip:build_icmp_echo_request()
	ip:build_icmp_header()
	ip:build_ip_packet()
	ip.echo_data = "a"
	ip.ip_offset=0
	ip:ip_set_ttl(ttl)
    -- local pktbin = bin.pack("H",
    --   "4500 0014 0000 4000 8000 0000 0000 0000 0000 0000" ..
    --   "0000 0000 0000 0000 0000 0000 6002 0c00 0000 0000 0204 05b4"
    -- )
    -- ip = packet.Packet:new(pktbin, pktbin:len())
    -- ip:tcp_parse(false)
    -- ip:ip_set_bin_src(iface.address)
    -- ip:ip_set_bin_dst(dst_ip)
    -- ip:tcp_set_sport(math.random(0x401, 0xffff))
    -- ip:tcp_set_dport(80)
    -- ip:tcp_set_seq(math.random(1, 0x7fffffff))
    -- ip:tcp_count_checksum()
    -- ip:ip_count_checksum()
    -- ip:ip_set_ttl(ttl)
    -- local pktbin = bin.pack("H",
    --   "4500 0014 0000 4000 8000 0000 0000 0000 0000 0000" ..
    --   "0000 0000 0800 0000"
    -- )

    -- ip = packet.Packet:new(pktbin, pktbin:len())

    -- ip:udp_parse(false)
    -- ip:ip_set_bin_src(iface.address)
    -- ip:ip_set_bin_dst(dst_ip)
    -- ip:set_u8(ip.ip_offset + 9, packet.IPPROTO_UDP)
    -- ip.ip_p = packet.IPPROTO_UDP
    -- ip:ip_set_len(pktbin:len())
    -- ip:udp_set_sport(math.random(0x401, 0xffff))
    -- ip:udp_set_dport(65534)
    -- ip:udp_set_length(ip.ip_len - ip.ip_hl * 4)
    -- ip:udp_count_checksum()
    -- ip:ip_set_ttl(ttl)
    -- ip:ip_count_checksum()
	send_l3_sock:ip_send(ip.buf)
end

local function get_distance_from_target_to_source(left_ttl)
	--print("left_ttl:",left_ttl)
	local ttl=0
	if left_ttl>64 then
		if left_ttl>128 then
			ttl=256-left_ttl
		else
			ttl=128-left_ttl
		end
	else
		ttl=64-left_ttl
	end
	return ttl
end

local function guest_network_distance_by_traceroute(end_ttl,error_ttl,iface,send_l3_sock,ip,icmp_echo_listener_signal,icmp_tole_listener_signal)
	local mid_ttl
	local times=0
	local result={}
	stdnse.sleep(3)
	for i=error_ttl+1, end_ttl do
		print("\n\nreset ttl",i)
		send_to_last_hop(iface,send_l3_sock,ip,i)
		stdnse.sleep(2)
		if icmp_echo_listener_signal['receive']==true then
			print("reply icmp echo")
			icmp_echo_listener_signal['receive']=nil
			result[i]="echo"
			mid_ttl=i
			break
		elseif icmp_tole_listener_signal['receive']==true then
			print("receive icmp time limit")
			result[i]="limit"
			icmp_tole_listener_signal['receive']=nil
		else
			result[i]="none"
		end
	end
	if result[mid_ttl]=="echo" and result[mid_ttl-1]=="limit" then
		--print("get ttl by traceroute",mid_ttl)
		return mid_ttl
	else
		--print("get ttl by traceroute fail",mid_ttl)
		return -1
	end

	-- body
end
--猜测到目标的网络距离
--
-- @param iface
-- @param send_l3_sock: l3 layer raw socket
-- @param icmp_echo_listener_signal:receive echo reply signal
-- @param icmp_tole_listener_signal:receive time limit signal
-- @param ip:target ip
function guest_network_distance(iface,send_l3_sock,icmp_echo_listener_signal,icmp_tole_listener_signal,ip)
	local pp=packet.Packet:new()
	local ttl_from_target_to_source
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
	stdnse.sleep(2)
	if icmp_echo_listener_signal['receive']==true then
		icmp_echo_listener_signal['receive']=nil		--error:forget reset to nil,cause error guess
		ttl_from_target_to_source=get_distance_from_target_to_source(icmp_echo_listener_signal['left_ttl'])
		--print("guest ttl",ttl_from_target_to_source)
		deviation_right=ttl_from_target_to_source-30+deviation_distance
		deviation_left=deviation_distance-ttl_from_target_to_source		--5-3
		if deviation_right<0 then
			deviation_right=0
		end
		if deviation_left<0 then
			deviation_left=0
		end
		min_ttl=ttl_from_target_to_source-deviation_right-deviation_distance+deviation_left
		max_ttl=ttl_from_target_to_source-deviation_right+deviation_distance+deviation_left

		if min_ttl<1 then
			min_ttl=1
		end
		if max_ttl>30 then
			max_ttl=30
		end
	else
		print("* ",ip," no receive first echo reply!")
	end
	print("max,min:",max_ttl,min_ttl,ttl_from_target_to_source)
	--print("ip offset：",pp.ip_offset)

	--23.197.209.17
	-- min_ttl=14
	-- max_ttl=24
	local left_ttl=min_ttl
	local right_ttl=max_ttl
	local deviation_fail=0
	local time_limit_ttl=-1
	local echo_reply_ttl=-1
	while true do
		mid_ttl=math.floor((left_ttl+right_ttl)/2)

		print("\n\nset ttl:",mid_ttl)
		pp:ip_set_ttl(mid_ttl)

		send_l3_sock:ip_send(pp.buf)
		stdnse.sleep(1)
		if icmp_echo_listener_signal['receive']==true then
			print("reply icmp echo")
			right_ttl=mid_ttl
			echo_reply_ttl=mid_ttl
			icmp_echo_listener_signal['receive']=nil
			if mid_ttl<=1 then
				break
			end
		elseif icmp_tole_listener_signal['receive']==true then
			print("receive icmp time limit")
			-- if mid_ttl>29 then
			-- 	mid_ttl=-1
			-- 	print("* ",ip," hop more than 30")
			-- 	break
			-- else
				left_ttl=mid_ttl+1
				time_limit_ttl=mid_ttl
				icmp_tole_listener_signal['receive']=nil
			-- end
		else
			print("send again")
			times=times+1
			--mid_ttl=mid_ttl+0.1		--ip:90.196.109.225, left_ttl=9,right_ttl=10, mid_ttl=9,no any reply
		end

		if right_ttl==min_ttl then				--all echo reply
			print(ip,"set min_ttl too big")
			left_ttl=min_ttl-deviation_distance
			if left_ttl<=0 then
				left_ttl=1
			end
			--mid_ttl=left_ttl  	--traceroute from mid_ttl to right_ttl
			min_ttl=left_ttl
			--deviation_fail=1
			--break
		elseif left_ttl==max_ttl then		--all time limit,left_ttl=max_ttl=mid_ttl+1
			print(ip,"set max_ttl too small")
			right_ttl=max_ttl+deviation_distance  --for traceroute from mid_ttl to right_ttl
			max_ttl=right_ttl
			--deviation_fail=1
			--break
		elseif time_limit_ttl+1==echo_reply_ttl then					--(mid_ttl==left_ttl)针对上次limit,而本次echo;
			mid_ttl=echo_reply_ttl 										-- or (right_ttl==left_ttl)针对本次limit后，left_ttl=mid_ttl+1=right_ttl
			print(ip,"guest ttl:",mid_ttl)
			break
		end
		if times>4 then
			break
		end
	end
	mid_ttl=math.floor(mid_ttl)
	if times>4 then
		mid_ttl=guest_network_distance_by_traceroute(right_ttl,mid_ttl,iface,send_l3_sock,ip,icmp_echo_listener_signal,icmp_tole_listener_signal)
		if mid_ttl>0 then
			print(mid_ttl,ip,"traceroute guess success!")
		else
			print(ip," traceroute guess fail!")
		end
	end

	icmp_echo_listener_signal['status']=1
	icmp_tole_listener_signal['guest']=0
	--print("guest end")
	return mid_ttl
	-- body
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

	--建立监听线程,用于接受icmp端口不可达包
	--
	-- @param icmp_pu_listener function name
	-- @param send_l3_sock l3 layer raw socket
	-- @param icmp_pu_listener_signal listener stop signal
	-- local icmp_pu_listener_signal={}
	-- local icmp_pu_listener_condvar = nmap.condvar(icmp_pu_listener_signal)
	-- icmp_pu_listener_signal['status']=0
	-- local icmp_pu_listener_handler=stdnse.new_thread(icmp_pu_listener,send_l3_sock,icmp_pu_listener_signal,host.ip)


	--建立监听线程，用于接收icmp生存时间过期报文
	--
	-- @param icmp_pu_listener function name
	-- @param icmp_tole_listener_signal listener stop signal and receive signal
	local icmp_tole_listener_signal={}
	local icmp_tole_listener_condvar = nmap.condvar(icmp_tole_listener_signal)
	icmp_tole_listener_signal['status']=0
	icmp_tole_listener_signal['guest']=1
	local icmp_tole_listener_handler=stdnse.new_thread(icmp_tole_listener,icmp_tole_listener_signal,host.ip)

	--建立监听线程，用于接收icmp echo respone报文
	--
	-- @param icmp_echo_listener function name
	-- @param icmp_echo_listener_signal listener stop signal and receive signal
	local icmp_echo_listener_signal={}
	local icmp_echo_listener_condvar = nmap.condvar(icmp_echo_listener_signal)
	icmp_echo_listener_signal['status']=0
	icmp_echo_listener_signal['left_ttl']=0
	local icmp_echo_listener_handler=stdnse.new_thread(icmp_echo_listener,icmp_echo_listener_signal,host.ip)

	stdnse.sleep(1)
	local guest_ttl=guest_network_distance(iface,send_l3_sock,icmp_echo_listener_signal,icmp_tole_listener_signal,host.ip)

	if guest_ttl>1 then
		print(host.ip,guest_ttl,"send packet to get last hop...")
		send_to_last_hop(iface,send_l3_sock,host.ip,guest_ttl-1)
		stdnse.sleep(1)
	elseif guest_ttl==1 then
		print(host.ip,"target in intranet ")
	else
		print(host.ip," guest ttl fail...")
		--return false
	end

	icmp_tole_listener_signal['status']=1
	--icmp_pu_listener_signal['status']=1

	repeat
		if coroutine.status(icmp_tole_listener_handler)=="dead" then
			icmp_tole_listener_handler=nil
		else
			print(host.ip,"wait icmp time to live exceeded listener end...")
			icmp_tole_listener_signal['status']=1
			icmp_tole_listener_condvar("wait")
			--print("wait icmp test...")
		end
	until icmp_tole_listener_handler==nil

	repeat
		if coroutine.status(icmp_echo_listener_handler)=="dead" then
			icmp_echo_listener_handler=nil
		else 
			--send again udp
			print("wait for icmp echo listener end...")
			icmp_echo_listener_condvar("wait")
		end
	until icmp_echo_listener_handler==nil
	-- repeat
	-- 	if coroutine.status(icmp_pu_listener_handler)=="dead" then
	-- 		icmp_pu_listener_handler=nil
	-- 	else 
	-- 		--send again udp
	-- 		print("wait for icmp port unreachable listener end...")
	-- 		icmp_pu_listener_condvar("wait")
	-- 	end
	-- until icmp_pu_listener_handler==nil



	send_l3_sock:ip_close()

	print("**************************************************\n\n")
	return true
end
