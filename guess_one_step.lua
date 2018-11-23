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
	--print("\nbegin icmp time to live exceeded packet listener...")
	local icmp_echo_rec_socket=nmap.new_socket()
	local capture_rule="(icmp[0]=0) and (icmp[1]=0) and host "..ip
	icmp_echo_rec_socket:pcap_open(iface.device,128,false,capture_rule)
	icmp_echo_rec_socket:set_timeout(5000)
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
	--local get_last_hop_count=0
	while signal['status']==0 do
		status,len,l2_icmp_t_l,l3_icmp_tol,time=icmp_tole_rec_socket:pcap_receive()
		--signal['receive']=nil
		if status then
			if signal['guest']==1 then	--猜ttl
				--print("receive time limit")
				signal['receive']=true
			else
				signal['last_hop']=1
				local last_hop_packet = packet.Packet:new(l3_icmp_tol, #l3_icmp_tol)
				local raw_sender_data_in_l3_icmp_tol_packet=l3_icmp_tol:sub(last_hop_packet.icmp_payload_offset+1)
				local raw_sender_packet_in_l3_icmp_tol_packet=packet.Packet:new(raw_sender_data_in_l3_icmp_tol_packet,#raw_sender_data_in_l3_icmp_tol_packet)
				local dst_ip=raw_sender_packet_in_l3_icmp_tol_packet.ip_dst
				
				for k,v in pairs(last_hop_packet) do
					if k=="ip_ttl" then
						--print(k,v)
					end
					if k=="ip_src" then
						print("#get_last_hop",ip,dst_ip,v)
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
	local times=0
	local time_limit_ttl=-1
	local echo_reply_ttl=-1
	stdnse.sleep(2)
	for i=error_ttl+1, end_ttl do
		print("\n\nreset ttl",i)
		set_ttl_to_ping(iface,send_l3_sock,ip,i)
		stdnse.sleep(1) 	--test,必须等待1-2秒
		if icmp_echo_listener_signal['receive']==true then
			print(ip,i,"traceroute reply icmp echo")
			icmp_echo_listener_signal['receive']=nil
			echo_reply_ttl=i
			break
		elseif icmp_tole_listener_signal['receive']==true then
			print(ip,i,"traceroute receive icmp time limit")
			time_limit_ttl=i
			icmp_tole_listener_signal['receive']=nil
		else
		end
	end
	if time_limit_ttl+1==echo_reply_ttl then
		--print("get ttl by traceroute success",mid_ttl)
		return echo_reply_ttl
	else
		--print("get ttl by traceroute fail",mid_ttl)
		return -1
	end

	-- body
end
function division_guess_ttl(iface,send_l3_sock,ip,icmp_echo_listener_signal,icmp_tole_listener_signal,left_ttl,right_ttl)
	local mid_ttl
	local times=0
	local min_ttl=left_ttl
	local max_ttl=right_ttl
	local time_limit_ttl=-1
	local echo_reply_ttl=-1
	local deviation_distance=5
	while true do
		mid_ttl=math.floor((left_ttl+right_ttl)/2)
		set_ttl_to_ping(iface,send_l3_sock,ip,mid_ttl)
		print("\n\nset ttl:",mid_ttl)
		stdnse.sleep(1) 	--test,网络延迟，必须等待2秒
		if icmp_echo_listener_signal['receive']==true then
			print(ip,mid_ttl,"reply icmp echo")
			right_ttl=mid_ttl
			echo_reply_ttl=mid_ttl
			icmp_echo_listener_signal['receive']=nil
			if mid_ttl<=1 then
				break
			end
		elseif icmp_tole_listener_signal['receive']==true then
			print(ip,mid_ttl,"receive icmp time limit")
			if mid_ttl>35 then 			--认为没有大于35跳的路由
				mid_ttl=-1
				print(ip," hop more than 35")
				break
			else
				left_ttl=mid_ttl+1
				time_limit_ttl=mid_ttl
				icmp_tole_listener_signal['receive']=nil
			end
		else
			print(ip,mid_ttl,"send again")
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
		if times>1 then
			break
		end
	end
	mid_ttl=math.floor(mid_ttl)
	if times>1 then
		if mid_ttl+1==echo_reply_ttl then
			print(ip,"last hop no reply,no need to traceroute")
			return -1
		end
		local old_mid_ttl=mid_ttl
		print(ip,time_limit_ttl,echo_reply_ttl,mid_ttl,old_mid_ttl,"begin traceroute to guess")
		mid_ttl=guest_network_distance_by_traceroute(34,mid_ttl,iface,send_l3_sock,ip,icmp_echo_listener_signal,icmp_tole_listener_signal)
		if mid_ttl>0 then
			print(ip,mid_ttl,"traceroute guess success!")
		else
			print(ip,"traceroute guess fail!")
		end
	end
	return mid_ttl
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
	local ttl_from_target_to_source=0
	local max_ttl = 30
	local min_ttl=1
	local mid_ttl=0
	local set_ttl=0
	local guess_ttl=0
	local status=true
	local times=0
	local time_limit_ttl=-1		--max time limit ttl
	local echo_reply_ttl=-1		--min echo reply ttl
	set_ttl_to_ping(iface,send_l3_sock,ip,64)
	stdnse.sleep(2)
	if icmp_echo_listener_signal['receive']==true then
		icmp_echo_listener_signal['receive']=nil		--error:forget reset to nil,cause error guess
		ttl_from_target_to_source=get_distance_from_target_to_source(icmp_echo_listener_signal['left_ttl'])
		print(ip,ttl_from_target_to_source,"first predict success,set ttl and send")
		set_ttl_to_ping(iface,send_l3_sock,ip,ttl_from_target_to_source)
		stdnse.sleep(2) 	--test,网络延迟，必须等待2秒
		if icmp_echo_listener_signal['receive']==true then
			print(ip,ttl_from_target_to_source,"first predict ttl echo reply")
			icmp_echo_listener_signal['receive']=nil
			echo_reply_ttl=ttl_from_target_to_source
			set_ttl=ttl_from_target_to_source
			while true do
				set_ttl=set_ttl-1
				print(ip,set_ttl,"set ttl and send")
				set_ttl_to_ping(iface,send_l3_sock,ip,set_ttl)
				stdnse.sleep(1)
				if icmp_echo_listener_signal['receive']==true then
					icmp_echo_listener_signal['receive']=nil
					echo_reply_ttl=set_ttl
					print(ip,set_ttl,"one step receive icmp echo reply")
				elseif icmp_tole_listener_signal['receive']==true then
					icmp_tole_listener_signal['receive']=nil
					print(ip,set_ttl,"one step receive icmp time limit,break")
					time_limit_ttl=set_ttl
					break
				else
					--nothing todo
				end
				if set_ttl<=1 then
					print(ip,"one step move to zero")
					break
				end
			end
		elseif icmp_tole_listener_signal['receive']==true then
			print(ip,ttl_from_target_to_source,"first predict ttl time limit")
			icmp_tole_listener_signal['receive']=nil
			time_limit_ttl=ttl_from_target_to_source
			set_ttl=ttl_from_target_to_source
			while true do
				set_ttl=set_ttl+1
				print(ip,set_ttl,"set ttl and send")
				set_ttl_to_ping(iface,send_l3_sock,ip,set_ttl)
				stdnse.sleep(1)
				if icmp_echo_listener_signal['receive']==true then
					icmp_echo_listener_signal['receive']=nil
					echo_reply_ttl=set_ttl
					print(ip,set_ttl,"one step receive icmp echo reply,break")
					break
				elseif icmp_tole_listener_signal['receive']==true then
					icmp_tole_listener_signal['receive']=nil
					time_limit_ttl=set_ttl
					print(ip,set_ttl,"one step receive icmp time limit")
				else
					--nothing todo
				end
				if set_ttl>30 and set_ttl ~= time_limit_ttl then
					print(ip,set_ttl,time_limit_ttl,"one step move more than 30")
					break
				end
			end
		else
			print(ip,"first send left ttl no reply")
			set_ttl=ttl_from_target_to_source
			while true do
				set_ttl=set_ttl+1
				print(ip,set_ttl,"set ttl and send")
				set_ttl_to_ping(iface,send_l3_sock,ip,set_ttl)
				stdnse.sleep(1)
				if icmp_echo_listener_signal['receive']==true then
					icmp_echo_listener_signal['receive']=nil
					echo_reply_ttl=set_ttl
					print(ip,set_ttl,"one step receive icmp echo reply,break")
					break
				elseif icmp_tole_listener_signal['receive']==true then
					icmp_tole_listener_signal['receive']=nil
					time_limit_ttl=set_ttl
					print(ip,set_ttl,"one step receive icmp time limit")
				else
					--nothing todo
				end
				if set_ttl>30 and set_ttl ~= time_limit_ttl then
					print(ip,set_ttl,time_limit_ttl,"one step move more than 30")
					break
				end
			end
			if time_limit_ttl==echo_reply_ttl-1 then
				guess_ttl=echo_reply_ttl
				print(ip,guess_ttl,"get_by_no_reply,one step guess ttl success")
			end
			--mid_ttl=mid_ttl+0.1		--ip:90.196.109.225, left_ttl=9,right_ttl=10, mid_ttl=9,no any reply
		end
	else
		local left_ttl=min_ttl
		local right_ttl=max_ttl
		print(ip,"first predict ttl by ping fail,no receive reply!")
	end
	if time_limit_ttl==echo_reply_ttl-1 then
		guess_ttl=echo_reply_ttl
		print(ip,guess_ttl,"one step guess ttl success")
	elseif echo_reply_ttl > -1 then
		print(ip,echo_reply_ttl,time_limit_ttl,"try last time")
		set_ttl_to_ping(iface,send_l3_sock,ip,echo_reply_ttl-1)
		stdnse.sleep(1)
		if icmp_tole_listener_signal['receive']==true then
			icmp_tole_listener_signal['receive']=nil
			guess_ttl=echo_reply_ttl
			print(ip,echo_reply_ttl,time_limit_ttl,"last try success")
		end
	else
		print(ip,time_limit_ttl,echo_reply_ttl,"one step guess ttl fail")
	end

	icmp_echo_listener_signal['status']=1
	icmp_tole_listener_signal['guest']=0
	if guess_ttl>1 and ttl_from_target_to_source>0 then
		print(ip,guess_ttl,ttl_from_target_to_source,"difference:",guess_ttl-ttl_from_target_to_source)
	end
	return guess_ttl
	-- body
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
	host_ip=host.ip
	--建立发送l3层报文的raw socket
	--用于发送设置了ttl的探测末跳报文
	local send_l3_sock = nmap.new_dnet()
	send_l3_sock:ip_open()

	--建立监听线程，用于接收icmp生存时间过期报文
	--
	-- @param icmp_pu_listener function name
	-- @param icmp_tole_listener_signal listener stop signal and receive signal
	local icmp_tole_listener_signal={}
	local icmp_tole_listener_condvar = nmap.condvar(icmp_tole_listener_signal)
	icmp_tole_listener_signal['status']=0
	icmp_tole_listener_signal['guest']=1
	icmp_tole_listener_signal['last_hop']=0		--是否收到最后一跳
	local icmp_tole_listener_handler=stdnse.new_thread(icmp_tole_listener,icmp_tole_listener_signal,host.ip,iface)

	--建立监听线程，用于接收icmp echo respone报文
	--
	-- @param icmp_echo_listener function name
	-- @param icmp_echo_listener_signal listener stop signal and receive signal
	local icmp_echo_listener_signal={}
	local icmp_echo_listener_condvar = nmap.condvar(icmp_echo_listener_signal)
	icmp_echo_listener_signal['status']=0
	icmp_echo_listener_signal['left_ttl']=0
	local icmp_echo_listener_handler=stdnse.new_thread(icmp_echo_listener,icmp_echo_listener_signal,host.ip,iface)

	stdnse.sleep(1)
	local guest_ttl=guest_network_distance(iface,send_l3_sock,icmp_echo_listener_signal,icmp_tole_listener_signal,host.ip)

	if guest_ttl>1 then
		print(host.ip,guest_ttl,"send packet to get last hop...")
		set_ttl_to_ping(iface,send_l3_sock,host.ip,guest_ttl-1)
		stdnse.sleep(2)
	else
		print(host.ip," guest ttl fail...")
		--return false
	end
	icmp_tole_listener_signal['status']=1

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
			icmp_echo_listener_signal['status']=1
			icmp_echo_listener_condvar("wait")
		end
	until icmp_echo_listener_handler==nil

	send_l3_sock:ip_close()
	return true
end
