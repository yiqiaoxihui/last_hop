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


-- Version 0.01
-- Created 09/25/2018 - v0.01 - created by Liu Yang

author = "Liu Yang"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}
-- The Head Section --


--建立监听线程
--用于接受icmp echo 响应报文
local function icmp_echo_listener(signal,ip,iface,VERBOSE)
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
local function icmp_tole_listener(signal,ip,iface,VERBOSE)
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
						if VERBOSE >=1 then
							print("#get_last_hop",ip,dst_ip,v)
						end
					end
				end				
			end
		else
			if VERBOSE >=2 then
				print(ip,"no icmp ttl exceeded packet back!")
			end
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
	if left_ttl>26 then 		--统计发现初始ttl为64左右的，left_ttl一般大于26
		if left_ttl>64 then
			if left_ttl>128 then
				if left_ttl>200 then
					ttl=255-left_ttl
				else
					ttl=200-left_ttl
				end
			else
				ttl=128-left_ttl
			end
		else
			ttl=64-left_ttl
		end
	else
		ttl=31-left_ttl		--统计发现，31为初始ttl的多,realtest,python get_reply_ttl_lt_32.py realtest/3.live.one
	end
	return ttl+1
end
--猜测到目标的网络距离
--
-- @param iface
-- @param send_l3_sock: l3 layer raw socket
-- @param icmp_echo_listener_signal:receive echo reply signal
-- @param icmp_tole_listener_signal:receive time limit signal
-- @param ip:target ip
function last_hop_one_step_guest_network_distance(iface,send_l3_sock,icmp_echo_listener_signal,icmp_tole_listener_signal,ip,ctrl_info,VERBOSE)
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
	local send_number=0
	local left_ttl=-1
	set_ttl_to_ping(iface,send_l3_sock,ip,64)
	stdnse.sleep(2)
	if icmp_echo_listener_signal['receive']==true then
		icmp_echo_listener_signal['receive']=nil		--error:forget reset to nil,cause error guess
		left_ttl=icmp_echo_listener_signal['left_ttl']
		ttl_from_target_to_source=get_distance_from_target_to_source(icmp_echo_listener_signal['left_ttl'])
		if VERBOSE>=1 then
			print(ip,ttl_from_target_to_source,"first predict ttl by ping success,receive reply")
		end

		if ttl_from_target_to_source>32 then  	--avoid too big ttl
			set_ttl=15
		else
			set_ttl=ttl_from_target_to_source
		end
		send_number=send_number+1
		set_ttl_to_ping(iface,send_l3_sock,ip,set_ttl)
		stdnse.sleep(1) 	--test,网络延迟，必须等待2秒
		if icmp_echo_listener_signal['receive']==true then
			if VERBOSE >=2 then
				print(ip,ttl_from_target_to_source,"first predict ttl echo reply")
			end
			icmp_echo_listener_signal['receive']=nil
			echo_reply_ttl=set_ttl
			-- set_ttl=ttl_from_target_to_source
			while set_ttl>1 do
				set_ttl=set_ttl-1
				send_number=send_number+1
				set_ttl_to_ping(iface,send_l3_sock,ip,set_ttl)
				stdnse.sleep(1)
				if icmp_echo_listener_signal['receive']==true then
					icmp_echo_listener_signal['receive']=nil
					echo_reply_ttl=set_ttl
					if VERBOSE >=2 then
						print(ip,set_ttl,"one step receive icmp echo reply")
					end
				elseif icmp_tole_listener_signal['receive']==true then
					icmp_tole_listener_signal['receive']=nil
					if VERBOSE >=2 then
						print(ip,set_ttl,"one step receive icmp time limit,break")
					end
					time_limit_ttl=set_ttl
					break
				else
					--nothing todo
				end
				if set_ttl<=1 then
					if VERBOSE >=2 then
						print(ip,"one step move to zero")
					end
					break
				end
			end
		elseif icmp_tole_listener_signal['receive']==true then
			if VERBOSE >=2 then
				print(ip,ttl_from_target_to_source,"first predict ttl time limit")
			end
			icmp_tole_listener_signal['receive']=nil
			time_limit_ttl=set_ttl
			-- set_ttl=ttl_from_target_to_source
			while set_ttl<=32 do
				set_ttl=set_ttl+1
				send_number=send_number+1
				set_ttl_to_ping(iface,send_l3_sock,ip,set_ttl)
				stdnse.sleep(1)
				if icmp_echo_listener_signal['receive']==true then
					icmp_echo_listener_signal['receive']=nil
					echo_reply_ttl=set_ttl
					if VERBOSE >=2 then
						print(ip,set_ttl,"one step receive icmp echo reply,break")
					end
					break
				elseif icmp_tole_listener_signal['receive']==true then
					icmp_tole_listener_signal['receive']=nil
					time_limit_ttl=set_ttl
					if VERBOSE >=2 then
						print(ip,set_ttl,"one step receive icmp time limit")
					end
				else
					--nothing todo
				end
				if set_ttl>32 and set_ttl ~= time_limit_ttl then
					if VERBOSE >=2 then
						print(ip,set_ttl,time_limit_ttl,"one step move more than 32")
					end
					break
				end
			end
		else
			if VERBOSE >=1 then
				print(ip,"first send left ttl no reply")
			end
			-- set_ttl=ttl_from_target_to_source
			while set_ttl<=32 do
				set_ttl=set_ttl+1
				send_number=send_number+1
				set_ttl_to_ping(iface,send_l3_sock,ip,set_ttl)
				stdnse.sleep(1)
				if icmp_echo_listener_signal['receive']==true then
					icmp_echo_listener_signal['receive']=nil
					echo_reply_ttl=set_ttl
					if VERBOSE >=2 then
						print(ip,set_ttl,"one step receive icmp echo reply,break")
					end
					break
				elseif icmp_tole_listener_signal['receive']==true then
					icmp_tole_listener_signal['receive']=nil
					time_limit_ttl=set_ttl
					if VERBOSE >=2 then
						print(ip,set_ttl,"one step receive icmp time limit")
					end
				else
					--nothing todo
				end
				if set_ttl>32 and set_ttl ~= time_limit_ttl then
					if VERBOSE >=2 then
						print(ip,set_ttl,time_limit_ttl,"one step move more than 30")
					end
					break
				end
			end
			if time_limit_ttl==(echo_reply_ttl-1) then
				guess_ttl=echo_reply_ttl
				if VERBOSE >=1 then
					print(ip,guess_ttl,"get_by_no_reply,one step guess ttl success")
				end
			end
			--mid_ttl=mid_ttl+0.1		--ip:90.196.109.225, left_ttl=9,right_ttl=10, mid_ttl=9,no any reply
		end
	else
		if VERBOSE >=1 then
			print(ip,"first predict ttl by ping fail,no receive reply!")
		end
	end
	if time_limit_ttl==(echo_reply_ttl-1) then
		guess_ttl=echo_reply_ttl
	end

	icmp_echo_listener_signal['status']=1
	icmp_tole_listener_signal['guest']=0
	if guess_ttl>1 and ttl_from_target_to_source>0 then
		send_number=send_number+1	--first ping
		ctrl_info['one_step_send']=ctrl_info['one_step_send']+send_number
		ctrl_info['one_step_get']=ctrl_info['one_step_get']+1
		if VERBOSE >=0 then
			print(ip,guess_ttl,ttl_from_target_to_source,"difference:",guess_ttl-ttl_from_target_to_source,send_number,left_ttl)
		end
	end
	return guess_ttl
	-- body
end

-- The Action Section --
--action = function(host, port)

last_hop_one_step = function(dst_ip,iface,ctrl_info,send_l3_sock,VERBOSE)
	print("last_hop_one_step:",dst_ip)
	--建立发送l3层报文的raw socket
	--用于发送设置了ttl的探测末跳报文
	-- local send_l3_sock = nmap.new_dnet()
	-- send_l3_sock:ip_open()

	--建立监听线程，用于接收icmp生存时间过期报文
	--
	-- @param icmp_pu_listener function name
	-- @param icmp_tole_listener_signal listener stop signal and receive signal
	local icmp_tole_listener_signal={}
	local icmp_tole_listener_condvar = nmap.condvar(icmp_tole_listener_signal)
	icmp_tole_listener_signal['status']=0
	icmp_tole_listener_signal['guest']=1
	icmp_tole_listener_signal['last_hop']=0		--是否收到最后一跳
	local icmp_tole_listener_handler=stdnse.new_thread(icmp_tole_listener,icmp_tole_listener_signal,dst_ip,iface,VERBOSE)

	--建立监听线程，用于接收icmp echo respone报文
	--
	-- @param icmp_echo_listener function name
	-- @param icmp_echo_listener_signal listener stop signal and receive signal
	local icmp_echo_listener_signal={}
	local icmp_echo_listener_condvar = nmap.condvar(icmp_echo_listener_signal)
	icmp_echo_listener_signal['status']=0
	icmp_echo_listener_signal['left_ttl']=0
	local icmp_echo_listener_handler=stdnse.new_thread(icmp_echo_listener,icmp_echo_listener_signal,dst_ip,iface,VERBOSE)

	stdnse.sleep(1)
	local guest_ttl=last_hop_one_step_guest_network_distance(iface,send_l3_sock,icmp_echo_listener_signal,icmp_tole_listener_signal,dst_ip,ctrl_info,VERBOSE)
	if guest_ttl>1 then
		-- set_ttl_to_ping(iface,send_l3_sock,dst_ip,guest_ttl-1)
		-- stdnse.sleep(1)
	else
		if VERBOSE >=1 then
			print(dst_ip,"guest_ttl_fail")
		end
		--return false
	end
	icmp_tole_listener_signal['status']=1

	repeat
		if coroutine.status(icmp_tole_listener_handler)=="dead" then
			icmp_tole_listener_handler=nil
		else
			if VERBOSE >=1 then
				print("last_hop_one_step",dst_ip,"wait icmp time to live exceeded listener end...")
			end
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
			if VERBOSE >=1 then
				print("last_hop_one_step",dst_ip,"wait for icmp echo listener end...")
			end
			icmp_echo_listener_signal['status']=1
			icmp_echo_listener_condvar("wait")
		end
	until icmp_echo_listener_handler==nil

	-- send_l3_sock:ip_close()
	return true
end