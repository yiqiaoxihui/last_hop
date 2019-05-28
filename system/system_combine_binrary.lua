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
			signal['icmp_pu']=1
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
					left_ttl=255-raw_sender_packet_in_l3_icmp_pu_packet.ip_ttl
				else
					left_ttl=128-raw_sender_packet_in_l3_icmp_pu_packet.ip_ttl
				end
			else
				left_ttl=64-raw_sender_packet_in_l3_icmp_pu_packet.ip_ttl
			end
			--print("icmp port unreachable to get left_ttl value:",raw_sender_packet_in_l3_icmp_pu_packet.ip_ttl)
			print(left_ttl+1,"set new ttl by icmp port unreachable")
			--print("send new packet to get last hop...")
			raw_sender_packet_in_l3_icmp_pu_packet:ip_set_ttl(left_ttl)
			---print("packet.buf len:",#raw_sender_packet_in_l3_icmp_pu_packet.buf)
			-- set_ttl_to_ping(iface,send_l3_sock,ip,left_ttl)
			--由于对udp包和icmp包处理方式有差别，因此，仍然发送udp包，可能所走路径不一样了
			send_l3_sock:ip_send(raw_sender_packet_in_l3_icmp_pu_packet.buf)
		else
			print("no icmp port unreachable packet back!")
		---local p2=packet.Packet:build_ip_packet(p1.ip_src,p1.ip_dst,"123",0,0xbeef,0,left_ttl,"1")
		end
	end
	icmp_pu_rec_socket:close()
	condvar("signal")
end
--建立监听线程
--用于接受icmp echo 响应报文
local function icmp_echo_listener(signal,ip,iface)
	--print("\nbegin icmp ping packet listener...")
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
				signal['status']=1
				signal['last_hop']=1  --已收到最后一跳,设置信号
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
			--print(ip,"no icmp ttl exceeded packet back!")
		end
	end
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
	if left_ttl>20 then
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
		ttl=30-left_ttl
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
function combine_binrary_guest_network_distance(iface,send_l3_sock,icmp_echo_listener_signal,icmp_tole_listener_signal,ip,ctrl_info)
	local ttl_from_target_to_source=0
	local max_ttl = 30
	local min_ttl=1
	local mid_ttl
	local times=0
	local send_number=0
	local guess_ttl=0
	local left_ttl=3
	local right_ttl=32
	local deviation_fail=0
	local time_limit_ttl=-1		--max time limit ttl
	local echo_reply_ttl=-1		--min echo reply ttl
	while left_ttl<=right_ttl do
		mid_ttl=math.floor((left_ttl+right_ttl)/2)
		print(ip,"set ttl and send:",mid_ttl)
		send_number=send_number+1
		set_ttl_to_ping(iface,send_l3_sock,ip,mid_ttl)
		stdnse.sleep(1) 	--test,网络延迟，必须等待2秒
		if icmp_echo_listener_signal['receive']==true then
			print(ip,mid_ttl,"reply icmp echo")
			right_ttl=mid_ttl-1
			echo_reply_ttl=mid_ttl
			icmp_echo_listener_signal['receive']=nil
			if mid_ttl<=3 then
				break
			end
		elseif icmp_tole_listener_signal['receive']==true then
			print(ip,mid_ttl,"receive icmp time limit")
			if mid_ttl>=32 then 			--认为没有大于35跳的路由
				mid_ttl=-1
				print(ip," hop more than 32")
				break
			else
				left_ttl=mid_ttl+1
				time_limit_ttl=mid_ttl
				icmp_tole_listener_signal['receive']=nil
			end
		else
			print(ip,mid_ttl,"send again")
			left_ttl=left_ttl+1  --默认未到达目标，中间路由器未回应，进一步扩大ttl
			times=times+1
			if times>2 then
				break
			end
			--mid_ttl=mid_ttl+0.1		--ip:90.196.109.225, left_ttl=9,right_ttl=10, mid_ttl=9,no any reply
		end
		if echo_reply_ttl == (time_limit_ttl+1) then
			guess_ttl=echo_reply_ttl
			break
		end
	end
	mid_ttl=math.floor(mid_ttl)
	if times>2 then
		if mid_ttl+1==echo_reply_ttl then
			print(ip,"last hop no reply,no need to traceroute")
		else
			print(ip,"middle router no reply,binrary can not deal")
		end
	end

	icmp_echo_listener_signal['status']=1		--猜ttl结束，停止监听
	icmp_tole_listener_signal['guest']=0		--猜ttl结束，获取末跳
	--print("guest end")
	if echo_reply_ttl==(time_limit_ttl+1) then
		guess_ttl=echo_reply_ttl
		ctrl_info['binrary_send']=ctrl_info['binrary_send']+send_number
		ctrl_info['binrary_get']=ctrl_info['binrary_get']+1
		print(ip,guess_ttl,ttl_from_target_to_source,"difference:",guess_ttl-ttl_from_target_to_source,send_number,left_ttl)
	else
		if echo_reply_ttl ~=-1 then
			print("guest_network_distance ONLY_ECHO_REPLY",echo_reply_ttl,time_limit_ttl)
		else
			print("guest_network_distance NO_ECHO_REPLY",echo_reply_ttl,time_limit_ttl)
		end
	end
	return guess_ttl
	-- body
end
-- The Action Section --
--action = function(host, port)

function last_hop_combine_binrary(dst_ip,iface,ctrl_info,send_l3_sock)
	print("action:",dst_ip)
	--建立发送l3层报文的raw socket
	--用于发送设置了ttl的探测末跳报文
	-- local send_l3_sock = nmap.new_dnet()
	-- send_l3_sock:ip_open()

	--建立监听线程,用于接受icmp端口不可达包
	--
	-- @param icmp_pu_listener function name
	-- @param send_l3_sock l3 layer raw socket
	-- @param icmp_pu_listener_signal listener stop signal
	local icmp_pu_listener_signal={}
	local icmp_pu_listener_condvar = nmap.condvar(icmp_pu_listener_signal)
	icmp_pu_listener_signal['status']=0 	--监听结束信号
	icmp_pu_listener_signal['icmp_pu']=0 	--是否收到icmp端口不可达信号
	local icmp_pu_listener_handler=stdnse.new_thread(icmp_pu_listener,send_l3_sock,icmp_pu_listener_signal,dst_ip,iface)

	stdnse.sleep(1)
	--建立监听线程，用于接收icmp生存时间过期报文
	--
	-- @param icmp_pu_listener function name
	-- @param icmp_tole_listener_signal listener stop signal and receive signal
	local icmp_tole_listener_signal={}
	local icmp_tole_listener_condvar = nmap.condvar(icmp_tole_listener_signal)
	icmp_tole_listener_signal['status']=0
	icmp_tole_listener_signal['guest']=0   		--初始不启用网络距离猜测
	icmp_tole_listener_signal['last_hop']=0		--是否收到最后一跳
	local icmp_tole_listener_handler=stdnse.new_thread(icmp_tole_listener,icmp_tole_listener_signal,dst_ip,iface)

	stdnse.sleep(1) 	--test,需要缓冲时间，保证线程全部启动
	--方法1.发送udp大端口报文，从icmp端口不可达报文中提取网络距离
	local send_udp_socket=nmap.new_socket("udp")
	send_udp_socket:sendto(dst_ip,65534,"")
	ctrl_info['udp_send']=ctrl_info['udp_send']+1
	stdnse.sleep(2)		--test,1s too short to get last_hop message
	--成功收到最后一跳
	--error:必须两者同时成立，可能出现并没有收到端口不可达，但是却收到time limit
	if (icmp_tole_listener_signal['last_hop']==1) and (icmp_pu_listener_signal['icmp_pu']==1) then
		print(dst_ip,"method1:udp_to_get_last_hop")
		icmp_tole_listener_signal['status']=1
		ctrl_info['udp_get']=ctrl_info['udp_get']+1
	--未收到time limit,但是收到端口不可达包，说明最后一跳不予响应
	elseif icmp_pu_listener_signal['icmp_pu']==1 then
		print(dst_ip,"receive icmp port unreachable packet,but last hop no reply!")
		icmp_tole_listener_signal['status']=1	--停止监听time to limit
	else
		print(dst_ip,"method2:begin to guest ttl")
		--未收到端口不可达包，只能二分法猜测
		icmp_tole_listener_signal['guest']=1 	--开始猜测
		icmp_pu_listener_signal['status']=1		--退出端口不可达监听
		--方法2. 二分法猜测网络距离

		--建立监听线程，用于接收icmp echo respone报文
		--
		-- @param icmp_echo_listener function name
		-- @param icmp_echo_listener_signal listener stop signal and receive signal
		local icmp_echo_listener_signal={}
		local icmp_echo_listener_condvar = nmap.condvar(icmp_echo_listener_signal)
		icmp_echo_listener_signal['status']=0
		icmp_echo_listener_signal['left_ttl']=0
		local icmp_echo_listener_handler=stdnse.new_thread(icmp_echo_listener,icmp_echo_listener_signal,dst_ip,iface)

		stdnse.sleep(2)  --test,必须等待，否则线程未启动完成，可能已经发送了探测包
		local guest_ttl=combine_binrary_guest_network_distance(iface,send_l3_sock,icmp_echo_listener_signal,icmp_tole_listener_signal,dst_ip,ctrl_info)
		icmp_echo_listener_signal['status']=1 	--退出echo reply监听
		icmp_tole_listener_signal['guest']=0	--猜测ttl结束
		if guest_ttl>1 then
			print(dst_ip,guest_ttl,"guess_lasthop_success,send packet to get last hop...")
			-- set_ttl_to_ping(iface,send_l3_sock,dst_ip,guest_ttl-1)
			-- stdnse.sleep(1)			--needtotest
			-- if icmp_tole_listener_signal['last_hop']==0 then
			-- 	print(dst_ip,"have guessed ttl,but no get last_hop")
			-- 	set_ttl_to_ping(iface,send_l3_sock,dst_ip,guest_ttl-1)
			-- 	--stdnse.sleep(1)
			-- else
			-- 	print("get last hop by guess success")
			-- end
		elseif guest_ttl==1 then
			print(dst_ip,"target in intranet")
		else
			print(dst_ip,"guest_ttl_fail")
			--return false
		end

		icmp_tole_listener_signal['status']=1
		repeat
			if coroutine.status(icmp_echo_listener_handler)=="dead" then
				icmp_echo_listener_handler=nil
			else 
				--send again udp
				print("wait icmp echo listener end...")
				icmp_echo_listener_signal['status']=1
				icmp_echo_listener_condvar("wait")
			end
		until icmp_echo_listener_handler==nil
	end

	repeat
		if coroutine.status(icmp_tole_listener_handler)=="dead" then
			icmp_tole_listener_handler=nil
		else
			print(dst_ip,"wait icmp time to live exceeded listener end...")
			icmp_tole_listener_signal['status']=1
			icmp_tole_listener_condvar("wait")
			--print("wait icmp test...")
		end
	until icmp_tole_listener_handler==nil

	repeat
		if coroutine.status(icmp_pu_listener_handler)=="dead" then
			icmp_pu_listener_handler=nil
		else
			print("wait icmp port unreachable listener end...")
			icmp_pu_listener_signal['status']=1 --先后顺序搞反，浪费大量时间
			icmp_pu_listener_condvar("wait")
		end
	until icmp_pu_listener_handler==nil
	-- send_l3_sock:ip_close()

	return true
end
