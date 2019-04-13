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
local mutex = nmap.mutex("test_mutex")
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
local function icmp_tole_listener(iface,signal,ip)
	--print("\nbegin icmp time to live exceeded packet listener...")
	local icmp_tole_rec_socket=nmap.new_socket()
	local str_hex_ip=ipOps.todword(ip)
	--print("str hex ip:",str_hex_ip)
	local capture_rule="icmp[24:4]="..str_hex_ip --(icmp[0]=11) and (icmp[1]=0) and 
	icmp_tole_rec_socket:pcap_open(iface.device,128,false,capture_rule)
	icmp_tole_rec_socket:set_timeout(5000)
	local status,len,l2_icmp_t_l,l3_icmp_tol,time
	local condvar=nmap.condvar(signal)
	--local get_last_hop_count=0
	while signal['status']==0 do
		status,len,l2_icmp_t_l,l3_icmp_tol,time=icmp_tole_rec_socket:pcap_receive()
		--signal['receive']=nil
		if status then
			print("receive !!!!!!!!!")
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
		else
			print(ip,"no icmp ttl exceeded packet back!")
		end
	end
	
	--print(ip,"get_last_hop_count:")
	icmp_tole_rec_socket:close()
	condvar("signal")
end
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
local function send_packet(iface,send_l3_sock,dst_ip,ttl,type)
	local ip
	print(type,packet.IPPROTO_UDP,packet.IPPROTO_TCP)
	if type=="6" then
	    local pktbin = bin.pack("H",
	      "4500 0014 0000 4000 8000 0000 0000 0000 0000 0000" ..
	      "0000 0000 0800 0000"
	    )
	    ip = packet.Packet:new(pktbin, pktbin:len())
	    ip:udp_parse(false)

	    ip:ip_set_bin_src(ipOps.ip_to_str(pi['src']))
	    ip:ip_set_bin_dst(ipOps.ip_to_str(pi['dst']))
	    ip:set_u8(ip.ip_offset + 9, packet.IPPROTO_UDP)
	    ip.ip_p = packet.IPPROTO_UDP
	    ip:ip_set_len(pktbin:len())
	    ip:udp_set_sport(pi['sport'])	--math
	    ip:udp_set_dport(pi['dport'])	--by send packet type array
	    ip:udp_set_length(ip.ip_len - ip.ip_hl * 4)
	    ip:udp_count_checksum()
	    ip:ip_set_ttl(pi['ttl'])
	    ip:ip_count_checksum()
	send_l3_sock:ip_send(ip.buf)
	elseif type==17 then
	    print("send tcp")
	    local pktbin = bin.pack("H",
	      "4500 0014 0000 4000 8000 0000 0000 0000 0000 0000" ..
	      "0000 0000 0000 0000 0000 0000 5002 0c00 0000 0000"
	    )--sportdport   seq     ack_seq  header_len:6,
									 --00000010:SYN
									 --00010000:ACK
									 --00000001:FIN
	    ip = packet.Packet:new(pktbin, pktbin:len())
	    ip:tcp_parse(false)
	    ip:ip_set_bin_src(ipOps.ip_to_str(pi['src']))
	    ip:ip_set_bin_dst(ipOps.ip_to_str(pi['dst']))
	    -- ip:tcp_set_flags(2)	0000 0000,00 URG ACK PSH RST SYN FIN 
	    ip:set_u8(ip.ip_offset + 9, packet.IPPROTO_TCP)
	    ip.ip_p = packet.IPPROTO_TCP
	    ip:ip_set_len(pktbin:len())
	    ip:tcp_set_sport(pi['sport'])
	    ip:tcp_set_dport(pi['dport'])
	    ip:tcp_set_seq(tcp_seq)

	    ip:tcp_count_checksum()
	    ip:ip_set_ttl(pi['ttl'])
	    ip:ip_count_checksum()

	send_l3_sock:ip_send(ip.buf)
	elseif type==1 then
		ip=packet.Packet:new()
		ip.ip_bin_dst=ipOps.ip_to_str(pi['dst'])
		ip.ip_bin_src = ipOps.ip_to_str(pi['src'])
		ip.echo_data = "abc"
		ip.echo_seq = echo_seq
		ip.echo_id=echo_id
		ip.ip_offset=0
		ip:build_icmp_echo_request()
		ip:build_icmp_header()
		ip:build_ip_packet()
		ip:ip_set_ttl(pi['ttl'])
		send_l3_sock:ip_send(ip.buf)
	else
		local ip_bin_dst=ipOps.ip_to_str(dst_ip)
		local ip_bin_src = ipOps.ip_to_str(iface.address)
		ip=packet.Packet:new()
		--ip:build_icmp_echo_request()
		ip:build_icmp_header(8,1)
		ip:build_ip_packet(ip_bin_src, ip_bin_dst, "", 0, 48879, 0, 0, ttl, 1)
		-- ip:build_icmp_header(1, 1, "icmp_payload", ip_bin_src, ip_bin_dst)
		-- ip:build_ip_packet()
		-- ip.ip_offset=0
		-- ip:ip_set_ttl(ttl)
	end
	send_l3_sock:ip_send(ip.buf)
	for k,v in pairs(ip) do
		print(k,v)
	end
end
function test_mutex(ip)
	stdnse.sleep(3)
	print(ip)
end
function iptobin1(str)
      local ret = ""
      for c in string.gmatch(str, "[0-9]+") do
              ret = ret .. string.char(c+0) -- automatic conversion to int
      end
      return ret
end

action = function(host)
	-- mutex "lock"
	-- local temp=ipOps.ip_to_str(host.ip)
	-- local temp1=ipOps.ip_to_str(host.ip)
	-- print(temp,temp1)

	-- test_mutex(host.ip)
	-- mutex "done"

	local ifname = nmap.get_interface() or host.interface
	if ( not(ifname) ) then
		return fail("Failed to determine the network interface name")
	end
	local iface = nmap.get_interface_info(ifname)
	local icmp_tole_listener_signal={}
	local icmp_tole_listener_condvar = nmap.condvar(icmp_tole_listener_signal)
	icmp_tole_listener_signal['status']=0
	local icmp_tole_listener_handler=stdnse.new_thread(icmp_tole_listener,iface,icmp_tole_listener_signal,host.ip)
	stdnse.sleep(1)

	local send_l3_sock = nmap.new_dnet()
	local ttl=stdnse.get_script_args("send.ttl")
	-- local type=stdnse.get_script_args("send.type")
	--print("ttl:",ttl)
	send_l3_sock:ip_open()
	send_packet(iface,send_l3_sock,host.ip,ttl,2)

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
	send_l3_sock:ip_close()
	return true
end
