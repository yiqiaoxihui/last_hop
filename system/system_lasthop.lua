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
local bit = require "bit"
-- local datetime = require "datetime"
-- local io = require "io"
require('system_combine_binrary')
require('system_combine_one_step')
require('system_one_step')
require('system_binrary')

-- require('parsepack') in prober

description = [[
	a traceroute tool,design some new way to improve traceroute
]]

---
-- @usage
-- sudo nmap --script fastrace --script-args='ip=52.78.22.146'
-- 
-- @output
-- 
--

-- Version 0.01
-- Created 04/11/2019 - v0.01 - created by Liu Yang

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
local function fail(err) return ("\n  ERROR: %s"):format(err or "") end

local function udp_and_one_step_is_not_better(ctrl_info)
	if (ctrl_info['udp_send']+ctrl_info['udp_get']+ctrl_info['one_step_send'])/(ctrl_info['udp_get']+ctrl_info['one_step_get'])  > (ctrl_info['one_step_send']/ctrl_info['one_step_get']) then
		return 1
	else
		return 0
	end
end
local function udp_and_binrary_is_not_better(ctrl_info)
	if (ctrl_info['udp_send']+ctrl_info['udp_get']+ctrl_info['binrary_send'])/(ctrl_info['udp_get']+ctrl_info['binrary_get'])  > (ctrl_info['binrary_send']/ctrl_info['binrary_get']) then
		return 1
	else
		return 0
	end
end
local function method_control(dst_ip,iface,result,ctrl_info,send_l3_sock,VERBOSE)
	local last_hop_condvar = nmap.condvar(result)
	--udp和步进平均发包大于步进单独平均发包
	-- now_method   --0 udp和步进;1 步进；2 二分，3 udp和二分
	--进入默认方法upd和步进的决策
	if ctrl_info['now_method'] ==0 then
		last_hop_combine_one_step(dst_ip,iface,ctrl_info,send_l3_sock,VERBOSE)
		--udp和步进 平均发包大于步进
		if  udp_and_one_step_is_not_better(ctrl_info) ==1 then
			--步进发包大于5，使用二分
			if (ctrl_info['one_step_send']/ctrl_info['one_step_get']) > 5 then
				ctrl_info['now_method']=2
			else
				--步进发包小于5，使用步进
				ctrl_info['now_method']=1
			end
		else--如果udp和步进法 发包小于步进法
			--判定步进发包是否大于5，大于5 转合并和二分法
			if (ctrl_info['one_step_send']/ctrl_info['one_step_get']) > 5 then 
				ctrl_info['now_method']=3
			end
		end
	end
	--进入udp和二分法的决策
	if ctrl_info['now_method'] == 3 then
		last_hop_combine_binrary(dst_ip,iface,ctrl_info,send_l3_sock,VERBOSE)
		--如果udp和二分平均发包量大于二分法
		if udp_and_binrary_is_not_better(ctrl_info) ==1 then
			--采用二分法
			ctrl_info['now_method']=2
		end
	end
	--进入步进法的决策
	if ctrl_info['now_method'] == 1 then
		last_hop_one_step(dst_ip,iface,ctrl_info,send_l3_sock,VERBOSE)--步进
		if (ctrl_info['one_step_send']/ctrl_info['one_step_get']) > 5 then
			ctrl_info['now_method']=2
		end
	end
	--二分法
	if ctrl_info['now_method'] == 2 then
		last_hop_binrary(dst_ip,iface,ctrl_info,send_l3_sock,VERBOSE)--二分
	end
	last_hop_condvar "signal"
end
local function test(point)
	point['a']=1
end

action=function()
	print("__________________")
	-- print(MID_IP("1.1.1.1",29))
	local ifname = nmap.get_interface() or host.interface
	if not ifname then
		return fail("Failed to determine the network interface name")
	end
	iface = nmap.get_interface_info(ifname)
	send_l3_sock = nmap.new_dnet()
	send_l3_sock:ip_open()
	local dst_ip=stdnse.get_script_args("ip")
	local ip_file=stdnse.get_script_args("ip_file")
	local VERBOSE=stdnse.get_script_args("verbose")
	local thread_count=15
	thread_count=stdnse.get_script_args("thread")
	if thread_count==nil then
		thread_count=15
	end
	thread_count=tonumber(thread_count)
	VERBOSE=tonumber(VERBOSE)
	if (not dst_ip)  and (not ip_file) then
		return fail("error:no target input")
	end
	if (dst_ip)  and (ip_file) then
		return fail("error:muti target")
	end

	local ctrl_info={}
	ctrl_info['udp_send']=0
	ctrl_info['udp_get']=0
	ctrl_info['binrary_send']=0
	ctrl_info['binrary_get']=0
	ctrl_info['one_step_send']=0
	ctrl_info['one_step_get']=0
	ctrl_info['now_method']=0
	ctrl_info['all_send']=0
	ctrl_info['all_get']=0
	ctrl_info['traceroute_send']=0
	local all_send
	local all_get
	local last_hop_thread_handler={}
	local last_hop_result={}
	local last_hop_condvar = nmap.condvar(last_hop_result)
	if dst_ip then
		local ip, err = ipOps.expand_ip(dst_ip)
		if not err then
			-- local test={}
			-- test[1]="asfd"
			local last_hop_co = stdnse.new_thread(method_control,dst_ip,iface,last_hop_result,ctrl_info,send_l3_sock,VERBOSE)
			last_hop_thread_handler[last_hop_co] = true
			-- last_hop_main(dst_ip,iface)
			-- print(test[1])
		else
			print("error:illege ip",dst_ip)
			return true
		end
	elseif ip_file then 		--从文件读入
		--ip_file="ip10wt"
		local ip_count=0
		local ip_list={}
		for line in io.lines(ip_file) do
			local ip=line
			local temp, err = ipOps.expand_ip(ip)
			if not err then
				-- print(ip,ip_count)
				table.insert(ip_list,ip)
			else
				print("error:illege ip:",ip)
			end
			-- stdnse.sleep(1)
			if #ip_list >= thread_count then
				-- print('begin thread last_hop',ip_count)
				for i in pairs(ip_list) do
					local last_hop_co = stdnse.new_thread(method_control,ip_list[i],iface,last_hop_result,ctrl_info,send_l3_sock,VERBOSE)
					last_hop_thread_handler[last_hop_co] = true
				end
				
			    repeat
			        for thread in pairs(last_hop_thread_handler) do
			            if coroutine.status(thread) == "dead" then
			                last_hop_thread_handler[thread] = nil
			            end
			        end
			        if (next(last_hop_thread_handler)) then
			            last_hop_condvar "wait"
			        end
			    until next(last_hop_thread_handler) == nil
				all_send=(ctrl_info['udp_send']+ctrl_info['one_step_send']+ctrl_info['binrary_send'])
				all_get=(ctrl_info['udp_get']+ctrl_info['one_step_get']+ctrl_info['binrary_get'])
				print("all      send,get,avg",all_send,all_get,all_send/all_get)
				print("udp      send,get,avg",ctrl_info['udp_send'],ctrl_info['udp_get'],ctrl_info['udp_send']/ctrl_info['udp_get'])
				print("one_step send,get,avg",ctrl_info['one_step_send'],ctrl_info['one_step_get'],ctrl_info['one_step_send']/ctrl_info['one_step_get'])
				print("binrary  send,get,avg",ctrl_info['binrary_send'],ctrl_info['binrary_get'],ctrl_info['binrary_send']/ctrl_info['binrary_get'])
				print("trace    send,get,avg",ctrl_info['traceroute_send'],all_get,ctrl_info['traceroute_send']/all_get)
			    ip_list={}
			end--end of if #ip_list>=15
		end--end of for
		--处理剩余不足15个ip
		-- print('begin thread last_hop',ip_count)
		for i in pairs(ip_list) do
			local last_hop_co = stdnse.new_thread(method_control,ip_list[i],iface,last_hop_result,ctrl_info,send_l3_sock,VERBOSE)
			last_hop_thread_handler[last_hop_co]=true
		end
		
	    repeat
	        for thread in pairs(last_hop_thread_handler) do
	            if coroutine.status(thread) == "dead" then
	                last_hop_thread_handler[thread] = nil
	            end
	        end
	        if (next(last_hop_thread_handler)) then
	            last_hop_condvar "wait"
	        end
	    until next(last_hop_thread_handler) == nil
	end
	all_send=(ctrl_info['udp_send']+ctrl_info['one_step_send']+ctrl_info['binrary_send'])
	all_get=(ctrl_info['udp_get']+ctrl_info['one_step_get']+ctrl_info['binrary_get'])
	print("all send ,get,avg",all_send,all_get,all_send/all_get)
	-- last_hop_main(dst_ip,iface)
	print("__________________")
	-- local s = Stack:new()
	-- s:push(1)
	-- s:push(2)
	-- print(s:top())
	-- s:printElement()
	send_l3_sock:ip_close()

	return true
end