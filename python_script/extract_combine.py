 # -*- coding:utf-8 -*-

#描述：从末跳发现输出信息中，统计发包量，末跳获取量
#使用方法： python this.py  末跳发现输出信息 数字1/0（1表示统计结果写入文件）

import os
import sys
#import decimal
file_path=sys.argv[1]
print file_path
fr=open(file_path,'r')
#执行末跳发现的目标总数
file_path_a=file_path+".action"
#获取末跳的信息
file_path_l=file_path+".lasthop"

file_path_f=file_path+".guest_ttl_fail"

file_path_pu=file_path+".pu"

file_path_udp=file_path+".udp"
# file_path_gs=file_path+".guess_lasthop_success"
file_path_dv=file_path+".division"

# fwgs=open(file_path_gs,'w')

file_path_first=file_path+".first"

file_path_trace_success=file_path+".trace_succss"

file_path_oss=file_path+".one_step_success"
if sys.argv[2] == "1":
	fwl=open(file_path_l,'w')
	fwa=open(file_path_a,'w')
	fwf=open(file_path_f,'w')

	fwpu=open(file_path_pu,'w')
	fwudp=open(file_path_udp,'w')
	fw_trace_success=open(file_path_trace_success,'w')
	fw_first=open(file_path_first,'w')
	fwdv=open(file_path_dv,'w')
	fw_oss=open(file_path_oss,'w')

first_send_ping_predict_ttl_no_reply=0
one_step_success=0
set_ttl_and_send=0

one_step=0
get_by_first_send_ping_predict_ttl_no_reply=0
last_try_success=0
try_last_time=0
action=0
guest_ttl_fail=0
small=0
big=0
last_hop_count=0
icmp_pu=0
traceroute_fail=0
traceroute_success=0
first_ping_no_reply=0
udp_to_get_last_hop=0
guess_lasthop_success=0
all_guest=0
but_no_reply=0
last_hop_set=set()
guest_ttl_success_set=set()
have_guessed_no_get=0
have_guessed_no_get_again=0

set_ttl_and_send=0 
difference={}
traceroute_packet=0
division_to_guest_ttl_success=0
no_need_to_traceroute=0
receive_echo_reply=0
echo_listener_execeed=0
first_predict_ttl_success=0
one_step=0

middle_not_reply=0
method_2_send=0
method_2_guess_success_traceroute_send=0
method_1_traceroute_send=0
ONLY_ECHO_REPLY=0
NO_ECHO_REPLY=0
while True:
	line = fr.readline()
	if not line:
		break
	if "action" in line:
		action=action+1
		if sys.argv[2] == "1":
			fwa.write(line.split()[1]+"\n")
	elif "guest_ttl_fail" in line:
		guest_ttl_fail=guest_ttl_fail+1
		if sys.argv[2] == "1":
			fwf.write(line.split()[0]+"\n")
	elif "#get_last_hop" in line:
		last_hop_count=last_hop_count+1
		if sys.argv[2] == "1":
			fwl.write(line.split()[1]+" "+line.split()[3]+"\n")
		last_hop_set.add(line.split()[1])
	elif ("icmp pu") in line:
		icmp_pu=icmp_pu+1
		if sys.argv[2] == "1":
			fwpu.write(line.split()[2]+"\n")
	elif "traceroute guess success" in line:
		traceroute_success=traceroute_success+1
		if sys.argv[2] == "1":
			fw_trace_success.write(line.split()[0]+"\n")
	elif  "traceroute guess fail" in line:
		traceroute_fail=traceroute_fail+1
	elif "division to guest ttl success" in line:
		division_to_guest_ttl_success=division_to_guest_ttl_success+1
		if sys.argv[2] == "1":		
			fwdv.write(line.split()[0]+"\n")
	elif "first predict ttl by ping fail,no receive reply" in line:
		first_ping_no_reply=first_ping_no_reply+1
		if sys.argv[2] == "1":
			fw_first.write(line.split()[0]+"\n")
	elif "udp_to_get_last_hop" in line:
		if sys.argv[2] == "1":
			fwudp.write(line.split()[0]+"\n")
		udp_to_get_last_hop=udp_to_get_last_hop+1
	elif "begin to guest ttl" in line:
		all_guest=all_guest+1
	elif "but last hop no reply" in line:		#receive icmp port unreachable packet,but last hop no reply
		but_no_reply=but_no_reply+1
	elif line[-37:]=="have guessed ttl,but no get last_hop\n":
		have_guessed_no_get=have_guessed_no_get+1
	elif "but no get last_hop again" in line:
		have_guessed_no_get_again=have_guessed_no_get_again+1
	elif "difference" in line:
		# traceroute_packet+=int(line.split()[1])
		method_2_send+=int(line.split()[5])
		d=int(line.split()[4])

		if difference.has_key(d):
			difference[d].append(line.split()[0])
		else:
			difference[d]=[]
			difference[d].append(line.split()[0])
		traceroute_packet=traceroute_packet+int(line.split()[1])
		method_2_guess_success_traceroute_send+=int(line.split()[1])
		ip=line.split()[0]
		# fwgs.write(ip+"\n")
		guess_lasthop_success=guess_lasthop_success+1
		one_step_success=one_step_success+1
		if sys.argv[2] == "1":		
			fw_oss.write(line.split()[0]+"\n")
	elif "set ttl and send" in line:
		set_ttl_and_send=set_ttl_and_send+1
	elif "last hop no reply,no need to traceroute" in line:
		no_need_to_traceroute=no_need_to_traceroute+1
	elif "receive echo reply" in line:
		receive_echo_reply=receive_echo_reply+1
	elif "echo listener:no reply back" in line:
		echo_listener_execeed=echo_listener_execeed+1
	elif "first predict ttl by ping success,receive reply" in line:
		first_predict_ttl_success=first_predict_ttl_success+1
	elif "first send left ttl no reply" in line:
		first_send_ping_predict_ttl_no_reply=first_send_ping_predict_ttl_no_reply+1
	elif "get_by_no_reply" in line:
		get_by_first_send_ping_predict_ttl_no_reply+=1
	# elif "one step guess ttl success" in line:
	# 	one_step_success=one_step_success+1
	# 	fw_oss.write(line.split()[0]+"\n")
	# elif "one step guess ttl fail" in line:
	# 	traceroute_packet+=0	#int(line.split()[2])--未成功获取末跳的，发包不算在内
	elif "set new ttl by icmp port unreachable" in line:
		traceroute_packet=traceroute_packet+int(line.split()[0])
		method_1_traceroute_send+=int(line.split()[0])
	# elif "guess_lasthop_success" in line:
	# 	traceroute_packet=traceroute_packet+int(line.split()[1])
	# 	method_2_guess_success_traceroute_send+=int(line.split()[1])
	# 	ip=line.split()[0]
	# 	fwgs.write(ip+"\n")
	# 	guess_lasthop_success=guess_lasthop_success+1
	elif "middle router no reply,binrary can not deal" in line:
		middle_not_reply+=1
	elif "NO_ECHO_REPLY" in line:
		NO_ECHO_REPLY+=1
	elif "ONLY_ECHO_REPLY" in line:
		ONLY_ECHO_REPLY+=1
	else:
		pass
if action==0:
	action=1
if last_hop_count==0:
	last_hop_count=1

# print "listener no echo reply back:",
# print echo_listener_execeed
get_and_ping_reply=0
one_step_sum=0
p_sum=0
for key in difference:
	p_sum+=len(difference[key])
print "p_sum",p_sum
send_pack_dic={}
for i in range (-200,1):
	send_pack_dic[i]=-i +3
for i in range(1,200):
	send_pack_dic[i]=i+2
m2_send_packet_test=0
for key in difference:
	m2_send_packet_test+=send_pack_dic[key]*len(difference[key])
	print key,len(difference[key]),len(difference[key])*1.0/p_sum
	one_step_sum=one_step_sum+(key+1)*len(difference[key])
	get_and_ping_reply+=len(difference[key])
print "m2_send_packet_test",m2_send_packet_test
	# for ip in difference[key]:
	# 	print ip
# print "get and ping reply:",
# print get_and_ping_reply
# print "one_step_sum:",
# if difference.has_key(0):
# 	one_step_sum=one_step_sum+len(difference[0])
# print one_step_sum

print "action:",
print action

print "r get last hop count:",
print last_hop_count,len(last_hop_set),last_hop_count*1.0/action

print "***************************icmp****************************"
print "receive upd port unreachable:",icmp_pu,icmp_pu*1.0/action
print "--receive port unreachable,but last hop no reply:",but_no_reply,but_no_reply*1.0/action
print "--icmp_pu-but_no_reply,upd_get_last_hop,zhanbi",icmp_pu-but_no_reply,udp_to_get_last_hop,(icmp_pu-but_no_reply)*1.0/action

print "***************************guess****************************"
print "number need to guest:",all_guest,all_guest*1.0/action
print "guess_lasthop_success:",guess_lasthop_success,len(guest_ttl_success_set),guess_lasthop_success*1.0/last_hop_count
print "guest ttl fail:",guest_ttl_fail
print "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
print "--division to guest ttl success:",division_to_guest_ttl_success
print "--no need to traceroute:",no_need_to_traceroute
print "middle_not_reply:",middle_not_reply
print "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"

print "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
print "one_step_success:",one_step_success
if all_guest!=0:
	print "one_step_success/all_guest",one_step_success*1.0/all_guest
else:
	print "one_step_success/action",one_step_success*1.0/action
print "--first ping get,first_ping_no_reply:",first_predict_ttl_success,first_ping_no_reply
print "----first_send_ping_predict_ttl_no_reply,get_by_first_send_ping_predict_ttl_no_reply:",
print first_send_ping_predict_ttl_no_reply,get_by_first_send_ping_predict_ttl_no_reply
print "ONLY_ECHO_REPLY,NO_ECHO_REPLY:",ONLY_ECHO_REPLY,NO_ECHO_REPLY
print "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"


print "*************************send packet**************************"
print "method 1 all udp send packet:",
if all_guest==0:
	print 0
else:
	print action+icmp_pu-but_no_reply,action,icmp_pu-but_no_reply
print "method 1 traceroute send packet:",
print method_1_traceroute_send

print "method2 all guest send packet,bujin,erfen:",set_ttl_and_send+all_guest,set_ttl_and_send
print "--set_ttl_and_send:",set_ttl_and_send
print "--all_guest:",all_guest
print "method2 all guest success send packet:",method_2_send
print "method2 success guess traceroute send packet:",method_2_guess_success_traceroute_send
print "method2 average send:",method_2_send*1.0/one_step_success


# print "one_step:",
# print one_step
print "\nall my send packet:",
if all_guest==0:
	print method_2_send
	print "\nall my average send packet:",
	print method_2_send*1.0/(udp_to_get_last_hop+one_step_success)
else:
	print action+udp_to_get_last_hop+method_2_send
	print action,udp_to_get_last_hop,method_2_send
	print "\nall my average send packet:",
	print (action+udp_to_get_last_hop+method_2_send)*1.0/(udp_to_get_last_hop+one_step_success)
# print icmp_pu+set_ttl_and_send+action+all_guest


print "traceroute:",traceroute_packet
print "\nall traceroute average send packet:", traceroute_packet*1.0/(udp_to_get_last_hop+one_step_success)
print "method1 traceroute:",method_1_traceroute_send
print "method2 traceroute:",method_2_guess_success_traceroute_send


# print "have_guessed_no_get:",
# print have_guessed_no_get,100*have_guessed_no_get/guest_ttl_success
# print "have_guessed_no_get_again:",
# print have_guessed_no_get_again,100*have_guessed_no_get_again/guest_ttl_success
fr.close()
if sys.argv[2] == "1":
	fwl.close()
	fwf.close()
	fwa.close()

	fwpu.close()
	fwudp.close()
	# fwgs.close()
	fw_first.close()
	fwdv.close()
	fw_oss.close()


