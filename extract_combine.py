import os
import sys
#import decimal
file_path=sys.argv[1]
print file_path
fr=open(file_path,'r')


file_path_l=file_path+".lasthop"
file_path_a=file_path+".action"
file_path_f=file_path+".guest_ttl_fail"
file_path_ts=file_path+".small"
file_path_tb=file_path+".big"
file_path_pu=file_path+".pu"
file_path_udp=file_path+".udp"
file_path_gs=file_path+".guest_ttl_success"
file_path_dv=file_path+".division"
fwl=open(file_path_l,'w')
fwa=open(file_path_a,'w')
fwf=open(file_path_f,'w')
fwts=open(file_path_ts,'w')
fwtb=open(file_path_tb,'w')
fwpu=open(file_path_pu,'w')
fwudp=open(file_path_udp,'w')
fwgs=open(file_path_gs,'w')
fwdv=open(file_path_dv,'w')
file_path_first=file_path+".first"
fw_first=open(file_path_first,'w')
file_path_trace_success=file_path+".trace_succss"
fw_trace_success=open(file_path_trace_success,'w')
file_path_oss=file_path+".one_step_success"
fw_oss=open(file_path_oss,'w')
first_send_left_ttl_no_reply=0
one_step_success=0
set_ttl_and_send=0

one_step=0
get_by_no_reply=0
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
first=0
udp_to_get_last_hop=0
guest_ttl_success=0
all_guest=0
but_no_reply=0
last_hop_set=set()
guest_ttl_success_set=set()
have_guessed_no_get=0
have_guessed_no_get_again=0

set_ttl_and_send=0 
reset_ttl_by_traceroute=0
difference={}
traceroute_packet=0
division_to_guest_ttl_success=0
no_need_to_traceroute=0
receive_echo_reply=0
echo_listener_execeed=0
first_predict_ttl_success=0
one_step=0
send_again=0
middle_not_reply=0
method_2_send=0
method_2_traceroute_send=0
method_1_traceroute_send=0
while True:
	line = fr.readline()
	if not line:
		break
	if "action" in line:
		action=action+1
		fwa.write(line.split()[1]+"\n")
	elif "guest_ttl_fail" in line:
		guest_ttl_fail=guest_ttl_fail+1
		fwf.write(line.split()[0]+"\n")
	elif "set max_ttl too small" in line:
		small=small+1
		fwts.write(line.split()[0]+"\n")
	elif "set min_ttl too big" in line:
		big=big+1
		fwtb.write(line.split()[0]+"\n")
	elif "#get_last_hop" in line:
		last_hop_count=last_hop_count+1
		fwl.write(line.split()[1]+"\n")
		last_hop_set.add(line.split()[1])
	elif ("icmp pu") in line:
		icmp_pu=icmp_pu+1
		fwpu.write(line.split()[2]+"\n")
	elif "traceroute guess success" in line:
		traceroute_success=traceroute_success+1
		fw_trace_success.write(line.split()[0]+"\n")
	elif  "traceroute guess fail" in line:
		traceroute_fail=traceroute_fail+1
	elif "division to guest ttl success" in line:
		division_to_guest_ttl_success=division_to_guest_ttl_success+1
		fwdv.write(line.split()[0]+"\n")
	elif "first predict ttl by ping fail,no receive reply" in line:
		first=first+1
		fw_first.write(line.split()[0]+"\n")
	elif "udp_to_get_last_hop" in line:
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
		method_2_send+=int(line.split()[5])
		d=int(line.split()[4])
		# if d<0:
		# 	d=d*(-1)
		if d==0:
			one_step=one_step+2
		else:
			one_step+=d+1
		if difference.has_key(d):
			difference[d].append(line.split()[0])
		else:
			difference[d]=[]
			difference[d].append(line.split()[0])
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
		first_send_left_ttl_no_reply=first_send_left_ttl_no_reply+1
	elif "get_by_no_reply" in line:
		get_by_no_reply+=1
	elif "one step guess ttl success" in line:
		one_step_success=one_step_success+1
		fw_oss.write(line.split()[0]+"\n")
	elif "one step guess ttl fail" in line:
		traceroute_packet+=int(line.split()[2])
	elif "set new ttl by icmp port unreachable" in line:
		traceroute_packet=traceroute_packet+int(line.split()[0])
		method_1_traceroute_send+=int(line.split()[0])
	elif "guest_ttl_success" in line:
		traceroute_packet=traceroute_packet+int(line.split()[1])
		method_2_traceroute_send+=int(line.split()[1])
		ip=line.split()[0]
		fwgs.write(ip+"\n")
		guest_ttl_success=guest_ttl_success+1
	elif "middle router no reply,binrary can not deal" in line:
		middle_not_reply+=1
	else:
		pass
if action==0:
	action=1
if last_hop_count==0:
	last_hop_count=1
if guest_ttl_success==0:
	guest_ttl_success=1
if all_guest==0:
	all_guest=1
# print "listener no echo reply back:",
# print echo_listener_execeed
get_and_ping_reply=0
one_step_sum=0
p_sum=0
for key in difference:
	p_sum+=len(difference[key])
print "p_sum",p_sum
for key in difference:
	print key,len(difference[key]),len(difference[key])*100/p_sum
	one_step_sum=one_step_sum+(key+1)*len(difference[key])
	get_and_ping_reply+=len(difference[key])
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

print "get last hop count:",
print last_hop_count,len(last_hop_set),100*last_hop_count/action

print "***************************icmp****************************"
print "receive upd port unreachable:",
print icmp_pu,100*icmp_pu/action
print "--receive port unreachable,but last hop no reply:",
print but_no_reply,100*but_no_reply/action
print "--receive port unreachable,and get last hop",
print icmp_pu-but_no_reply,100*(icmp_pu-but_no_reply)/action

print "***************************guess****************************"
print "number need to guest:",
print all_guest,100*all_guest/action
print "--first ping get,no get:",
print first_predict_ttl_success,first
print "guest ttl success:",
print guest_ttl_success,len(guest_ttl_success_set),100*guest_ttl_success/last_hop_count
print "guest ttl fail:",
print guest_ttl_fail
print "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
print "--division to guest ttl success:",
print division_to_guest_ttl_success
print "--no need to traceroute:",
print no_need_to_traceroute
print "middle_not_reply:",middle_not_reply
print "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
print "--one_step_success:",
print one_step_success
# print "--last try success,try last time",
# print last_try_success,try_last_time
print "----get_by_no_reply,all second send no reply:",
print get_by_no_reply,first_send_left_ttl_no_reply


print "first predict ttl by ping too small:",
print small
print "first predict ttl by ping too big:",
print big

print "*************************send packet**************************"
print "method 1 all udp send packet:",
print action+icmp_pu,action,icmp_pu
print "method 1 traceroute send packet:",
print method_1_traceroute_send

print "method2 all guest send packet:",
print  set_ttl_and_send+reset_ttl_by_traceroute+all_guest
print method_2_send
print "method2 traceroute send packet:",
print  method_2_traceroute_send

print "--first ping",
print all_guest
print "--reset_ttl_by_traceroute",
print reset_ttl_by_traceroute
print "--set_ttl_and_send:",
print set_ttl_and_send
print "----send_again",
print send_again

# print "one_step:",
# print one_step
print "my send packet:",
print icmp_pu+set_ttl_and_send+reset_ttl_by_traceroute+action+all_guest

print "traceroute:",
print traceroute_packet


# print "have_guessed_no_get:",
# print have_guessed_no_get,100*have_guessed_no_get/guest_ttl_success
# print "have_guessed_no_get_again:",
# print have_guessed_no_get_again,100*have_guessed_no_get_again/guest_ttl_success
fr.close()
fwl.close()
fwf.close()
fwa.close()
fwts.close()
fwtb.close()
fwpu.close()
fwudp.close()
fwgs.close()
fw_first.close()
fwdv.close()
fw_oss.close()


