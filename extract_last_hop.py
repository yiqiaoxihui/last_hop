import os
import sys
file_path=sys.argv[1]
print file_path
fr=open(file_path,'r')


file_path_l=file_path+".lasthop"
file_path_a=file_path+".action"
file_path_f=file_path+".traceroute_fail"
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

set_new_ttl_by_icmp_port_unreachable=0
set_ttl_and_send=0 
reset_ttl_by_traceroute=0
difference={}
traceroute_packet=0
division_to_guest_ttl_success=0
no_need_to_traceroute=0
receive_echo_reply=0
no_echo_reply_back=0
first_predict_ttl_success=0
one_step=0
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
	elif line[0]=="#":
		last_hop_count=last_hop_count+1
		fwl.write(line.split()[1]+"\n")
		last_hop_set.add(line.split()[1])
	elif ("icmp pu") in line:
		icmp_pu=icmp_pu+1
		#fwpu.write(line.split()[0]+"\n")
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
	elif "guest_ttl_success" in line:
		traceroute_packet=traceroute_packet+int(line.split()[1])
		ip=line.split()[0]
		fwgs.write(ip+"\n")
		if ip in guest_ttl_success_set:
			print "repeat guest_ttl_success:"+ip
		else:
			guest_ttl_success_set.add(ip)
		guest_ttl_success=guest_ttl_success+1
	elif "begin to guest ttl" in line:
		all_guest=all_guest+1
	elif "but last hop no reply" in line:		#receive icmp port unreachable packet,but last hop no reply
		but_no_reply=but_no_reply+1
	elif line[-37:]=="have guessed ttl,but no get last_hop\n":
		have_guessed_no_get=have_guessed_no_get+1
	elif "but no get last_hop again" in line:
		have_guessed_no_get_again=have_guessed_no_get_again+1
	elif "difference" in line:
		d=int(line.split()[4])
		if d<0:
			d=d*(-1)
		if d==0:
			one_step=one_step+2
		else:
			one_step+=d+1
		if difference.has_key(d):
			difference[d].append(line.split()[0])
		else:
			difference[d]=[]
			difference[d].append(line.split()[0])
	elif "set ttl and send:" in line:
		set_ttl_and_send=set_ttl_and_send+1
	elif "set new ttl by icmp port unreachable" in line:
		traceroute_packet=traceroute_packet+int(line.split()[0])
		set_new_ttl_by_icmp_port_unreachable=set_new_ttl_by_icmp_port_unreachable+1
	elif "reset ttl by traceroute" in line:
		reset_ttl_by_traceroute=reset_ttl_by_traceroute+1
	elif "traceroute fail get max time limit" in line:
		traceroute_packet=traceroute_packet+int(line.split()[1])
	elif "last hop no reply,no need to traceroute" in line:
		no_need_to_traceroute=no_need_to_traceroute+1
	elif "receive echo reply" in line:
		receive_echo_reply=receive_echo_reply+1
	elif "no echo reply back!!!!!!" in line:
		no_echo_reply_back=no_echo_reply_back+1
	elif "first predict ttl by ping success,receive reply" in line:
		first_predict_ttl_success=first_predict_ttl_success+1
	else:
		pass

left=guest_ttl_success_set.difference(last_hop_set)
left1=last_hop_set.difference(guest_ttl_success_set)
print len(last_hop_set)
print len(guest_ttl_success_set)
print len(left)
print len(left1)

one_step_sum=0
for key in difference:
	print key,len(difference[key])
	one_step_sum=one_step_sum+(key+1)*len(difference[key])
	# for ip in difference[key]:
	# 	print ip
print "one_step_sum:",
print one_step_sum
one_step_sum=one_step_sum+len(difference[0])
print one_step_sum
if action==0:
	action=1
if last_hop_count==0:
	last_hop_count=1
if guest_ttl_success==0:
	guest_ttl_success=1
if all_guest==0:
	all_guest=1

print "action:",
print action

print "get last hop count:",
print last_hop_count,len(last_hop_set),100*last_hop_count/action

print "***************************icmp****************************"
print "receive upd port unreachable:",
print icmp_pu,100*icmp_pu/action

print "receive port unreachable,but last hop no reply:",
print but_no_reply,100*but_no_reply/action

print "receive port unreachable,and get last hop",
print icmp_pu-but_no_reply,100-100*but_no_reply/action
print "udp_to_get_last_hop:",
print udp_to_get_last_hop,100*udp_to_get_last_hop/last_hop_count
print "\n\n"

print "***************************guess****************************"
print "number need to guest:",
print all_guest,100*all_guest/action


print "\nguest ttl success:",
print guest_ttl_success,len(guest_ttl_success_set),100*guest_ttl_success/last_hop_count
print "--division to guest ttl success:",
print division_to_guest_ttl_success
print "--traceroute guess success:",
print traceroute_success,100*traceroute_success/last_hop_count
print "--traceroute guess fail:",
print traceroute_fail

print "\nguest ttl fail:",
print guest_ttl_fail

print "first predict ttl by ping fail,no receive reply:",
print first
print "first predict ttl by ping success,receive reply:",
print first_predict_ttl_success
print "receive_echo_reply:",
print receive_echo_reply
print "listener no echo reply back:",
print no_echo_reply_back


print "first predict ttl by ping too small:",
print small
print "first predict ttl by ping too big:",
print big
print "no need to traceroute:",
print no_need_to_traceroute
print "*************************send packet**************************"
print "set_new_ttl_by_icmp_port_unreachable:",
print set_new_ttl_by_icmp_port_unreachable
print "set_ttl_and_send:",
print set_ttl_and_send
print "one_step:",
print one_step
print "reset_ttl_by_traceroute",
print reset_ttl_by_traceroute
print "my send packet:",
print set_new_ttl_by_icmp_port_unreachable+set_ttl_and_send+reset_ttl_by_traceroute+action
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