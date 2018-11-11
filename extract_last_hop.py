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
fwl=open(file_path_l,'w')
fwa=open(file_path_a,'w')
fwf=open(file_path_f,'w')
fwts=open(file_path_ts,'w')
fwtb=open(file_path_tb,'w')
fwpu=open(file_path_pu,'w')
fwudp=open(file_path_udp,'w')
fwgs=open(file_path_gs,'w')
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
difference={}
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
	elif "too small" in line:
		small=small+1
		fwts.write(line.split()[0]+"\n")
	elif "too big" in line:
		big=big+1
		fwtb.write(line.split()[0]+"\n")
	elif line[0]=="#":
		last_hop_count=last_hop_count+1
		fwl.write(line.split()[1]+"\n")
		last_hop_set.add(line.split()[1])
	elif ("icmp pu") in line:
		icmp_pu=icmp_pu+1
		#fwpu.write(line.split()[0]+"\n")
	elif "traceroute guess success" in line :
		traceroute_success=traceroute_success+1
	elif  "traceroute fail!" in line:
		traceroute_fail=traceroute_fail+1
	elif "first" in line:
		first=first+1
	elif "udp_to_get_last_hop" in line:
		fwudp.write(line.split()[0]+"\n")
		udp_to_get_last_hop=udp_to_get_last_hop+1
	elif "guest_ttl_success" in line:
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
		d=line.split()[4]
		if difference.has_key(d):
			difference[d]=difference[d]+1
		else:
			difference[d]=1
	else:
		pass

left=guest_ttl_success_set.difference(last_hop_set)
print len(last_hop_set)
print len(guest_ttl_success_set)
print len(left)

for key in difference:
	print key,difference[key]

print "action:",
print action
print "icmp port unreachable:",
print icmp_pu,100*icmp_pu/action
print "receive port unreachable,but_no_reply:",
print but_no_reply,100*but_no_reply/action

print "guess too small:",
print small
print "guest too big:",
print big
print "no receive first echo reply:",
print first


print "last_hop_count:",
print last_hop_count,len(last_hop_set),100*last_hop_count/action
print "udp_to_get_last_hop:",
print udp_to_get_last_hop,100*udp_to_get_last_hop/last_hop_count
print "all_guest",
print all_guest,100*all_guest/action
print "guest ttl fail:",
print guest_ttl_fail,100*guest_ttl_fail/all_guest
print "guest_ttl_success:",
print guest_ttl_success,len(guest_ttl_success_set),100*guest_ttl_success/last_hop_count
print "traceroute_success:",
print traceroute_success,100*traceroute_success/last_hop_count
print "traceroute_fail:",
print traceroute_fail,100*traceroute_fail/all_guest


print "have_guessed_no_get:",
print have_guessed_no_get,100*have_guessed_no_get/last_hop_count
print "have_guessed_no_get_again:",
print have_guessed_no_get_again,100*have_guessed_no_get_again/guest_ttl_success

fr.close()
fwl.close()
fwf.close()
fwa.close()
fwts.close()
fwtb.close()
fwpu.close()
fwudp.close()
fwgs.close()