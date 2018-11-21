import os
import sys
file_path=sys.argv[1]
print file_path
fr=open(file_path,'r')

first_predict_no_rely=0
first_send_left_ttl_no_reply=0
one_step_success=0
set_ttl_and_send=0
difference={}
while True:
	line = fr.readline()
	if not line:
		break
	if "action" in line:
		action=action+1
	elif "first send left ttl no reply" in line:
		first_send_left_ttl_no_reply=first_send_left_ttl_no_reply+1
	elif "first predict ttl by ping fail,no receive reply" in line:
		first_predict_no_rely=first_predict_no_rely+1
	elif "one step guess ttl success" in line:
		one_step_success=one_step_success+1
	elif "difference" in line:
		d=int(line.split()[4])
		if d<0:
			d=d*(-1)
		one_step=one_step+d+1
		if difference.has_key(d):
			difference[d].append(line.split()[0])
		else:
			difference[d]=[]
			difference[d].append(line.split()[0])
	elif "set ttl and send:" in line:
		set_ttl_and_send=set_ttl_and_send+1
	else:
		pass

print "action:",
print action
print "one_step_success:",
print one_step_success
print "first_send_left_ttl_no_reply:",
print first_send_left_ttl_no_reply
print "first_predict_no_rely:",
print first_predict_no_rely
print "one step send packet number:",
print set_ttl_and_send
