import os
import sys
file_path=sys.argv[1]
print file_path
fr=open(file_path,'r')


file_path_oss=file_path+".one_step_success"
fw_oss=open(file_path_oss,'w')
first_predict_no_rely=0
first_send_left_ttl_no_reply=0
one_step_success=0
set_ttl_and_send=0
action=0
difference={}
one_step=0
get_by_no_reply=0
last_try_success=0
try_last_time=0

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
	elif "get_by_no_reply,one step guess ttl success" in line:
		get_by_no_reply+=1
	elif "one step guess ttl success" in line:
		one_step_success=one_step_success+1
		fw_oss.write(line.split()[0]+"\n")
	elif "try last time" in line:
		try_last_time+=1
	elif "last try success" in line:
		last_try_success+=1
	elif "difference" in line:
		d=int(line.split()[4])
		# if d<0:
		# 	d=d*(-1)
		# one_step=one_step+d+1
		if difference.has_key(d):
			difference[d].append(line.split()[0])
		else:
			difference[d]=[]
			difference[d].append(line.split()[0])
	elif "set ttl and send" in line:
		set_ttl_and_send=set_ttl_and_send+1
	else:
		pass

print "action:",
print action
print "one_step_success:",
print one_step_success
print "try last time",
print	try_last_time
print "last try success",
print	last_try_success
print "first_send_left_ttl_no_reply:",
print first_send_left_ttl_no_reply
print "get_by_no_reply:",
print get_by_no_reply
print "first ping no reply:",
print first_predict_no_rely
print "one step send packet number:",
print set_ttl_and_send


print one_step
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

fr.close()
fw_oss.close()