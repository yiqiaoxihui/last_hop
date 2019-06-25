 # -*- coding:utf-8 -*-

#描述：从末跳发现输出信息中，统计末跳获取量
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

if sys.argv[2] == "1":
	fwl=open(file_path_l,'w')
	fwa=open(file_path_a,'w')

one_step_success=0
action=0
last_hop_count=0


while True:
	line = fr.readline()
	if not line:
		break
	if "action" in line:
		action=action+1
		if sys.argv[2] == "1":
			fwa.write(line.split()[1]+"\n")
	elif "#get_last_hop" in line:
		last_hop_count=last_hop_count+1
		if sys.argv[2] == "1":
			fwl.write(line.split()[1]+" "+line.split()[3]+"\n")
	else:
		pass
if action==0:
	action=1
if last_hop_count==0:
	last_hop_count=1
print "do lasthop ip:",
print action

print "get last hop count,last_hop_count/action(%):",
print last_hop_count,last_hop_count*1.0/action


# print "have_guessed_no_get:",
# print have_guessed_no_get,100*have_guessed_no_get/guest_ttl_success
# print "have_guessed_no_get_again:",
# print have_guessed_no_get_again,100*have_guessed_no_get_again/guest_ttl_success
fr.close()
if sys.argv[2] == "1":
	fwl.close()
	fwa.close()



