import os
import sys
file_path=sys.argv[1]

dic={}
fr=open(file_path,'r')
while True:
	line = fr.readline()
	if not line:
		break
	else:
		dic[line.split()[0]]=line.split()[1]
fr.close()

file_path=sys.argv[2]

fr=open(file_path,'r')
while True:
	line = fr.readline()
	if not line:
		break
	else:
		ip=line.split()[0]
		lasthop=line.split()[1]
		if lasthop!= "*" and dic.has_key(ip):
			if dic[ip]!=lasthop:
				print ip,dic[ip],lasthop
			else:
				pass

fr.close()