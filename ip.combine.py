import os
import sys
import re


ip_set=set()
fw=open(sys.argv[2],'w')
list_dir = os.listdir(sys.argv[1])
for file in list_dir:
	print file
	if file[-16:]=="one_step_success":
		fr=open(sys.argv[1]+file,'r')
		while True:
			line=fr.readline()
			if not line:
				break
			else:
				ip_set.add(line.strip())
		fr.close()
for ip in ip_set:
	fw.write(ip+"\n")
fw.close()
