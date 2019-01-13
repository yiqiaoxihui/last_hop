import os
import sys
import re
file_path=sys.argv[1]
print file_path
fr=open(file_path,'r')
list_ip=fr.readlines()
fr.close()
fw=open(sys.argv[2],'w')
reg_ip=r'((?:(?:1[0-9][0-9]\.)|(?:2[0-4][0-9]\.)|(?:25[0-5]\.)|(?:0{0,3}[1-9][0-9]\.)|(?:0{0,3}[0-9]\.)){3}(?:(?:1[0-9][0-9])|(?:2[0-4][0-9])|(?:25[0-5])|(?:0{0,3}[1-9][0-9])|(?:0{0,3}[0-9])))'
s=set()
for line in list_ip:
	if "ROUTEUR" in line:
		ip_range=re.findall(reg_ip,line)
		if ip_range!=[]:
			ip=ip_range[0]
			s.add(ip)
for ip in s:
	fw.write(ip+"\n")
fw.close()
