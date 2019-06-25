import os
import sys
import re
file_path_all=sys.argv[1]
file_path_sub=sys.argv[2]

fr1=open(file_path_all,'r')
list_ip_all=fr1.readlines()
fr1.close()

fr2=open(file_path_sub,'r')
list_ip_sub=fr2.readlines()
fr2.close()
fw=open(file_path_all+"-sub-"+file_path_sub,'w')
l1=[]
l2=[]
for ip in list_ip_all:
	l1.append(ip.strip())
for ip in list_ip_sub:
	l2.append(ip.strip())
for ip in l1:
	if ip not in l2:
		fw.write(ip+"\n")
fw.close()
