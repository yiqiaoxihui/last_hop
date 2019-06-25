import os
import sys
file_path=sys.argv[1]
print file_path
fr=open(file_path,'r')
list_ip=fr.readlines()
fr.close()
fw=open(file_path,'w')
for line in list_ip:
	print line
	fw.write(line.split()[0]+"\n")
fw.close()
