import os
import sys
file_path=sys.argv[1]
print file_path
fr=open(file_path,'r')
dic={}
while True:
	line = fr.readline().strip()
	if not line:
		break
	elif dic.has_key(line):
		dic[line]=dic[line]+1
	else:
		dic[line]=1

for k in dic:
	if dic[k]>1:
		print(k)

fr.close()

