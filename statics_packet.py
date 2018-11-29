import os
import sys
file_path=sys.argv[1]
print file_path
fr=open(file_path,'r')
difference={}
while True:
	line = fr.readline()
	if not line:
		break
	elif "difference" in line:
		d=int(line.split()[4])
		# if d<0:
		# 	d=d*(-1)
		if difference.has_key(d):
			difference[d]['count']+=1
			difference[d]['packet']+=int(line.split()[5])
		else:
			difference[d]={}
			difference[d]['count']=1
			difference[d]['packet']=int(line.split()[5])

for key in difference:
	print key,difference[key]['packet']/difference[key]['count']

fr.close()