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
			pass
		else:
			difference[d]={}
			difference[d]['32']=0
			difference[d]['64']=0
			difference[d]['128']=0
			difference[d]['256']=0
		left_ttl=int(line.split()[6])
		if left_ttl>=256:
			print "never happen"+line.split()[0]
		elif left_ttl>=128:
			difference[d]['256']+=1
		elif left_ttl>=64:
			difference[d]['128']+=1
		elif left_ttl>=32:
			difference[d]['64']+=1
		else:
			difference[d]['32']+=1

for key in difference:
	print "\n"
	print key
	s=0
	for d in difference[key]:
		s+=difference[key][d]
	for d in difference[key]:
		print d,difference[key][d],100*difference[key][d]/s,"%"

fr.close()
