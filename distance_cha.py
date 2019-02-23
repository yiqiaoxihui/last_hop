import os
import sys
file_path=sys.argv[1]
print file_path
fr=open(file_path,'r')
fw=open("cha.ip",'w')
difference={}
while True:
	line = fr.readline()
	if not line:
		break
	elif "difference" in line:
		hop=(line.split()[1])
		d=(line.split()[4])
		# if d<0:
		# 	d=d*(-1)
		if difference.has_key(hop):
			pass
		else:
			difference[hop]={}
		if difference[hop].has_key(d):
			difference[hop][d]['count']+=1
			difference[hop][d]['ip'].append(line.split()[0])
		else:
			difference[hop][d]={}
			difference[hop][d]['count']=1
			difference[hop][d]['ip']=[]
			difference[hop][d]['ip'].append(line.split()[0])
		if int(line.split()[6])<20:
			print line
for key in difference:
	print "hop:",key
	#ob=sorted(difference[key].items(),key=lambda item:item[0])
	for item in difference[key]:
		print "gap:",item,"count:",difference[key][item]['count']
		s="hop"+key+"gap"+item+"count"+str(difference[key][item]['count'])+"\n"
		fw.write(s)
		for ip in difference[key][item]['ip']:
			fw.write(ip+" ")
		fw.write("\n")
		#print "gap:",item[0],"count:",item[1]
	print "---------------------------------"
fw.close()
fr.close()


