import os
import sys
import shlex
import subprocess
import time
file_path=sys.argv[1]
print file_path
# fr=open(file_path,'r')
# l=[]
# action=[]
# last_hop=[]
# while True:
# 	line=fr.readline().strip()
# 	if not line:
# 		break
# 	else:
# 		l.append(line)
# fr.close()
last_hop=set()
for i in range(0,20):
	time.sleep(3)
	left=set()
	action=set()
	cmd="nmap -sn -n -e eno2 --script /home/ly/nmap_script/last_hop/guess_one_step.lua --max-hostgroup 50 -iL "+file_path
	cmd = shlex.split(cmd)
	p = subprocess.Popen(cmd, shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
	while p.poll() is None:
		line = p.stdout.readline()
		line = line.strip()
		if line:
			if "action" in line:
				action.add(line.split()[1])
			elif "difference" in line:
				# print "turns:"+str(i)
				#print line
				last_hop.add(line.split()[0])
			else:
				pass
	if p.returncode == 0:
		print('Subprogram success')
		print i
		left=action.difference(last_hop)
		print "action:"+str(len(action))
		print "last_hop:"+str(len(last_hop))
		print "left:"+str(len(left))
		if len(left)==0:
			print "all ip get last_hop"
			break
		fw=open(file_path,'w')
		for ip in left:
			fw.write(ip+"\n")
		fw.close()
	else:
		print('Subprogram failed')
		print i
		break

