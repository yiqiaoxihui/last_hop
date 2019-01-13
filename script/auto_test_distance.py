import os
import sys
import shlex
import subprocess
import time
file_path=sys.argv[2]
script_path=sys.argv[1]
print script_path, file_path

for i in range(1,8):
	for j in range(1,8):
		print "\n\ndistance:"+str(i)+","+str(j)
		time.sleep(3)
		fw=open("guess.distance."+str(i)+"."+str(j),"w")
		cmd="nmap -sn -n -e eno2 --script "+script_path+" -iL "+file_path+" --script-args='distance="+str(i)+",second_distance="+str(j)+"'"
		cmd = shlex.split(cmd)
		p = subprocess.Popen(cmd, shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
		difference={}
		set_ttl_and_send=0
		while p.poll() is None:
			line = p.stdout.readline()
			fw.write(line)
			line = line.strip()
			if line:
				if "difference" in line:
					d=int(line.split()[4])
					if difference.has_key(d):
						difference[d]['count']+=1
						difference[d]['packet']+=int(line.split()[5])
					else:
						difference[d]={}
						difference[d]['count']=1
						difference[d]['packet']=int(line.split()[5])
				elif "set ttl and send" in line:
					set_ttl_and_send=set_ttl_and_send+1

		fw.close()
		for key in difference:
			print key,10*difference[key]['packet']/difference[key]['count']
		print "set_ttl_and_send:",set_ttl_and_send
		if p.returncode == 0:
			print('Subprogram success')
		else:
			print('Subprogram failed')
			print i
			break