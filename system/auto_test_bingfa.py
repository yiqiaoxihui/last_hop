import os
import sys
import shlex
import subprocess
import time
print "script_path,outfilename,iface,ip"
script_path=sys.argv[1]
file_path=sys.argv[2]
iface=sys.argv[3]
ip=sys.argv[4]

print script_path, file_path
packet_type_dic={}

for key in range(10,100,10):
	print "key:",key
	time.sleep(3)
	fw=open("ip.1w.bingfa"+str(key),"w")
	script_args="'thread="+str(key)+",verbose=0,ip_file="+ip+"'"
	cmd="nmap -e "+iface+" --script "+script_path+" --script-args="+script_args
	print cmd
	fw.write(cmd)
	cmd = shlex.split(cmd)
	p = subprocess.Popen(cmd, shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
	while p.poll() is None:
		line = p.stdout.readline()
		fw.write(line.strip()+"\n")
		print line.strip()
	fw.close()
	if p.returncode == 0:
		print('Subprogram success')
	else:
		print('Subprogram failed')
		break