import os
import sys
import shlex
import subprocess
import time
if sys.argv[4] == "1":
	file_path=sys.argv[2]
	print file_path
	fw1=open(sys.argv[2]+".runtimeresult",'a') #no change
	fw1.write(sys.argv[1]+"\n") #which method
	last_hop=set()
	for i in range(0,9):
		time.sleep(3)
		left=set()
		action=set()
		cmdstr="nmap -sn -n -e "+sys.argv[3]+" --script "+sys.argv[1]+" --min-hostgroup 50 -iL "+file_path
		cmd = shlex.split(cmdstr)
		p = subprocess.Popen(cmd, shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
		while p.poll() is None:
			line = p.stdout.readline()
			line = line.strip()
			# print line
			if line:
				if "action" in line:
					action.add(line.split()[1])
				elif "difference" in line:
					# print "turns:"+str(i)
					print line
					last_hop.add(line.split()[0])
				else:
					pass
		if p.returncode == 0:
			print('Subprogram success')
			print i
			left=action.difference(last_hop)
			print "now action:",(len(action))
			print "last_hop:",(len(last_hop))
			print "left:",(len(left))
			fw1.write(str(i)+"\n")
			fw1.write("action:"+str(len(action))+"\n")
			fw1.write("last_hop:"+str(len(last_hop))+"\n")
			fw1.write("left:"+str(len(left))+"\n")
			fw1.flush()
			if len(left)==0:
				print "all ip get last_hop"
				break
			if i==0:
				# sn=sys.argv[2].split('/')[-1]
				file_path=file_path+".leftip"
			fw=open(file_path,'w')
			for ip in left:
				fw.write(ip+"\n")
			fw.flush()
			fw.close()
		else:
			print('Subprogram failed')
			print i
			break
	fw1.close()
else:
	file_path=sys.argv[2]
	print file_path
	fw1=open(sys.argv[2]+".runtimeresult",'a')
	last_hop=set()
	fw1.write(sys.argv[1]+"\n")
	for i in range(0,10):
		left=set()
		action=set()
		cmdstr="nmap -sn -n -e "+sys.argv[3]+" --script "+sys.argv[1]+" --script-args='verbose=0,thread=100,ip_file="+file_path+"'"
		# cmd='nmap -sn -n -e eno2 --script system_lasthop.lua --script-args="verbose=0,thread=50,ip_file=ip.6w"'
		print cmdstr
		cmd = shlex.split(cmdstr)
		print cmd
		p = subprocess.Popen(cmd, shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
		while p.poll() is None:
			line = p.stdout.readline()
			line = line.strip()
			print line
			if line:
				if "action" in line:
					action.add(line.split()[1])
				elif "difference" in line:
					# print "turns:"+str(i)
					print line
					last_hop.add(line.split()[0])
				else:
					pass
		if p.returncode == 0:
			print('Subprogram success')
			print i
			print "action",len(action)
			left=action.difference(last_hop)
			print "now action:",(len(action))
			print "last_hop:",(len(last_hop))
			print "left:",(len(left))
			fw1.write(str(i)+"\n")
			
			fw1.write("action:"+str(len(action))+"\n")
			fw1.write("last_hop:"+str(len(last_hop))+"\n")
			fw1.write("left:"+str(len(left))+"\n")
			fw1.flush()
			if len(left)==0:
				print "all ip get last_hop"
				break
			if i==0:
				# sn=sys.argv[2].split('/')[-1]
				file_path=file_path+".leftip"
			fw=open(file_path,'w')
			for ip in left:
				fw.write(ip+"\n")
			fw.flush()
			fw.close()
		else:
			print('Subprogram failed')
			print i
			break
		time.sleep(3)
	fw1.close()