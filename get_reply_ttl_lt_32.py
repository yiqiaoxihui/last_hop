import sys
import os


fr=open(sys.argv[1],"r")
fw=open(sys.argv[2],'w')
left_ttl_dic={}
min_left_ttl_when_init_ttl64={}
min_left_ttl_when_init_ttl64['left_ttl']=64
init_ttl_dic={}
while True:
	line = fr.readline()
	if not line:
		break
	if "difference" in line:
		left_ttl=int(line.split()[6])
		if left_ttl_dic.has_key(left_ttl) == False:
			left_ttl_dic[left_ttl]=1
		else:
			left_ttl_dic[left_ttl]+=1
		if left_ttl<=64:
			ip=line.split()[0]
			guess_ttl=line.split()[1]
			refer_ttl=line.split()[2]
			send_packet=int(line.split()[5])
			init_ttl=left_ttl+int(guess_ttl)-1
			if init_ttl_dic.has_key(init_ttl) == False:
				init_ttl_dic[init_ttl]=1
			else:
				init_ttl_dic[init_ttl]+=1
			if init_ttl>50:
				if left_ttl<min_left_ttl_when_init_ttl64['left_ttl']:
					min_left_ttl_when_init_ttl64['left_ttl']=left_ttl
					min_left_ttl_when_init_ttl64['ip']=ip
					# fw.write(guess_ttl+" "+refer_ttl+" "+str(left_ttl)+" "+str(init_ttl)+" "+send_packet+" "+ip+"\n")
			# fw.write(guess_ttl+" "+refer_ttl+" "+send_packet+" "+str(left_ttl)+" "+str(left_ttl+int(guess_ttl))+" "+send_packet+" "+ip+"\n")
			if send_packet>=20:
				# print left_ttl
				fw.write(guess_ttl+" "+refer_ttl+" "+str(left_ttl)+" "+str(init_ttl)+" "+str(send_packet)+" "+ip+"\n")
fr.close()
fw.close()
for key in left_ttl_dic:
	if key<=40:
		print key,left_ttl_dic[key]
print "init_ttl"
for key in init_ttl_dic:
	if key<=64:
		print key,init_ttl_dic[key]
print min_left_ttl_when_init_ttl64['ip'],min_left_ttl_when_init_ttl64['left_ttl']