import os
import sys
import json
import time
import math
import matplotlib.pyplot as plt 

def draw(draw_list):
	#plt.plot(x1,y1,label='router')#,linewidth=3,color='r',marker='o', markerfacecolor='blue',markersize=12
	for line in draw_list:
		plt.plot(draw_list[line]['x'],draw_list[line]['y'],label=line) 
	plt.xlabel('') 
	plt.ylabel('')
	plt.title('') 
	plt.legend() 
	plt.show() 
def hop_gap_count():
	file_path=sys.argv[1]
	print file_path
	fr=open(file_path,'r')
	difference={}
	sum=0
	while True:
		line = fr.readline()
		if not line:
			break
		elif "difference" in line:
			sum+=1
			hop=int(line.split()[1])
			d=int(line.split()[4])
			# if d<0:
			# 	d=d*(-1)
			if difference.has_key(hop):
				pass
			else:
				difference[hop]={}
			if difference[hop].has_key(d):
				difference[hop][d]+=1
			else:
				difference[hop][d]=1
			if int(line.split()[6])<20:
				#print line
				pass
	draw_list={}
	for key in difference:
		print "hop:",key
		if key>20 or key<10:
			continue
		draw_list[key]={}
		draw_list[key]['x']=[]
		draw_list[key]['y']=[]
		ob=sorted(difference[key].items(),key=lambda item:item[0])
		for item in ob:
			print "gap:",item[0],"count:",item[1]
			if item[0]>20 or item[0]<-10:
				continue
			draw_list[key]['x'].append(item[0])
			draw_list[key]['y'].append(math.sqrt(item[1]))
		print "---------------------------------"
	print sum
	with open('./a.txt','w') as f:
		f.write( json.dumps( draw_list,ensure_ascii=False,indent=2 ) )
	fr.close()
	draw(draw_list)

def left_ttl_hop_count():
	file_path=sys.argv[1]
	print file_path
	fr=open(file_path,'r')
	difference={}
	sum=0
	while True:
		line = fr.readline()
		if not line:
			break
		elif "difference" in line:
			sum+=1
			hop=int(line.split()[1])
			left_ttl=int(line.split()[6])
			# if d<0:
			# 	d=d*(-1)
			if difference.has_key(left_ttl):
				pass
			else:
				difference[left_ttl]={}
			if difference[left_ttl].has_key(hop):
				difference[left_ttl][hop]+=1
			else:
				difference[left_ttl][hop]=1
			if int(line.split()[6])<20:
				#print line
				pass
	draw_list={}
	for key in difference:
		print "left_ttl:",key
		if key>64 or key<32:
			continue
			pass
		draw_list[key]={}
		draw_list[key]['x']=[]
		draw_list[key]['y']=[]
		ob=sorted(difference[key].items(),key=lambda item:item[0])
		for item in ob:
			print "real hop:",item[0],"count:",item[1]
			if item[0]>20 or item[0]<-10:
				#continue
				pass
			draw_list[key]['x'].append(item[0])
			draw_list[key]['y'].append(math.sqrt(item[1]))
		print "---------------------------------"
	print sum
	fr.close()
	draw(draw_list)
def write_list_to_file():
	with open(sys.argv[2],'w') as f:
		f.write(json.dumps( draw_list,ensure_ascii=False,indent=2 ))
	f.close()

def read_json_from_file():
	with open(sys.argv[1],'r') as load_f:
		draw_list = json.load(load_f)
	# for l in draw_list:
	# 	print l
	draw(draw_list)
read_json_from_file()
# left_ttl_hop_count()
# hop_gap_count()

