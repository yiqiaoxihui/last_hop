#!/usr/bin/env python
# -*- coding:utf-8 -*-
from __future__ import division
import os
import sys
import json
import time
import math
import matplotlib.pyplot as plt 

def statics_init_ttl(file):
	all_ip=0
	host_distribution={}
	hops={}
	print file
	fr=open(file,'r')
	print file
	while True:
		line = fr.readline()
		if not line:
			break
		elif "difference" in line:
			all_ip+=1
			guest_ttl=int(line.split()[1])
			left_ttl=int(line.split()[6])
			init_ttl=guest_ttl+left_ttl-1
			if host_distribution.has_key(init_ttl):
				host_distribution[init_ttl]+=1
			else:
				host_distribution[init_ttl]=1
			if (init_ttl>=67 and init_ttl<=71) or (init_ttl>=259 and init_ttl<=265) or(init_ttl>130 and init_ttl<140):
				print "guest_ttl,left_ttl:",guest_ttl,left_ttl,init_ttl
				
		#break
	fr.close()
		#endif
	#end for
		#break

	x2=[]
	y2=[]
	host_number=0
	for key in host_distribution:
		print key,host_distribution[key]
		host_number+=host_distribution[key]
		# if (key>=50 and key<=74) or (key>=243 and key<=265):
		# 	x2.append(key)
		# 	y2.append(1)
		# else:
	current=0.0
	for key in host_distribution:
		print key,host_distribution[key]
		x2.append(key)
		current+=host_distribution[key]/host_number
		y2.append(current)
		# y2.append(math.sqrt(host_distribution[key]))
	print "all ip:",all_ip
	draw(x2,y2)
def sc_warts2json(file_dir):   
	list_dir = os.listdir(file_dir)
	for file in list_dir:
		if file[-6:]==".warts":
			text_name=file+".json"
			if text_name in list_dir:	#已经
				print file+" has json"
				continue
			else:
				cmd="sc_warts2json "+file+" > "+text_name
				err=os.system(cmd)
				print text_name+":"+str(err)
				time.sleep(1)
def draw(x2,y2):
	#plt.plot(x1,y1,label='router')#,linewidth=3,color='r',marker='o', markerfacecolor='blue',markersize=12 
	plt.plot(x2,y2,label='host') 
	plt.xlabel('init ttl') 
	plt.ylabel('ip number/sqrt') 
	plt.title('init ttl table') 
	plt.legend() 
	plt.show() 

if __name__=="__main__":
	path=sys.argv[1]
	statics_init_ttl(path)
