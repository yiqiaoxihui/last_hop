#!/usr/bin/env python
# -*- coding:utf-8 -*-
from __future__ import division
import os
import sys
import json
import time
import math
import matplotlib.pyplot as plt 
def statics_init_ttl(file_dir):
	all_ip=0
	host_distribution={}
	host=set()
	router=set()
	router_distribution={}
	hops={}
	host_ip=0
	list_dir = os.listdir(file_dir)
	for file in list_dir:
		#print file
		if file[-5:]==".json":
			fr=open(file,'r')
			print file
			while True:
				line = fr.readline().strip()
				if not line:
					break
				else:
					all_ip+=1
					jo=json.loads(line)
					dst=jo['dst']
					host.add(dst)
					if jo.has_key('hops'):
						hops=jo['hops']
						len_hops=len(hops)
						if len_hops<=0:
							continue
						#print "dst:",dst
						#print "hops:",len_hops,hops[len_hops-1]['addr']
						# for i in range(0,len_hops-1):
						# 	router.add(hops[i]['addr'])
						# 	init_ttl=int(hops[i]['reply_ttl'])+hops[i]['probe_ttl']-1
						# 	#print i,init_ttl
						# 	if router_distribution.has_key(init_ttl):
						# 		router_distribution[init_ttl]+=1
						# 	else:
						# 		router_distribution[init_ttl]=1
						if dst==hops[len_hops-1]['addr']:
							host_ip+=1
							init_ttl=int(hops[len_hops-1]['reply_ttl'])+hops[len_hops-1]['probe_ttl']-1
							#print "target:",dst,init_ttl
							if host_distribution.has_key(init_ttl):
								host_distribution[init_ttl]+=1
							else:
								host_distribution[init_ttl]=1
				#break
			fr.close()
		#endif
	#end for
		#break
	print "router:"
	x1=[]
	y1=[]
	x2=[]
	y2=[]
	for key in router_distribution:
		print key,router_distribution[key]
		x1.append(key)
		y1.append(math.sqrt(router_distribution[key]))
	# print "host:"
	# for key in host_distribution:
	# 	print key,host_distribution[key]
	# 	# if (key>=50 and key<=74) or (key>=243 and key<=265):
	# 	# 	x2.append(key)
	# 	# 	y2.append(1)
	# 	# else:
	# 	x2.append(key)
	# 	y2.append(math.sqrt(host_distribution[key]))
	host_number=0
	# for key in host_distribution:
	# 	print key,host_distribution[key]
	# 	host_number+=host_distribution[key]
	# 	if (key>=50 and key<=74) or (key>=243 and key<=265):
	# 		x2.append(key)
	# 		y2.append(1)
	# 	else:
	# 		pass
	current=0.0
	for key in host_distribution:
		print key,host_distribution[key]
		x2.append(key)
		current+=host_distribution[key]/host_number
		y2.append(current)
	print "all ip,host ip:",all_ip,host_ip
	print len(host)
	print len(router)
	draw(x1,y1,x2,y2)
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
def draw(x1,y1,x2,y2):
	#plt.plot(x1,y1,label='router')#,linewidth=3,color='r',marker='o', markerfacecolor='blue',markersize=12 
	plt.plot(x2,y2,label='host') 
	plt.xlabel('init ttl') 
	plt.ylabel('ip number/sqrt') 
	plt.title('init ttl table') 
	plt.legend() 
	plt.show() 

if __name__=="__main__":
	path=sys.argv[1]
	sc_warts2json(path)
	statics_init_ttl(path)
