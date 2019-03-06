#!/usr/bin/env python
# -*- coding:utf-8 -*-
import os
import os.path
import sys
import subprocess
import time
import gzip
import datetime
import re
import struct
import socket
#file type:
#		.warts.gz
#		.warts
#		.warts.txt
#		.useful.hop
def extract_traceroute_get_last_hop(file_name):
	print file_name+" Begin ..."
	dic={}
	reg_trace_ip=r'(?:traceroute from )((?:(?:1[0-9][0-9]\.)|(?:2[0-4][0-9]\.)|(?:25[0-5]\.)|(?:0{0,3}[1-9][0-9]\.)|(?:0{0,3}[0-9]\.)){3}(?:(?:1[0-9][0-9])|(?:2[0-4][0-9])|(?:25[0-5])|(?:0{0,3}[1-9][0-9])|(?:0{0,3}[0-9]))) {0,2}to {0,2}((?:(?:1[0-9][0-9]\.)|(?:2[0-4][0-9]\.)|(?:25[0-5]\.)|(?:0{0,3}[1-9][0-9]\.)|(?:0{0,3}[0-9]\.)){3}(?:(?:1[0-9][0-9])|(?:2[0-4][0-9])|(?:25[0-5])|(?:0{0,3}[1-9][0-9])|(?:0{0,3}[0-9])))'
	#reg=r'inetnum.+(*).+-'
	reg_trace_last_hop=r'([1-9]+) {0,2}((?:(?:1[0-9][0-9]\.)|(?:2[0-4][0-9]\.)|(?:25[0-5]\.)|(?:0{0,3}[1-9][0-9]\.)|(?:0{0,3}[0-9]\.)){3}(?:(?:1[0-9][0-9])|(?:2[0-4][0-9])|(?:25[0-5])|(?:0{0,3}[1-9][0-9])|(?:0{0,3}[0-9]))|(\*))'
	fr=open(file_name,'r')
	#hop_file_path=file_name+".star.hop"
	useful_hop_file_path=file_name+".useful.hop"
	#diff_hop_file_path=file_name+".unreach.hop"
	#fw=open(hop_file_path,'w')
	fuw=open(useful_hop_file_path,'w')
	#fud=open(diff_hop_file_path,'w')
	fr.seek(0,0)
	sums=0
	star_hop=0;
	diff_last_hop=0
	same_last_hop=0
	all_ip=0
	content=""
	pre_traceroute_ip=""
	line=fr.readline()
	if line[0:10]=="traceroute":
		ip_range=re.findall(reg_trace_ip,line)
		if ip_range!=[]:
			pre_traceroute_ip=ip_range[0][1]
			local_ip=ip_range[0][0]
	while True:
		prev_line=line
		line=fr.readline().strip()
		if line[0:10]=="traceroute":
			sums=sums+1
			last_hop_list=re.findall(reg_trace_last_hop,prev_line)
			if last_hop_list!=[]:
				last_hop_num=last_hop_list[0][0]
				last_hop_ip=last_hop_list[0][1]
				if last_hop_ip!="*":
					if pre_traceroute_ip==last_hop_ip:
						fuw.write(pre_traceroute_ip+" "+last_hop_ip+" "+last_hop_num+'\n')
						#print pre_traceroute_ip+" "+last_hop_ip+" "+last_hop_num
						same_last_hop=same_last_hop+1
					else:
						diff_last_hop=diff_last_hop+1
						#fud.write(pre_traceroute_ip+" "+last_hop_ip+" "+last_hop_num+'\n')
						#fud.write(pre_traceroute_ip+'\n')
				else:
					#fw.write(pre_traceroute_ip+" "+last_hop_ip+" "+last_hop_num+'\n')
					#fud.write(pre_traceroute_ip+'\n')
					#print prev_line
					star_hop=star_hop+1
			#
			ip_range=re.findall(reg_trace_ip,line)
			if ip_range!=[]:
				pre_traceroute_ip=ip_range[0][1]
				local_ip=ip_range[0][0]
			else:
				print "error trace:"+line
		elif line=="":
			last_hop_list=re.findall(reg_trace_last_hop,prev_line)
			if last_hop_list!=[]:
				last_hop_num=last_hop_list[0][0]
				last_hop_ip=last_hop_list[0][1]
				if last_hop_ip!="*":
					if pre_traceroute_ip==last_hop_ip:
						fuw.write(pre_traceroute_ip+" "+last_hop_ip+" "+last_hop_num+'\n')
						#print pre_traceroute_ip+" "+last_hop_ip+" "+last_hop_num
						same_last_hop=same_last_hop+1
					else:
						diff_last_hop=diff_last_hop+1
						#fud.write(pre_traceroute_ip+" "+last_hop_ip+" "+last_hop_num+'\n')
						#fud.write(pre_traceroute_ip+'\n')
				else:
					#fw.write(pre_traceroute_ip+" "+last_hop_ip+" "+last_hop_num+'\n')
					#fud.write(pre_traceroute_ip+'\n')
					star_hop=star_hop+1
			break
		else:
			pass
	print file_name+" sums:",
	print sums
	print file_name+" star_hop:",
	print star_hop
	print file_name+" diff_last_hop:",
	print diff_last_hop
	print file_name+" same_last_hop:",
	print same_last_hop
	print file_name+" End ...\n\n"
	#fr.close()
	#fw.close()
	fuw.close()
  
def ungz(file_dir):   
	list_dir = os.listdir(file_dir)
	for file in list_dir:
		if file[-8:]=="warts.gz":
			if file[:-3] in list_dir:	#已经解压
				print file+" has ungz"
				continue
			else:
				cmd="gzip -d "+file;
				err=os.system(cmd)
				print file+":"+str(err)

def sc_warts2text(file_dir):   
	list_dir = os.listdir(file_dir)
	for file in list_dir:
		if file[-5:]=="warts":
			text_name=file+".txt"
			if text_name in list_dir:	#已经
				print file+" has txt"
				continue
			else:
				cmd="sc_warts2text "+file+" > "+text_name
				err=os.system(cmd)
				print text_name+" "+str(err)
def read_and_extract(file_dir):
	list_dir = os.listdir(file_dir)
	for file in list_dir:
		if file[-9:]=="warts.txt":
			if file+".useful.hop" not in list_dir:
				extract_traceroute_get_last_hop(file)
			else:
				print file+" has useful hop"
def combine(file_dir):
	dic={}
	list_dir = os.listdir(file_dir)
	for file in list_dir:
		if file[-10:]=="useful.hop":
			fp=open(file,'r')
			while True:
				line=fp.readline()
				if line:
					l=line.strip().split()
					if len(l)==3:
						if dic.has_key(l[0]):
							print "repeat ip:"+line
						dic[l[0]]=l[2]
					else:
						print "error data:"+line
				else:
					break
			fp.close()
	file_path=raw_input("input combine write file name:\n")
	fw=open(file_path,'w')
	for key in dic:
		fw.write(key+"\n")
	fw.close()
	print "all_ip:"+str(len(dic))

def get_file_by_ip_main(file_dir):
	flag=0
	list_dir = os.listdir(file_dir)
	tip=raw_input("input query ip:")
	for file in list_dir:
		if flag==1:
			break
		if file[-10:]=="useful.hop":
				fp=open(file,'r')
				while True:
					line = fp.readline()
					if not line:
						break
					else:
						ip=line.strip.split()[0]
						if tip==ip:
							print "find target:"+file
							flag=1
							break
				fp.close()
		else:
			print file+" has useful hop"
if __name__=="__main__":
	path=sys.argv[1]
	ungz(path)
	sc_warts2text(path)
	read_and_extract(path)
	combine(path)