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
import json
from IPy import IP
def get_link_node_from_dir():
	all_ip=0
	last_hop_count=1
	all_packet=0
	# for file in list_dir:
	all_time=0
	lh_set=set()
	fw=open(sys.argv[2],'w')
	if True:
		fr=open(sys.argv[1],'r')
		print file
		while True:
			line = fr.readline().strip()
			if not line:
				break
			else:
				all_ip+=1
				jo=json.loads(line)
				if jo.has_key('start_time'):
					start_time=int(jo['start_time'])
				if jo.has_key('stop_time'):
					stop_time=int(jo['stop_time'])
					all_time+=(stop_time-start_time)
				if jo.has_key('dst')==False:
					continue
				dst=jo['dst']
				if jo.has_key('hops'):
					hops=jo['hops']
					len_hops=len(hops)
					if len_hops<=1:
						continue
					if (int)(hops[len_hops-2]['probe_ttl']) +1  == int(hops[len_hops-1]['probe_ttl']) and jo['dst'] == hops[len_hops-1]['addr']:
						# print jo['dst'],hops[len_hops-2]['addr']
						last_hop_count+=1
						lh_set.add(hops[len_hops-2]['addr'])
						if jo.has_key('probe_count'):
							all_packet+=int(jo['probe_count'])
						fw.write(jo['dst']+" "+hops[len_hops-2]['addr']+"\n")
		fr.close()

	fw.close()
	print "last_hop_count:",last_hop_count
	print "all_packet:",all_packet
	print "avg:",all_packet*1.0/last_hop_count
	print "time",all_time
		# print i,item
	rlh=0
	for i in lh_set:
		rlh+=1
	print "unique lasthop",rlh
if __name__ == '__main__':
	get_link_node_from_dir()
