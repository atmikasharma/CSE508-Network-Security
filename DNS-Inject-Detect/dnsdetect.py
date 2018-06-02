


#ATMIKA SHARMA
#SBU ID: 111464371

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import os
import os.path
from scapy.all import *
import sys, getopt
import socket
import fcntl
import struct
import time
#from collections import deq

global intrfc
global file
global bpf
global mylist


intrfc = ''
file = ''
#data
mylist = {}
bpf = ''

def dnsfunc(pkt):
	if IP in pkt:

		destination = pkt[IP].dst

		source = pkt[IP].src

		if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:

			mylist[pkt[DNS].id] = '0'

		if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 1:

			if pkt[DNS].id in mylist:

				if mylist[pkt[DNS].id] == '0':
				
					mylist[pkt[DNS].id] = str(pkt[DNSRR].rdata)
				
				elif mylist[pkt[DNS].id] == str(pkt[DNSRR].rdata):
					print mylist[pkt[DNS].id]
					print '\n'
					print str(pkt[DNSRR].rdata)
					print 'sent again'

				else:

					
					print '\n' + time.strftime("%Y-%m-%d %H:%M") + ' poisoning attempt'
					
					print 'transaction ID: ' + str(pkt[DNS].id) + ' request: ' + pkt.getlayer(DNS).qd.qname
					
					print 'Answer 1: ' + mylist[pkt[DNS].id]
					
					print 'Answer 2: ' + str(pkt[DNSRR].rdata)
					


if __name__ == "__main__":

	try:

		# http://www.pythonforbeginners.com/system/python-sys-argv

		#looping through options
		options, arguments = getopt.getopt(sys.argv[1:], "hi:r:",["interface=", "file="])

	except getopt.GetoptError:
		
		print 'invalid options getopt error'
		
		sys.exit()

	for option, argument in options:

		#interface by user
		if option in ("-i", "--interface"):
			intrfc=argument

		#pcap file in this case
		elif option in ("-r", "--file"):
			file=argument

	
	#last argument get bpf
	if(len(sys.argv)==4):
		bpf = sys.argv[3]

	#last argument get bpf
	elif(len(sys.argv)==6):
		bpf = sys.argv[5]

	if intrfc:
		flag = 1
	else:
		flag = 0

	#sniff from file
	if flag==0:
		sniff(offline=file, filter="udp and port 53", prn=dnsfunc, store=0)
	#sniff from interface and detect
	else:
		sniff(iface=intrfc, filter="udp and port 53", prn=dnsfunc, store=0)

	#https://thepacketgeek.com/scapy-sniffing-with-custom-actions-part-1/

	print "\nFINISH"


