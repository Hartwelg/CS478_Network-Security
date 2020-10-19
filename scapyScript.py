from scapy.all import * #pull in all of scapy -- you could do it other ways, but this makes it isomorphic to using scapy command line
import socket
import sys
import time
import base64
from scapy.utils import PcapWriter
from scapy.layers.http import HTTPRequest

def main():
	if len(sys.argv) > 1: #if we have a command line argument
		try:
			packets = rdpcap(sys.argv[1])
			#rdpcap is how we read a previously captured pcap file
		except:
			print("File read failure: %s not found" % sys.argv[1])
			sys.exit(1)
	else:
		print("Need a pcap file to read!")
		sys.exit(1)

	binFile = open("download.bin", "wb")
	string = "Content-type: text/html"
	for packet in packets:
		if packet.haslayer(TCP) and packet.sport == 5000 and packet.getlayer(TCP).flags == 0x019 and packet.len >= 1500:
			print(packet.summary())
			#packet.show()
			#a = PcapWriter("filtered.pcap", append=True, sync=True)
			#a.write(packet)
			load = packet.getlayer(Raw).load
			part = load[142:]
			a = base64.b64decode(part)
			binFile.write(a)
		else:
			continue
	binFile.close()

if __name__ == '__main__':
	main()
	