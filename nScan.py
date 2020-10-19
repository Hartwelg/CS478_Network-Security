from scapy.all import *
import socket
import subprocess
import sys
import argparse

"""
This scans the top 100 tcp ports and prints the open ones. 
One of the nmap explorations involved a scan of the top 100 ports for a given host, so I made TCP and UDP versions of this function.
Only scans 100 ports, not sure why it takes forever
Works best on scanme.nmap.org
Tested on my VM, all ports closed (verified with an actual nmap scan)
"""
def tcpPortList(serverIP):
	#get top 100 tcp ports in string form
	tPorts = subprocess.getoutput("sort -r -k3 /usr/share/nmap/nmap-services | grep tcp | cut -f2 | cut -f1 -d'/' | head -n 100")
	#array for tcp ports
	tcpPorts = []
	#split port strings by newline character
	tcp = tPorts.split("\n")
	#add all ports to tcpPorts array
	for port in tcp:
		tcpPorts.append(port)
	#turn all array values into integers
	tcpPorts = [int(x) for x in tcpPorts]
	#list all the open tcp ports from top 100
	for port in tcpPorts:
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		otherResult = sock.connect_ex((serverIP, port))
		if otherResult == 0:
			print("TCP port {}".format(port))	
		sock.close()
	return 0
"""
This scans the top 100 UDP ports and prints the open ones.
One of the nmap explorations involved a scan of the top 100 udp ports for a given host, so this function is included.
Only scans 100 ports, not sure why it takes forever
Works best on scanme.nmap.org
Tested on my VM, all ports closed (verified with an actual nmap scan)
"""
def udpPortList(serverIP):
	#get top 100 udp ports in string form
	uPorts = subprocess.getoutput("sort -r -k3 /usr/share/nmap/nmap-services | grep udp | cut -f2 | cut -f1 -d'/' | head -n 100")
	#array for udp ports
	udpPorts = []
	#split port strings by newline character
	udp = uPorts.split("\n")
	#add all ports to udpPorts array
	for port in udp:
		udpPorts.append(port)
	#turn all array values into integers
	udpPorts = [int(x) for x in udpPorts]
	#list all open udp ports from top 100
	for port in udpPorts:
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		otherResult = sock.connect_ex((serverIP, port))
		if otherResult == 0:
			print("UDP port {}".format(port))
		sock.close()
	return 0
"""
This performs a TCP connect() scan on a given host.
The 'Simple nmap scans' exploration called for a tcp connect() scan of a range of ports, so this function is included here.
works best with scanme.nmap.org
"""
def tcpConnect(serverIP):
	src_port = RandShort()
	dst_port = 80

	tcp_connect_scan_resp = sr1(IP(dst=serverIP)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=10)
	if(str(type(tcp_connect_scan_resp))=="<type 'NoneType'>"):
		print ("Closed")
	elif(tcp_connect_scan_resp.haslayer(TCP)):
		if(tcp_connect_scan_resp.getlayer(TCP).flags == 0x12):
			send_rst = sr(IP(dst=serverIP)/TCP(sport=src_port,dport=dst_port,flags="AR"),timeout=10)
			print ("Open")
		elif (tcp_connect_scan_resp.getlayer(TCP).flags == 0x14):
			print ("Closed")
"""
This scans a subnet within a given IP address.
It takes an IP address and appends '/24' to it, then runs a port scan on that subnet
I made this function to replicate the 'Network nmap scans' exploration
This works on my VM subnet (192.168.172.128/24)
"""
def subnetScan(serverIP):
	#append subnet mask to serverIP
	serverIP = serverIP + "/24"
	print("scanning subnet: ", serverIP)
	#ARP packet
	arp = ARP(pdst=serverIP)
	#Broadcasting MAC address
	ether = Ether(dst="ff:ff:ff:ff:ff:ff")
	#stack
	packet = ether/arp
	result = srp(packet, timeout=1, verbose=0)[0]
	#array for list of ip address/MAC address pairs
	ips = []
	
	#appends IP addresses and their MAC addresses to the ips list
	for sent, received in result:
		ips.append({'ip': received.psrc, 'mac': received.hwsrc})

	#lists unique IP addresses and their MAC addresses
	print("Available devices on network:")
	print("IP" + " "*22+"MAC")
	for address in ips:
		print("{:16}	{}".format(address['ip'], address['mac']))

"""
This function performs a TCP connect() scan of three port ranges, as described in the 'Simple nmap scans' exploration
I re-used most of the code in here from the tcpConnect() function above.
"""
def tcpRangeScan(serverIP):
	#make three port range arrays
	range1 = []
	range2 = []
	range3 = []
	#random source port
	src_port = RandShort()
	#populate port range arrays with ranges specified in nmap exploration
	for x in range(20, 101):
		range1.append(x)
	for x in range(130, 151):
		range2.append(x)
	for x in range(400, 501):
		range3.append(x)
	#scan every port in range1
	for port in range1:
		tcp_connect_scan_resp = sr1(IP(dst=serverIP)/TCP(sport=src_port,dport=port,flags="S"),timeout=10)
		if(str(type(tcp_connect_scan_resp))=="<type 'NoneType'>"):
			print ("Closed")
		elif(tcp_connect_scan_resp.haslayer(TCP)):
			if(tcp_connect_scan_resp.getlayer(TCP).flags == 0x12):
				send_rst = sr(IP(dst=serverIP)/TCP(sport=src_port,dport=port,flags="AR"),timeout=10)
				print ("Open")
			elif (tcp_connect_scan_resp.getlayer(TCP).flags == 0x14):
				print ("Closed")
	#scan every port in range2
	for port in range2:
		tcp_connect_scan_resp = sr1(IP(dst=serverIP)/TCP(sport=src_port,dport=port,flags="S"),timeout=10)
		if(str(type(tcp_connect_scan_resp))=="<type 'NoneType'>"):
			print ("Closed")
		elif(tcp_connect_scan_resp.haslayer(TCP)):
			if(tcp_connect_scan_resp.getlayer(TCP).flags == 0x12):
				send_rst = sr(IP(dst=serverIP)/TCP(sport=src_port,dport=port,flags="AR"),timeout=10)
				print ("Open")
			elif (tcp_connect_scan_resp.getlayer(TCP).flags == 0x14):
				print ("Closed")
	#scan every port in range3
	for port in range3:
		tcp_connect_scan_resp = sr1(IP(dst=serverIP)/TCP(sport=src_port,dport=port,flags="S"),timeout=10)
		if(str(type(tcp_connect_scan_resp))=="<type 'NoneType'>"):
			print ("Closed")
		elif(tcp_connect_scan_resp.haslayer(TCP)):
			if(tcp_connect_scan_resp.getlayer(TCP).flags == 0x12):
				send_rst = sr(IP(dst=serverIP)/TCP(sport=src_port,dport=port,flags="AR"),timeout=10)
				print ("Open")
			elif (tcp_connect_scan_resp.getlayer(TCP).flags == 0x14):
				print ("Closed")

def main():
	parser = argparse.ArgumentParser()
	#add optional arguments
	#################
	#tcp top 100 scan
	parser.add_argument("-tcp", help="list top 100 tcp ports", action="store_true")
	#udp top 100 scan
	parser.add_argument("-udp", help="list top 100 udp ports", action="store_true")
	#tcp connect scan
	parser.add_argument("-tcpConnect", help="tcp connect scan", action="store_true")
	#scan a subnet for hosts
	parser.add_argument("-subnet", help="find ip addresses on network", action="store_true")
	#scan three tcp port ranges
	parser.add_argument("-range", help="scan tcp port ranges", action="store_true")

	args = parser.parse_args()
	#get IP address of user-entered target
	target = input("Please enter host to scan:")
	serverIP = socket.gethostbyname(target)
	#some options take awhile to operate
	print("This might take awhile")

	#print IP address that we are scanning
	print("scanning IP: ", serverIP)

	#check for optional arguments
	if args.tcp:
		tcpPortList(serverIP)
	if args.udp:
		udpPortList(serverIP)
	if args.tcpConnect:
		tcpConnect(serverIP)
	if args.subnet:
		subnetScan(serverIP)
	if args.range:
		tcpRangeScan(serverIP)

if __name__ == "__main__":
	main()