from scapy.all import *

ip=IP(src='10.0.0.1',dst='20.0.0.2')
SYN=TCP(sport=1500,dport=443,flags='S',seq=1000)
SYNACK=sr1(ip/SYN)

# ACK              
my_ack = SYNACK.seq + 1
ACK=TCP(sport=1500, dport=443, flags='A', seq=1001, ack=my_ack)
send(ip/ACK)

my_payload="space for rent!"
TCP_PUSH=TCP(sport=1500, dport=80, flags="PA", seq=102, ack=my_ack)
send(ip/TCP_PUSH/my_payload)