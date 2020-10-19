for packet in packets:
		if packet.haslayer(TCP) and packet.sport == 5000 and packet.getlayer(TCP).flags == 0x019 and packet.len >= 1500:
			print(packet.summary())
			length = packet.len
			print(f"length: {length}")
			load = packet.getlayer(Raw).load
			print("load: ")
			print(load)
			#packet.show()
			#wrpcap("filtered.pcap", packet, append=True)
		else:
			continue