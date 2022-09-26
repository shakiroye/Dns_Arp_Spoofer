#!/usr/bin/env python3
# coding:utf8
import netfilterqueue
from scapy.layers.dns import *
from scapy.layers.inet import *


def callback(packet):
    scapy_packet = IP(packet.get_payload())
    if scapy_packet.haslayer(DNSRR):
        qname = scapy_packet[DNSQR].qname
        if b"bing.com" in qname:
            print("Visite de bing détectée")
    packet.accept()


try:
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(50, callback)
    queue.run()
except KeyboardInterrupt:
    queue.unbind()
    print("\n[-] Stopped")
except Exception as e:
    print(str(e))