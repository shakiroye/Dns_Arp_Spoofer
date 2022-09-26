#!/usr/bin/env python3
# coding:utf8
import argparse
from scapy.all import *


def sniffer(interface):
    scapy.all.sniff(iface=interface, store=False, prn=callback, filter="port 80")


def callback(packet):
    print(packet)


parser = argparse.ArgumentParser(description="Outil d'analyse réseau")
parser.add_argument("-iface", dest="iface",
                    help="Interface réseau à utiliser",
                    required=False)
args = parser.parse_args()

if args.iface:
    sniffer(args.iface)
