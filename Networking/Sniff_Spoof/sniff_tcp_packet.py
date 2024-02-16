#!/usr/bin/env python3

from scapy.all import *

def print_pkt(pack):
        pack.show()

# Capture TCP packet with specific IP 10.9.0.6 and must be in port 23
pkt = sniff(iface=['br-00835518abdf','ens32'], filter='tcp and port 23 and src host 10.9.0.6', prn=print_pkt)