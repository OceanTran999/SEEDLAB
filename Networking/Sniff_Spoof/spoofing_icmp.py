#!/usr/bin python3

from scapy.all import *

a=IP(src='10.9.0.6', dst='10.9.0.5')
ls(a)
print("\n\n\n\n\n")

pkt = a/ICMP()
ls(pkt)