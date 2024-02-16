#!/usr/bin/env python3

from scapy.all import *

def print_pkt(package):
        package.show()

pkt = sniff(iface=['br-00835518abdf','ens32'],filter='icmp',prn=print_pkt)