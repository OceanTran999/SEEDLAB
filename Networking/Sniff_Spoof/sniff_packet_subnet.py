#!/usr/bin/env python3

from scapy.all import *

def print_pkt(pack):
        pack.show()

pkt = sniff(iface=['br-00835518abdf','ens32'],filter='src or dst net 128.230.0.0/16', prn=print_pkt)