from scapy.all import *
import sys

def routing(ip_src, ip_dst, ttl):
    a = IP(src=ip_src, dst=ip_dst)
    a.ttl=ttl

    b = ICMP()
    pkt = a/b
    pkt.show()
    send(pkt, verbose=0)

ttl = int(sys.argv[1])
src = '10.9.0.5'
dst = sys.argv[2]

routing(src, dst, ttl)