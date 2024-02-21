# Answer in my observation:

## Task 1:

### Task 1B:
#### In scenario 1:
- Ping host B to host A so that the ARP table will save IP and MAC address of host B.
- When sending ARP Reply to host A, it will replace the MAC address of host B into host M's.

#### In scenario 2:
- The packet still sent to the target A but it was not saved in ARP cache.

### Task 1C:
#### Scenario 1: 
- When using host B ping to host A, the ARP table in host A will save IP and MAC Address of host B, then when host M sends to host B a gratuitous ARP packet (request/reply).
- The ARP table in host A will automatically replace the MAC Address of host B  to MAC address of host M, and the IP Addres still use host B.

#### Scenario 2: 
- Host M sends gratuitous ARP packet (request/reply) to host B successfully but the ARP table in host A does not update.

## Task 2:
### After sending poison ARP Reply to host A and B from host M and then ping from host A to B:
- IP Forwarding in host M turn off:
    ** Host A will not receive ICMP Reply from host M.
    ** Host A will send ARP Request packet to host M.
    ** After not receiving ARP Reply from host M, host A will send ARP request to Broadcast Address.Then, host B will send ARP Reply to host A.

- IP Forwarding in host M turn on:
** Host M will receive ICMP Request from host A and move it to host B.
** Host B will send ICMP Rely to host M. After that, host M will send ICMP Redirect to host B with its IP address.
** Host M now can impersonate host B by using host B's IP address, and send ICMP Reply back to host A.
    
### After launching MITM-attack in Telnet server.
- When IP forwarding turns off in all Telnet connection, the ARP table will reset the MAC address into correct hosts.
- When IP forwarding turns on in all Telnet connection, the ARP table saves MAC address of host M only. However, host M can not spoof packets as it impersonates each host to send the copy packets to the another.
- When turning on IP forwarding after host A connects to host B's Telnet server, and turning off
IP forwarding before host A types input in B's Telnet Server. This time, host M will be the middle node between A and B. It receives message from host A and modify the keystroke character into 'Z' and sends to B. When receiving packet from Server B, it does not change anything and send to A.