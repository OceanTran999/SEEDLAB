# Answer in my observation

## Task 1

### Task 1.1

- To make the SYN flooding attack successful in Victim's Telnet server. I have to reset the TCP information for IPv4/IPv6 destination in Victim server, so that when User1 or User2 establish a Telnet connection in Victim Server, they will fail and keep waiting for connection. To reset the TCP information for IPv4/IPv6 destination in Victim server, using this command:
```console
ip tcp_metrics show     # (Check TCP cache)
ip tcp_metrics flush
```

- Here's the number of instances program that run paralelly to attack successfully in different size queue in victim server:
** Size of queue in victim server is 80:     2 instances
** Size of queue in victim server is 128:    5 instances

### Task 1.2
- The difference between when running SYN flooding attack using file `synflood.c` and using Python program to attack, I don't need to run multiple instances attack programs in parallel when using C program. Observing the attack through Wireshark, I see that the victim server only sends [SYN, ACK] packets at first time, after that it replys those packets slower than before as the attack program may run so fast that the victim server can't reply to each packets. Moreover, Telnet in victim server is not be able to accept to User1 or User2 although it has saved IP address of User1 or User2 machine from TCP connection before.
- In my view, the reason why the C Program runs faster is because:
+ The checksum of TCP calculates with Pseudo TCP Header which is only 12 bytes and contains fields:
** IP Source/Destination address.
** Reserved bit: 8 bits with 0 values.
** Protocol: protocol field of IP Header.
** TCP Length: computed length of TCP segment, including TCP header and data length.
+ The Python Program uses Internet Protocol (IP) which is in layer 3 and Transmission Control Protocol (TCP) which is in layer 4. That means the size of packets in Python program, which were sent to the victim machine may be bigger than in C Program.

### Task 1.3
When turning on SYN Cookie countermeasure, the User1 or User2 can connect to Victim's Telnet Server immediatly after request to Server, as the Victim Server doesn't send the TCP Retransmit [SYN, ACK] packets. Instead, it only sends an [SYN, ACK] packet to the Attack Machine.