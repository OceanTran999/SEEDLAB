# Answer in my observation
## Task 2.1
- We need root privilege to run a sniffer program to access the network interface.
- The program will stop in line that has `pcap_open_live()` function when running sniffer prgram without root privilege.

## Task 2.2
- You have to set the value of Identifer (LE) and Sequence number (LE) fields, otherwise, the remote machine will not send the ICMP echo_reply to our machine.