// Task 2.3: Write a program whenever it sees an ICMP echo request, regardless of what the target IP
// address is, your program should immediately send out an echo reply using the packet spoofing
// technique.

// References:
// https://stackoverflow.com/questions/5328070/how-to-convert-string-to-ip-address-and-vice-versa
// https://www.binarytides.com/raw-sockets-c-code-linux/


#include <pcap.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <net/if.h>
#include <arpa/inet.h>

#include "packet_header.h"

void spoof_packet(struct ip_head* ip)
{
    int enable = 1;
    struct sockaddr_in sin;

    // Create a RAW socket that can interact with IP header
    int socketfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(socketfd < 0)
    {
        perror("Error! Can't open raw socket: ");
        return;
    }

    // Set socket option
    if(setsockopt(socketfd, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable)) < 0)
    {
        perror("Error! Can't set socket option: ");
        return;
    }

    sin.sin_family = AF_INET;
    sin.sin_addr = ip->ip_dst;

    // Make sure in network byte order
    if(sendto(socketfd, ip, ntohs(ip->ip_totlen), 0, (struct sockaddr*)&sin, sizeof(sin)) < 0)
    {
        perror("Error! Can't send spoofing packet: ");
        return;
    }
}

unsigned short int cal_chksum(unsigned short int* buffer, int length)
{
    int sum = 0;
    unsigned short int*w = buffer;
    unsigned short int temp = 0;
    int nleft = length;

    // Add buffer to a 32-bit accumulator, then add 16-bit higher to 16-bit lower.
    // Finlly add carry bit if it has.
    while(nleft > 1)
    {
        sum += *w;
        w++;
        nleft -= 2;
    }

    // If the last bit is 1 instead of 0
    if(nleft == 1)
    {
        *(unsigned char*)&temp = *(unsigned char*)w;
        sum += temp;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);     // Add carry bits

    return (unsigned short int)(~sum);
}

void capture_packets(unsigned char* args, const struct pcap_pkthdr* header, const unsigned char* packet)
{
    char ipaddr[INET_ADDRSTRLEN];
    struct ip_head* ip_sniff = (struct ip_head*)(packet + sizeof(struct ether_head));
    struct icmp_head* icmp_sniff = (struct icmp_head*)(packet + sizeof(struct ether_head) 
                                                                + sizeof(struct ip_head));
    
    /* Spoofing ICMP echo_reply packet */
    printf("\nSending spoofed packet.....\n\n");
    char buffer[1500];
    memset(buffer, 0, 1500);

    struct ip_head* ip = (struct ip_head*)buffer;
    struct icmp_head* icmp = (struct icmp_head*)(buffer + sizeof(struct ip_head));
    
    // Fill in ICMP Header
    icmp->icmp_type = 0;                    // 0: echo_reply
    icmp->icmp_chksum = 0;
    icmp->icmp_id = icmp_sniff->icmp_id;
    icmp->icmp_seq = icmp_sniff->icmp_seq;
    
    // Fill in IP Header
    ip->ip_ver = 4;
    ip->ip_headlen = 5;
    ip->ip_ttl = 20;
    ip->ip_src.s_addr = ip_sniff->ip_dst.s_addr;
    ip->ip_dst.s_addr = ip_sniff->ip_src.s_addr;
    ip->ip_proto = IPPROTO_ICMP;
    ip->ip_totlen = htons(sizeof(struct ip_head) + sizeof(struct icmp_head));   // Make sure in network byte order
    
    // Calculate ICMP checksum
    icmp->icmp_chksum = cal_chksum((unsigned short int*)icmp, sizeof(struct icmp_head));

    // Send spoofing packet
    spoof_packet(ip);
    
    printf("===== Captured packet info =====\n");
    (ip_sniff->ip_proto == IPPROTO_ICMP) ? printf("Protocol: ICMP\n"):
                                            printf("Protocol: Not ICMP\n");

    printf("IP Source: %s\n", inet_ntop(AF_INET, &(ip_sniff->ip_src.s_addr), ipaddr, INET_ADDRSTRLEN));
    printf("IP Destination: %s\n", inet_ntop(AF_INET, &(ip_sniff->ip_dst.s_addr), ipaddr, INET_ADDRSTRLEN));
    printf("=================\n");
}

int main()
{
    pcap_t* handle;
    struct bpf_program fp;
    bpf_u_int32 net;
    char errbuf[PCAP_ERRBUF_SIZE];
    char* device = "br-d6b258aef2ee";
    char filter_exp[] = "icmp and dst host 10.9.0.5";
    int timeout = 5000;             // miliseconds

    // Opening a network device for sniffing and turn on promiscuous mode
    handle = pcap_open_live(device, BUFSIZ, 1, timeout, errbuf);
    if(handle == NULL)
    {
        fprintf(stderr, "Error! Can't open device %s - %s\n", device, errbuf);
        return 1;
    }

    // Compile expression
    if(pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
    {
        fprintf(stderr, "Error! Can't compile expression - %s\n", pcap_geterr(handle));
        return 2;
    }

    // Applying filter
    if(pcap_setfilter(handle, &fp) == -1)
    {
        fprintf(stderr, "Error! Can't apply the filter - %s\n", pcap_geterr(handle));
        return 2;
    }

    // Sniffing and spoofing
    pcap_loop(handle, 10, capture_packets, NULL);

    // Closing network device
    pcap_close(handle);

    return 0;
}