// Task 2.2A: Writing program sends out spoofed IP packets.
// Task 2.2B: Spoof an ICMP echo request packet on behalf of another machine (i.e., 
//              using another machine’s IP address as its source IP address). 
//              This packet should be sent to a remote machine on the Internet
//              (the machine must be alive)

// Refs:
// https://www.man7.org/linux/man-pages/man7/ip.7.html: struct sockaddr_in
// https://pubs.opengroup.org/onlinepubs/7908799/xns/inet_addr.html: inet_addr()
// https://pubs.opengroup.org/onlinepubs/7908799/xns/arpainet.h.html: arpa/inet.h
// https://www.man7.org/linux/man-pages/man3/inet_addr.3.html: arpa/inet.h
// https://stackoverflow.com/questions/24590818/what-is-the-difference-between-ipproto-ip-and-ipproto-raw: IPPROTO_IP vs IPPROTO_RAW

#include <unistd.h>
#include <stdio.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <net/if.h>

#include "packet_header.h"

void send_packet(struct ip_head* ip)
{
    int enable = 1;
    struct sockaddr_in sin;
    int ret = 0;
    char* device = "br-d6b258aef2ee";

    // SOCK_RAW: Create a raw socket to access IP protocol directly
    // IPPROTO_RAW: Tell the system that our packet already has the IP Header, which prevents OS adding
    //              another IP header.
    int sockfd;
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    // Check if socket() is failed
    if(sockfd < 0)
    {
        perror("Error! Failed to open raw socket!\n");
        return;
    }

    //Set socket option
    if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable)) < 0)
    {
        perror("Failed to set socket option: ");
        return;
    }


    //  This data structure is needed when sending the packets using sockets. Normally, we need to 
    //  fill out several fields, but for raw sockets, we only need to fill out this one field
    sin.sin_family = AF_INET;
    sin.sin_addr = ip->ip_dst;

    // Send out the IP packet.
    //    ip_len is the actual size of the packet.
    if(sendto(sockfd, ip, ntohs(ip->ip_totlen), 0, (struct sockaddr*)&sin, sizeof(sin)) < 0)
    {
        perror("Error! Can't send packet: ");
        return;
    }
    close(sockfd);
}

unsigned short int cal_chksum(unsigned short int* buffer, int length)
{
    int nleft = length;
    unsigned short int* w = buffer;
    int sum = 0;
    unsigned short int temp=0;

    // First add all the bits to the 32-bit integer.
    // Then use 16-bit higher add to 16-bit lower to calculate checksum.
    // Finally add the carry bit to the current checksum to get the correct checksum.
    while(nleft > 1)
    {
        sum = sum + *w;
        w = w + 1;
        nleft -= 2;
    }

    // If the last bits is 1
    if(nleft == 1)
    {
        *(unsigned char*)(&temp) = *(unsigned char*)w;
        sum += temp;
    }

    sum = (sum >> 16) + (sum  & 0xffff);
    sum += (sum >> 16);    // Add carry bits

    return (unsigned short int)(~sum);
}

int main(int argc, char* argv[])
{
    char buffer[1500];
    memset(buffer, 0, 1500);

    if(argc != 3)
    {
        printf("Error! Can't run the program.\n");
        printf("Usage syntax: ./task fake_ip target_ip\n");
        return 1;
    }
      
    // Here you can construct the IP packet using buffer[]
    // - construct the IP header ...
    // - construct the TCP/UDP/ICMP header ...
    // - fill in the data part if needed ...
    // Note: you should pay attention to the network/host byte order.
    
    // Force the pointer to the IP header in the packet.
    // Point to the ICMP header by getting IP header length.
    struct icmp_head* icmp = (struct icmp_head*)(buffer + sizeof(struct ip_head));

    /* Fill in ICMP header */
    // echo_request = 8
    // echo_reply = 0
    icmp->icmp_type = 8;
    icmp->icmp_chksum = 0;
    icmp->icmp_id = 2304;       // Identifier (LE)
    icmp->icmp_seq = 256;       // Sequence number (LE)

    struct ip_head* ip = (struct ip_head*)buffer;
    /* Fill in IP header */
    ip->ip_headlen = 5;
    ip->ip_ver = 4;
    ip->ip_ttl = 64;
    ip->ip_src.s_addr = inet_addr(argv[1]);     // Fake IP
    ip->ip_dst.s_addr = inet_addr(argv[2]);     // IP that on the Internet and it must be alive
    ip->ip_proto = IPPROTO_ICMP;
    ip->ip_totlen = htons(sizeof(struct ip_head) + sizeof(struct icmp_head));       // make sure in network byte order.

    // Calculate ICMP checksum
    icmp->icmp_chksum = cal_chksum((unsigned short int*)icmp, sizeof(struct icmp_head));

    send_packet(ip);
    return 0;
}