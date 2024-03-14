// Task2.1A: Print out the source and destination IP addresses of each captured packet
// Task2.1B: Write filter expressions for your sniffer program to capture each of the followings


// References:
// https://pubs.opengroup.org/onlinepubs/009695399/basedefs/arpa/inet.h.html
// https://pubs.opengroup.org/onlinepubs/009695399/functions/inet_addr.html
// https://www.ibm.com/docs/en/qsip/7.4?topic=queries-berkeley-packet-filters: Berkeley Packet Filters syntax (bpf_program)
// https://stackoverflow.com/questions/5328070/how-to-convert-string-to-ip-address-and-vice-versa

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>

#include "packet_header.h"

void got_packet(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet)
{
    printf("\t\t===== CAPTURED PACKET INFO =====\n");
    printf("Packet capture length: %d\n", header->caplen);
    printf("Packet total length: %d\n\n", header->len);
    
    // Print raw packet
    printf("Packet structure in bytes!");
    for(int i = 0; i < header->len; i++)
    {
        if(i % 16 == 0)
        {
            printf("\n");
        }
        printf("%2x  ", packet[i]);
    }
    printf("\n\n");

    // Force the compiler to treat the pointer to the Ethernet header.
    struct ether_head *eth;
    eth = (struct ether_head *) packet;

    // Get the Ethernet length to find the beginning of the IP Header
    struct ip_head *ip = (struct ip_head *) (packet + sizeof(struct ether_head));

    char ipaddr[INET_ADDRSTRLEN];
    /* 
        htonl(): convert unsigned int from host to network byte order.
        ntohl(): reverse of htonl().
        htons(): convert unsigned short int from host to network byte order.
        ntohs(): reverse of htons().
    */
    if(ntohs(eth->type) != 0x800)       // IPv4: 0x800
    {
        printf("Invalid packet\n");
        return;
    }
    else
    {
        printf("IP Source: %s\n", inet_ntop(AF_INET, &(ip->ip_src), ipaddr, INET_ADDRSTRLEN));
        printf("IP Destination: %s\n", inet_ntop(AF_INET, &(ip->ip_dst), ipaddr, INET_ADDRSTRLEN));
    }
    printf("\n\n");
}

int main()
{
    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;              // Berkeley packet filters pr
    char filter_exp[30];
    bpf_u_int32 net;
    char *device = "br-d6b258aef2ee";
    int timeout = 5000;     // milisecond
    int choose;

    printf("Please choose your type of filter: \n");
    printf("[1] ICMP Packets\n");
    printf("[2] TCP Packets with a destination port number in range from 10 to 100\n");
    scanf("%d", &choose);
    
    if(choose < 1 || choose > 2)
    {
        printf("Error! Invalid value\n");
        exit(1);
    }

    if(choose == 1)
    {
        strcpy(filter_exp, "icmp");
    }
    else
    {
        strcpy(filter_exp, "tcp dst portrange 10-100");
    }

    // 1: Turn on promiscuous mode
    // 2: Turn off promiscuous mode
    handle = pcap_open_live(device, BUFSIZ, 1, timeout, errbuf);

    if(handle == NULL)
    {
        fprintf(stderr, "Error! Can't open device '%s': %s\n", device, errbuf);
        return 1;
    }
    
    // Compile the expression
    // 0: The expression should not be "optimized"
    // 1: The expression should be "optimized"

    // Function return:
    // -1: Failed
    // other values: Success

    if(pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
    {
        printf("Bad filter - %s\n", pcap_geterr(handle));
        return 2;
    }

    // Apply the filter
    if(pcap_setfilter(handle, &fp) == -1)
    {
        printf("Error setting filter - %s\n", pcap_geterr(handle));
        return 2;
    }

    // Get 9 packets in loop
    // -1 means sniff packets until there is an error.
    pcap_loop(handle, 9, got_packet, NULL);

    // Close
    pcap_close(handle);
    return 0;
}