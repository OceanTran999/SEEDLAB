#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>


// This function will be invoked by pcap for each captured packet.
// We can process each packet inside this function.
void capture_packet(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet)
{
    printf("Got a packet!\n");
}

int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "icmp";
    bpf_u_int32 net;

    // Step 1: Open live pcap session on NIC.
    handle = pcap_open_live("br-d6b258aef2ee", BUFSIZ, 1, 1000, errbuf);

    if(handle == NULL)
    {
        fprintf(stderr, "Can't open device 'br-d6b258aef2ee': %s\n", errbuf);
        return(2);
    }
   
    // Step 2: Compile filter_exp into BPF psuedo-code
    pcap_compile(handle, &fp, filter_exp, 0, net);
    if(pcap_setfilter(handle, &fp) != 0)
    {
        pcap_perror(handle, "Error: ");
        exit(EXIT_FAILURE);
    }
    
    // Step 3: Caputre packets
    pcap_loop(handle, -1, capture_packet, NULL);

    pcap_close(handle); // Close the handle
    return 0;
}