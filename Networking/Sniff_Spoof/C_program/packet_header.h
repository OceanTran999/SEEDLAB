/* Ethernet Header */
struct ether_head{
    unsigned char dest_host[6]; // Destination MAC Address
    unsigned char src_host[6]; // Source MAC Address
    unsigned short type;        // ARP? or TCP? or RARP? etc
};


/* IP Header */
struct ip_head{
    unsigned char ip_headlen:4;   // IP header length
    unsigned char ip_ver:4;       // IP version
    unsigned char tos;              // Type of service
    
    unsigned short int ip_totlen;   // Total length
    unsigned short int id;          // Identification
    unsigned short int ip_flag:3;      // Fragmentation flags
    unsigned short int ip_off:13;       // Flag offset

    unsigned char ip_ttl;               // Time to live
    unsigned char ip_proto;             // Protocol
    unsigned short int ip_chksum;       // IP Checksum
    struct in_addr ip_src;              // IP Source
    struct in_addr ip_dst;              // IP Destination
};


/* TCP Header */
struct tcp_head{
    unsigned short int sport;       // Source port
    unsigned short int dport;       // Destination port
    unsigned int seq;               // Sequence number
    unsigned int ack;               // Acknowledge number
    unsigned char resrvd;           // Data offset, reserved
#define OFF(th)             (((th)->resrvd & 0xf0) >> 4)
    unsigned char flags;
#define FIN 0x01
#define SYN 0x02
#define RST 0x04
#define PUSH 0x08
#define ACK 0x16
#define URG 0x20
#define ECE 0x40
#define CWR 0x80
#define FLAGS (FIN|SYN|RST|PUSH|ACK|URG|ECE|CWR)
    unsigned short int win;         // Window size
    unsigned short int tcp_chksum;  // TCP Checksum
    unsigned short int urp;         // Urgent pointer
};

/* ICMP Header */
struct icmp_head{
    unsigned char icmp_type;   // Type
    unsigned char code;        // Code
    unsigned short int icmp_chksum;  // Checksum
    unsigned short int icmp_id;      // Identifier
    unsigned short int icmp_seq;     // Sequence number
};