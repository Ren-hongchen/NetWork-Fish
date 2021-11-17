#ifndef FORMAT_H
#define FORMAT_H

typedef unsigned char u_char;
typedef unsigned short u_short;
typedef unsigned int u_int;
typedef unsigned long u_long;

typedef struct ether_header{
    u_char ethernet_des_host[6];
    u_char ethernet_src_host[6];
    u_short type;
} ETHER_HEADER;

typedef struct ip_header {
    u_char version_length;
    u_char TOS;
    u_short total_length;
    u_short identification;
    u_short offset;
    u_char ttl;
    u_char protocol;
    u_short checksum;
    u_int src_addr;
    u_int des_addr;
} IP_HEADER;

typedef struct tcp_header {
    u_short src_port;
    u_short des_port;
    u_int sequence_number;
    u_int ack_number;
    u_char header_length;
    u_char flags;
    u_short window_size;
    u_short checksum;
    u_short urgent_pointer;
} TCP_HEADER;

typedef struct udp_header{
    u_short src_port;
    u_short des_port;
    u_short data_length;
    u_short checksum;
} UDP_HEADER;

typedef struct arp_header{
    u_short type;
    u_short protocol;
    u_char mac_len;
    u_char ip_len;
    u_short op_type;
    u_char src_eth_addr[6];
    u_char src_ip_addr[4];
    u_char des_eth_addr[6];
    u_char des_ip_addr[4];
} ARP_HEADER;

typedef struct icmp_header{
    u_char type;
    u_char code;
    u_short checksum;
    u_short identification;
    u_short sequence;
} ICMP_HEADER;

#endif // FORMAT_H
