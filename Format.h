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

#endif // FORMAT_H
