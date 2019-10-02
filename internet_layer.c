//
// Created by sidahmedlahmer on 10/2/19.
//
#include "internet_layer.h"
#include "linux/ip.h"
#include "linux/ipv6.h"
void internet_layer_handler(const u_char* packet,int version){
    if(version == 4)
        ipv4_handler(packet);
    if(version == 6)
        ipv6_handler(packet);
}
static void ip_handler(const u_char *packet){
    struct iphdr *ipHeader = (struct iphdr *)packet;
    struct in_addr addr;
    fprintf(stdout,"\t\tversion : %x\n",ipHeader->version);
    addr.s_addr = ipHeader->saddr;
    fprintf(stdout,"\t\tsource ip :%s\n",inet_ntoa(addr));
    addr.s_addr = ipHeader->daddr;
    fprintf(stdout,"\t\tdest ip :%s\n",inet_ntoa(addr));
    fflush(stdout);
}
static void ipv6_handler(const u_char * packet){
     struct ipv6hdr * ipv6Header = (struct ipv6hdr *)packet;
     char sip[INET6_ADDRSTRLEN];
     char dip[INET6_ADDRSTRLEN];
     inet_ntop(AF_INET6, &(ipv6Header->daddr),dip, INET6_ADDRSTRLEN);
     inet_ntop(AF_INET6, &(ipv6Header->saddr),sip, INET6_ADDRSTRLEN);
     fprintf(stdout,"\t[+] version   : %x\n",ipv6Header->version);
     fprintf(stdout,"\t[+] source ip : %s\n",sip);
     fprintf(stdout,"\t[+] dest ip   : %s\n",dip);
     fflush(stdout);


}
static void ipv4_handler(const u_char * packet){
    struct iphdr *ipHeader = (struct iphdr *)packet;
    char sip[INET_ADDRSTRLEN];
    char dip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET,&(ipHeader->saddr),sip,INET_ADDRSTRLEN);
    inet_ntop(AF_INET,&(ipHeader->daddr),dip,INET_ADDRSTRLEN);
    fprintf(stdout,"\t [+] version   : %x\n",ipHeader->version);
    fprintf(stdout,"\t [+] source ip : %s\n",sip);
    fprintf(stdout,"\t [+] dest ip   : %s\n",dip);
    fprintf(stdout,"\t [+] ihl       : %d\n",ipHeader->ihl);
    fprintf(stdout,"\t [+] ttl       : %d\n",ipHeader->ttl);
    fprintf(stdout,"\t [+] checksum  : %x\n",ipHeader->check);
    fprintf(stdout,"\t [+] total len : %d\n",ipHeader->tot_len);
    fprintf(stdout,"\t [+] id        : %d\n",ipHeader->id);
    fprintf(stdout,"\t [+] frag off  : %d\n",ipHeader->frag_off);
    fflush(stdout);

    switch (ipHeader->protocol){
        default:
            fprintf(stderr,"\t [-] Protocol not recognized yet %x\n",ipHeader->protocol);
            break;
        case 0x01: // ICMP

            break;
        case 0x02: //IGMP

            break;
        case 0x03: // GGP

            break;
        case 0x06:// TCP

            break;
        case 0x08: //EGP

            break;
        case 0x11: // UDP

            break;

        case 0x59: // OSPF

            break;

    }





}