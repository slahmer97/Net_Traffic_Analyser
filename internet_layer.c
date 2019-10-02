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
     fprintf(stdout,"%s[+] IPV6, src : (%s), dst : (%s)\n",ONESPACE,sip,dip);
     fprintf(stdout,"%s[..] version   : %x\n",TWOSPACES,ipv6Header->version);

     fflush(stdout);


}
static void ipv4_handler(const u_char * packet){
    struct iphdr *ipHeader = (struct iphdr *)packet;
    char sip[INET_ADDRSTRLEN];
    char dip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET,&(ipHeader->saddr),sip,INET_ADDRSTRLEN);
    inet_ntop(AF_INET,&(ipHeader->daddr),dip,INET_ADDRSTRLEN);
    fprintf(stdout,"%s[+] IPV4, src : (%s), dst : (%s)\n",ONESPACE,sip,dip);
    fprintf(stdout,"%s[..] version   : %x\n",TWOSPACES,ipHeader->version);
    fprintf(stdout,"%s[..] ihl       : %d\n",TWOSPACES,ipHeader->ihl);
    fprintf(stdout,"%s[..] ttl       : %d\n",TWOSPACES,ipHeader->ttl);
    fprintf(stdout,"%s[..] checksum  : %x\n",TWOSPACES,ipHeader->check);
    fprintf(stdout,"%s[..] total len : %d\n",TWOSPACES,ipHeader->tot_len);
    fprintf(stdout,"%s[..] id        : %d\n",TWOSPACES,ipHeader->id);
    fprintf(stdout,"%s[..] frag off  : %d\n",TWOSPACES,ipHeader->frag_off);
    fflush(stdout);


    const u_char * data = &packet[sizeof(struct iphdr)];

    switch (ipHeader->protocol){
        default:
            fprintf(stderr,"%s[-] Protocol not recognized yet %x\n",TWOSPACES,ipHeader->protocol);
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