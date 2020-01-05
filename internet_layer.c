//
// Created by sidahmedlahmer on 10/2/19.
//
#include "internet_layer.h"
#include "linux/ip.h"
#include "linux/ipv6.h"
#include "linux/icmp.h"
#include "linux/igmp.h"
#include "linux/tcp.h"
#include "transport_layer.h"
int verbose;
void internet_layer_handler(const u_char* packet,int version){
    if(version == 4)
        ipv4_handler(packet);
    if(version == 6)
        ipv6_handler(packet);
}

void ipv6_handler(const u_char * packet){
     struct ipv6hdr * ipv6Header = (struct ipv6hdr *)packet;
     char sip[INET6_ADDRSTRLEN];
     char dip[INET6_ADDRSTRLEN];
     inet_ntop(AF_INET6, &(ipv6Header->daddr),dip, INET6_ADDRSTRLEN);
     inet_ntop(AF_INET6, &(ipv6Header->saddr),sip, INET6_ADDRSTRLEN);
     fprintf(stdout,"%s[+] IPV6, src : (%s), dst : (%s)\n",ONESPACE,sip,dip);
     fprintf(stdout,"%s[..] version   : %x\n",TWOSPACES,ipv6Header->version);

     fflush(stdout);


}
void ipv4_handler(const u_char * packet){
    struct iphdr *ipHeader = (struct iphdr *)packet;
    char sip[INET_ADDRSTRLEN];
    char dip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET,&(ipHeader->saddr),sip,INET_ADDRSTRLEN);
    inet_ntop(AF_INET,&(ipHeader->daddr),dip,INET_ADDRSTRLEN);
    fprintf(stdout,"%s[+] IPV4, src : (%s), dst : (%s)\n",ONESPACE,sip,dip);
    if(verbose == 3) {
        fprintf(stdout,"%s[..] version   : %x\n",ONESPACE,ipHeader->version);
        fprintf(stdout,"%s[..] ihl       : %d\n",ONESPACE,ipHeader->ihl);
        fprintf(stdout,"%s[..] ttl       : %d\n",ONESPACE,ipHeader->ttl);
        fprintf(stdout,"%s[..] checksum  : %x\n",ONESPACE,htons(ipHeader->check));
        fprintf(stdout,"%s[..] total len : %d\n",ONESPACE,htons(ipHeader->tot_len));
        fprintf(stdout,"%s[..] id        : %d\n",ONESPACE,ipHeader->id);
        fprintf(stdout,"%s[..] frag off  : %d\n",ONESPACE,ipHeader->frag_off);
    }
    fflush(stdout);
    unsigned int data_len = htons(ipHeader->tot_len) - (ipHeader->ihl*4);
    //add ihl case later
    const u_char * data = &packet[sizeof(struct iphdr)];

    switch (ipHeader->protocol){
        default:
            fprintf(stderr,"%s[-] Protocol not recognized yet %x\n",TWOSPACES,ipHeader->protocol);
            break;
        case 0x01: // ICMP
            if(verbose == 3 || verbose == 2){
                fprintf(stdout,"%s[+] ICMP(4)   \n",THREESPACES);
                if(verbose == 3)
                    icmp_handler(data);
            }
            break;
        case 0x02: //IGMP

            break;
        case 0x03: // GGP

            break;
        case 0x06:// TCP
            if(verbose >= 2){
                tcp_handler(data,data_len);
            }
            break;
        case 0x08: //EGP

            break;
        case 0x11: // UDP
            if(verbose >= 2)
                udp_handler(data);
            break;

        case 0x59: // OSPF

            break;

    }





}
void icmp_handler(const u_char * packet){
    struct icmphdr* icmpHeader = (struct icmphdr*)packet;
    icmpHeader->code = 1;
}
/*


static void  igmp_handler(const u_char*packet){
    struct igmphdr* igmpHeader = (struct igmphdr*)packet;
    igmpHeader->code = 1;
    fprintf(stdout,"%s[+] IGMP(4)   \n",THREESPACES);

}
static void  ospf_handler(const u_char*packet){
    packet++;
    fprintf(stdout,"%s[+] OSPF(4)   \n",THREESPACES);
}
static void  rib_handler (const u_char*packet){
    packet++;
    fprintf(stdout,"%s[+] RIB(4)   \n",THREESPACES);
}
 */