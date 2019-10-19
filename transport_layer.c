//
// Created by sidahmedlahmer on 10/2/19.
//


#include <zconf.h>
#include <linux/udp.h>
#include <stdio.h>
#include "includes.h"
#include "transport_layer.h"
#include "bootp.h"

void udp_handler(const u_char* packet){
    struct udphdr* udpHeader = (struct udphdr*)packet;
    ushort sport = htons(udpHeader->source);
    ushort dport = htons(udpHeader->dest);
    fprintf(stdout,"%s[+] UDP, src : (%hu), dst : (%hu)\n",TWOSPACES,sport,dport);
    fprintf(stdout,"%s[..] checksum  : %x\n",TWOSPACES,htons(udpHeader->check));
    fprintf(stdout,"%s[..] len : %d\n",TWOSPACES,udpHeader->len);

    const u_char* data = &packet[sizeof(struct udphdr)];

    if(sport == 68 || dport == 68 || sport == 67 || dport == 67){
        bootp_handler(data);
    }



}

void bootp_handler(const u_char* packet){
    struct bootp_h* bootpHeader = (struct bootp_h*)packet;
    u_char *vend = bootpHeader->bp_vend;
    uint dhcp_magic = htonl(*((unsigned int*)vend));


    char cip[INET_ADDRSTRLEN];
    char yip[INET_ADDRSTRLEN];
    char sip[INET_ADDRSTRLEN];
    char gip[INET_ADDRSTRLEN];

    inet_ntop(AF_INET,&(bootpHeader->bp_ciaddr),cip,INET_ADDRSTRLEN);
    inet_ntop(AF_INET,&(bootpHeader->bp_yiaddr),yip,INET_ADDRSTRLEN);
    inet_ntop(AF_INET,&(bootpHeader->bp_siaddr),sip,INET_ADDRSTRLEN);
    inet_ntop(AF_INET,&(bootpHeader->bp_giaddr),gip,INET_ADDRSTRLEN);

    u_char  op_code =(bootpHeader->bp_op);
    u_char h_type = (bootpHeader->bp_htype);
    fprintf(stdout,"%s[+] Bootp ( %s ) %s\n",THREESPACES,(op_code == 1)?"Request":"Response",(dhcp_magic== 0x63825363)?"( Dynamic Host Configuration Protocole )":"");
    fprintf(stdout,"%s[..] Hardware Type      : %s\n",THREESPACES,(h_type == 1)?"Ethernet":"Unknown");
    fprintf(stdout,"%s[..] Hardware Len       : %d\n",THREESPACES,bootpHeader->bp_hlen);
    fprintf(stdout,"%s[..] Hop Count Len      : %d\n",THREESPACES,bootpHeader->bp_hops);
    fprintf(stdout,"%s[..] Transaction Id     : %d\n",THREESPACES,bootpHeader->bp_xid);
    fprintf(stdout,"%s[..] Flags              : %d\n",THREESPACES,bootpHeader->bp_flags);
    fprintf(stdout,"%s[..] Number of secs     : %d\n",THREESPACES,bootpHeader->bp_secs);
    fprintf(stdout,"%s[..] Client ip address  : %s\n",THREESPACES,cip);
    fprintf(stdout,"%s[..] Your ip address    : %s\n",THREESPACES,yip);
    fprintf(stdout,"%s[..] Server ip address  : %s\n",THREESPACES,sip);
    fprintf(stdout,"%s[..] Gateway ip address : %s\n",THREESPACES,gip);
    fprintf(stdout,"%s[..] Hardware address   : %s\n",THREESPACES, (h_type == 1) ? ether_ntoa((const struct ether_addr *) bootpHeader->bp_chaddr) : "Unknown");
    fprintf(stdout,"%s[..] Server Hostname    : %s\n",THREESPACES,bootpHeader->bp_sname);
    fprintf(stdout,"%s[..] Boot file          : %s\n",THREESPACES,bootpHeader->bp_file);
  //  fprintf(stdout,"%s[..] Hop Count Len : %d\n",THREESPACES,bootpHeader->bp_hops);


}