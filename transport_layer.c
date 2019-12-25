//
// Created by sidahmedlahmer on 10/2/19.
//


#include <zconf.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <stdio.h>
#include "includes.h"
#include "transport_layer.h"
#include "bootph.h"
#include "application_layer.h"

void tcp_handler(const u_char*packet,unsigned int len){
    struct tcphdr* tcpHeader = (struct tcphdr*)packet;
    ushort source = htons(tcpHeader->source);
    ushort dest =  htons(tcpHeader->dest);
    const u_char* data =(const u_char*) &packet[tcpHeader->doff*4];
    fprintf(stdout,"%s[+] TCP, src : (%hu), dst : (%hu)\n",TWOSPACES,source,dest);
    fprintf(stdout,"%s[..] seq       : 0x%x\n",TWOSPACES,htonl(tcpHeader->seq));
    fprintf(stdout,"%s[..] seq ack   : 0x%x\n",TWOSPACES,htonl(tcpHeader->ack_seq));
    fprintf(stdout,"%s[..] check     : 0x%x\n",TWOSPACES,htons(tcpHeader->check));
    fprintf(stdout,"%s[..] cwr       : 0x%x\n",TWOSPACES,htons(tcpHeader->cwr));
    fprintf(stdout,"%s[..] doff      : 0x%x\n",TWOSPACES,htons(tcpHeader->doff));
    fprintf(stdout,"%s[..] ece       : 0x%x\n",TWOSPACES,htons(tcpHeader->ece));
    fprintf(stdout,"%s[..] fin       : 0x%x\n",TWOSPACES,htons(tcpHeader->fin));
    fprintf(stdout,"%s[..] ack       : 0x%x\n",TWOSPACES,htons(tcpHeader->ack));
    fprintf(stdout,"%s[..] psh       : 0x%x\n",TWOSPACES,htons(tcpHeader->psh));
    fprintf(stdout,"%s[..] res1      : 0x%x\n",TWOSPACES,htons(tcpHeader->res1));
    fprintf(stdout,"%s[..] rst       : 0x%x\n",TWOSPACES,htons(tcpHeader->rst));
    fprintf(stdout,"%s[..] syn       : 0x%x\n",TWOSPACES,htons(tcpHeader->syn));
    fprintf(stdout,"%s[..] urg       : 0x%x\n",TWOSPACES,htons(tcpHeader->urg));
    fprintf(stdout,"%s[..] urg_ptr   : 0x%x\n",TWOSPACES,htons(tcpHeader->urg_ptr));
    fprintf(stdout,"%s[..] window    : 0x%x\n",TWOSPACES,htons(tcpHeader->window));
    unsigned int data_len = len -((unsigned int) tcpHeader->doff*4) ;
    fprintf(stdout,"%s[..] data len  : %d\n",TWOSPACES,data_len);

    if(data_len <= 0){
        fprintf(stdout,"%s[..]TCP SEGMENT HAS NO DATA\n",TWOSPACES);
        return;
    }
    if(source == 80 || dest == 80)
            http_parser(data,data_len);
    else if(source == 25 || dest == 25)
            smtp_parser(data,data_len);
    else
        fprintf(stdout,"%s[-] Application isn't implemented yet\n",TWOSPACES);
}
void udp_handler(const u_char* packet){
    struct udphdr* udpHeader = (struct udphdr*)packet;
    ushort sport = htons(udpHeader->source);
    ushort dport = htons(udpHeader->dest);
    fprintf(stdout,"%s[+] UDP, src : (%hu), dst : (%hu)\n",TWOSPACES,sport,dport);
    fprintf(stdout,"%s[..] checksum  : 0x%x\n",TWOSPACES,htons(udpHeader->check));
    fprintf(stdout,"%s[..] len : 0x%d\n",TWOSPACES,udpHeader->len);

    const u_char* data = &packet[sizeof(struct udphdr)];

    if(sport == 68 || dport == 68 || sport == 67 || dport == 67){
        bootp_handler(data);
    }




}

void bootp_handler(const u_char* packet){
    struct bootp* bootpHeader = (struct bootp*)packet;
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