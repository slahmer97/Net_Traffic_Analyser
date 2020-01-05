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
int verbose;
char *get_dhcp_message_type(unsigned char i);

void tcp_handler(const u_char*packet, unsigned int len){
    struct tcphdr* tcpHeader = (struct tcphdr*)packet;
    ushort source = htons(tcpHeader->source);
    ushort dest =  htons(tcpHeader->dest);
    const u_char* data =(const u_char*) &packet[tcpHeader->doff*4];
    fprintf(stdout,"%s[+] TCP, src : (%hu), dst : (%hu)\n",TWOSPACES,source,dest);
    if(verbose != 3)
        return;
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
    else if(source == 110 || dest == 110)
        pop_parser(data,data_len);
    else if(source == 143 || dest == 143)
        imap_parser(data,data_len);
    else if(source == 21 || dest == 21){
        ftp_parser(data,data_len);
    }
    else if(source == 23 || dest == 23){
        telnet_parser(data,data_len);
    }
    //else if(source == 53 || dest == 53)
        //dns_parser(data,data_len);
    else
        fprintf(stdout,"%s[-] Application isn't implemented yet\n",TWOSPACES);
}
void udp_handler(const u_char* packet){
    struct udphdr* udpHeader = (struct udphdr*)packet;
    ushort sport = htons(udpHeader->source);
    ushort dport = htons(udpHeader->dest);
    fprintf(stdout,"%s[+] UDP, src : (%hu), dst : (%hu)\n",TWOSPACES,sport,dport);
    if(verbose != 3)
        return;
    fprintf(stdout,"%s[..] checksum  : 0x%x\n",TWOSPACES,htons(udpHeader->check));
    fprintf(stdout,"%s[..] len : 0x%d\n",TWOSPACES,htons(udpHeader->len));

    const u_char* data = &packet[sizeof(struct udphdr)];

    if(sport == 68 || dport == 68 || sport == 67 || dport == 67){
        bootp_handler(data);
    }
    if(sport == 53 || dport == 53)
        dns_parser(data,0);



}

void bootp_handler(const u_char* packet){
    struct bootp* bootpHeader = (struct bootp*)packet;
    u_char *vend = bootpHeader->bp_vend;
    uint vend_s = htonl(*((unsigned int*)vend));
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
    fprintf(stdout,"%s[+] Bootp ( %s ) %s\n",THREESPACES,(op_code == 1)?"Request":"Response",(vend_s == 0x63825363)?"( Dynamic Host Configuration Protocole )":"");
    if(verbose != 3)
        return;
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

   // print_box_hex(THREESPACES,(const char*)&bootpHeader->bp_vend[4],BP_VEND_LEN);

    for (int i = 4; i < BP_VEND_LEN; ++i) {
        uint8_t len;
        unsigned char c = bootpHeader->bp_vend[i];
        switch (c){
            case END:
                fprintf(stdout,"%s     [...] OPTION_END\n",THREESPACES);
                return;
            case DHCP_MSG_TYPE:
                i++;
                fprintf(stdout,"%s     [...] DHCP Message Type (%s)\n",THREESPACES,get_dhcp_message_type(bootpHeader->bp_vend[++i]));
                break;
            case CLIENT_IDENTIFIER:
                i++;
                len = (uint8_t )bootpHeader->bp_vend[i];
                i++;
                uint8_t type= (uint8_t )bootpHeader->bp_vend[i];
                i++;
                fprintf(stdout,"%s     [...] Client identifier : %s\n",THREESPACES,(type == 1)? ether_ntoa((const struct ether_addr *)&bootpHeader->bp_vend[i]):"Unknown");
                ether_ntoa((const struct ether_addr *) bootpHeader->bp_chaddr);
                i += len-2;
                break;
            case REQUESTED_IP:
                i++;
                len = (uint8_t )bootpHeader->bp_vend[i];
                i++;
                if(len == 4){
                    fprintf(stdout,"%s     [...] Requested IP addr : %u.%u.%u.%u \n",THREESPACES,bootpHeader->bp_vend[i],bootpHeader->bp_vend[i+1],bootpHeader->bp_vend[i+2],bootpHeader->bp_vend[i+3]);
                }
                i +=len-1;
                break;
            case SUBNET_MASK:
                i++;
                len = (uint8_t )bootpHeader->bp_vend[i];
                i++;
                if(len == 4){
                    fprintf(stdout,"%s     [...] Subnet Mask : %u.%u.%u.%u \n",THREESPACES,bootpHeader->bp_vend[i],bootpHeader->bp_vend[i+1],bootpHeader->bp_vend[i+2],bootpHeader->bp_vend[i+3]);
                }
                i +=len-1;
                break;
            case PARAMETER_LIST:
                i++;
                uint8_t num = bootpHeader->bp_vend[i];
                i++;
                fprintf(stdout,"%s     [...] Param list : %u \n",THREESPACES,num);
                i +=num-1;
                break;
            case RENEWAL_TIME:
                i++;
                num = bootpHeader->bp_vend[i];
                i++;
                fprintf(stdout,"%s     [...] Renewal Time : %u \n",THREESPACES,*(unsigned *)&bootpHeader->bp_vend[i]);
                i +=num-1;
                break;
            case LEASE_TIME:
                i++;
                num = bootpHeader->bp_vend[i];
                i++;
                fprintf(stdout,"%s     [...] Ip Lease time : %u \n",THREESPACES,*(unsigned *)&bootpHeader->bp_vend[i]);
                i +=num-1;
                break;
            case DHCP_SERVER_ID:
                i++;
                len = (uint8_t )bootpHeader->bp_vend[i];
                i++;
                if(len == 4){
                    fprintf(stdout,"%s     [...] Server Identifier : %u.%u.%u.%u \n",THREESPACES,bootpHeader->bp_vend[i],bootpHeader->bp_vend[i+1],bootpHeader->bp_vend[i+2],bootpHeader->bp_vend[i+3]);
                }
                i +=len-1;
                break;

        }
    }
  //  fprintf(stdout,"%s[..] Hop Count Len : %d\n",THREESPACES,bootpHeader->bp_hops);


}

char *get_dhcp_message_type(unsigned char i) {
    switch (i){
        case 1:
            return "Discover";
        case 2:
            return "Offer";
        case 3:
            return "Request";
        case 4:
            return "Decline";
        case 5:
            return "Ack";
        case 6:
            return "Nack";
        case 7:
            return "Release";
        case 8:
            return "Inform";
        case 9:
            return "ForceRenew";
        case 10:
            return "LeaseQuery";
        case 11:
            return "LeaseUnassined";
        case 12:
            return "LeaseUnknown";
        case 13:
            return "LeaseActivate";
        case 14:
            return "BulkLeaseQuery";
        case 15:
            return "LeaseQueryDone";
        case 16:
            return "ActivateLeaseQuery";
        case 17:
            return "LeaseStatusQuery";
        case 18:
            return "Tls";
        default:
            return "Unknown";
    }
}
//==========================
