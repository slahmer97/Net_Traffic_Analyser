//
// Created by sidahmedlahmer on 10/2/19.
//
#include "link_layer.h"
#include "internet_layer.h"

char * arp_op_str[] = {
        [ARPOP_REQUEST]   = "ARP request",
        [ARPOP_REPLY]     = "ARP reply",
        [ARPOP_RREQUEST]  = "RARP request",
        [ARPOP_RREPLY]    = "RARP reply",
        [ARPOP_InREQUEST] = "InARP request",
        [ARPOP_InREPLY]   = "InARP reply",
        [ARPOP_NAK]       = "(ATM)ARP NAK"
};
void link_layer_handler(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char*packet){
    static int count = 1;
    fprintf(stdout,"<-----------------------------%d----------------------------->>>\n",count++);
    fprintf(stdout,"[+] len : %u\n",pkthdr->len);
    fprintf(stdout,"[+] capt_len : %u\n",pkthdr->caplen);
    fprintf(stdout,"[+] capt_time : %ld\n",pkthdr->ts.tv_sec);
    struct ether_header* etherHeader =( struct ether_header*)packet;
    fflush(stdout);
    unsigned short type = htons(etherHeader->ether_type);
    fprintf(stdout,"%s[+] %s (%x), Src : (%s), Dst : (%s) \n",TWOSPACES,"Ethernet II",
            type,ether_ntoa((const struct ether_addr *)&etherHeader->ether_shost),
            ether_ntoa((const struct ether_addr *)&etherHeader->ether_dhost));
  //  fprintf(stdout,"%s[+] ethertype : %x\n",TWOSPACES,type);
  //  fprintf(stdout,"%s[+] source mac : %s\n",TWOSPACES,ether_ntoa((const struct ether_addr *)&etherHeader->ether_shost));
   // fprintf(stdout,"%s[+] destination mac : %s\n",TWOSPACES,ether_ntoa((const struct ether_addr *)&etherHeader->ether_dhost));

    int ether_header_size = sizeof( struct ether_header);
    //SAVE
    const u_char* data = &packet[ether_header_size];
    switch ((type)){
        default:
            fprintf(stdout,"%s\n","????[-] no description is provided for this type");
            break;
        case ETHERTYPE_IPV6:
            internet_layer_handler(data,6);
           // ip_handler(&packet[ether_header_size]);
            break;
        case ETHERTYPE_IP :
            internet_layer_handler(data,4);
            // ip_handler(&packet[ether_header_size]);
            break;
        case ETHERTYPE_ARP:
            arp_handler(data);
            break;
        case ETHERTYPE_REVARP:
            rarp_handler(data);
            break;
    }

    fflush(stdout);
}
static void arp_handler(const u_char*packet){
    fprintf(stdout,"%s[+] arp_handler %lu\n",FOURSPACES,sizeof(*((struct arphdr*)packet)));
    struct arphdr* arp_header = (struct arphdr*)packet;
    unsigned short hardware_type = arp_header->ar_hrd;
    unsigned short protocol_type = arp_header->ar_pro;
    unsigned char  arp_op_code   = htons(arp_header->ar_op);


    //check display option
 //   printf("%s╞══ Proto = ARP, Adress resolution\n");
//    printf("%s├ hardware type  : %s\n",
  //         (ntohs(arp_header->ar_hrd) == 1) ? "Ethernet" : "Unknown");
   // printf("%s├ protocol type  : %s\n",
   //        (ntohs(arp_header->ar_pro) == 0x0800) ? "IPv4" : "Unknown");
    fprintf(stdout,"%s[+] operation      : %s\n",TWOSPACES,arp_op_str[arp_op_code]);
}
void rarp_handler(const u_char*packet){
    fprintf(stdout,"%s[+] reverse arp\n",TWOSPACES);
}

