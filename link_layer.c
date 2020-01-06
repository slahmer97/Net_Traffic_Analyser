//
// Created by sidahmedlahmer on 10/2/19.
//
#include "link_layer.h"
#include "internet_layer.h"
#include "string.h"
int verbose;
char * arp_op_str[] = {
        [ARPOP_REQUEST]   = "ARP request",
        [ARPOP_REPLY]     = "ARP reply",
        [ARPOP_RREQUEST]  = "RARP request",
        [ARPOP_RREPLY]    = "RARP reply",
        [ARPOP_InREQUEST] = "InARP request",
        [ARPOP_InREPLY]   = "InARP reply",
        [ARPOP_NAK]       = "(ATM)ARP NAK"
};
char * ether_type_str[] = {
        [ETHERTYPE_IPV6]   = "IPV6",
        [ETHERTYPE_IP]     = "IPV4",
        [ETHERTYPE_ARP]    = "ARP",
        [ETHERTYPE_REVARP] = "Reverse ARP"
};
/**
 * @brief : this function defines the callback, which will be called on the arriving of frame
 *          on the arrival of each frame, there will be four possible ways (which are already implemented ) :
 *          * if ether_type indicates that there's an ipv6 ip packet encapsulated, so ipv6 parser will be called.
 *          * if ether_type indicates that there's an ipv4 ip packet encapsulated, so ipv4 parser will be called.
 *          * if ether_type indicates that there's an arp frame encapsulated, so arp_parser will be called.
 *          * if ether_type indicates that there's an rarp frame encapsulated, so rarp parser will be called.
 * @param useless
 * @param pkthdr
 * @param p : represents frame data.
 * @remarks : this functions copy the received data into an internal buffer which is reseted to 0 each time
 *            link_layer_handler() is started.
 *
 */
void link_layer_handler(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char*p){
    useless++;
    static int count = 1;
    char packet[1500] = {0};
    memcpy(packet,p,pkthdr->caplen);
    fprintf(stdout,"<-----------------------------Packet : %d----------------------------->>>\n",count++);
    if(verbose == 3){
        fprintf(stdout,"[+] len : %u\n",pkthdr->len);
        fprintf(stdout,"[+] capt_len : %u\n",pkthdr->caplen);
        fprintf(stdout,"[+] capt_time : %ld\n",pkthdr->ts.tv_sec);
    }
    struct ether_header* etherHeader =( struct ether_header*)packet;
    unsigned short type = htons(etherHeader->ether_type);

    fprintf(stdout,"[+] %s (%x), Src : (%s), Dst : ","Ethernet II",
            type,ether_ntoa((const struct ether_addr *)&etherHeader->ether_shost));
    fprintf(stdout,"(%s) \n",ether_ntoa((const struct ether_addr *)&etherHeader->ether_dhost));

    int ether_header_size = sizeof( struct ether_header);
    //SAVE
    const u_char* data = (const u_char*)&packet[ether_header_size];
    switch ((type)){
        default:
            fprintf(stdout,"%s\n","????[-] no description is provided for this type");
            break;
        case ETHERTYPE_IPV6:
            internet_layer_handler(data,6);
            break;
        case ETHERTYPE_IP :
            internet_layer_handler(data,4);
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
void arp_handler(const u_char*packet){
    struct arphdr* arp_header = (struct arphdr*)packet;
    //unsigned short hardware_type = arp_header->ar_hrd;
    //unsigned short protocol_type = arp_header->ar_pro;
    unsigned char  arp_op_code   = htons(arp_header->ar_op);
    //TODO

    fprintf(stdout,"%s[.] op      : %s\n",ONESPACE,arp_op_str[arp_op_code]);
}
void rarp_handler(const u_char*packet){
    packet++;//TODO
    fprintf(stdout,"%s[.] reverse arp\n",ONESPACE);
}

