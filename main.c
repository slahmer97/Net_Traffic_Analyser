#define __BIG_ENDIAN_BITFIELD 1

#include <stdio.h>
#include "stdlib.h"
#include <pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <linux/ip.h>
#include "my_const.h"
extern char *ether_ntoa (__const struct ether_addr *__addr) __THROW;
extern char *ether_ntoa_r (__const struct ether_addr *__addr, char *__buf)__THROW;
/*
void display_all_int(pcap_if_t * t){
    char* tmp;
    while(t !=  NULL){

        printf("Device name : %s\n",t->name);
        printf("Description : %s\n",t->description);
        printf("Flags : %x\n",t->flags);
        printf("Addresses : \n");
        struct pcap_addr* tmp_addr = t->addresses;
        while (tmp_addr != NULL){
            struct in_addr addr;
            addr.s_addr = (in_addr_t) t->addresses->addr;
            tmp = inet_ntoa(addr);
            printf("\t addr : %s\n",tmp);
            addr.s_addr = (in_addr_t) t->addresses->broadaddr;
            tmp = inet_ntoa(addr);
            printf("\t broad_addr : %s\n",tmp);
            addr.s_addr = (in_addr_t) t->addresses->netmask;
            tmp = inet_ntoa(addr);
            printf("\t mask_addr : %s\n",tmp);
            addr.s_addr = (in_addr_t) t->addresses->dstaddr;
            tmp = inet_ntoa(addr);
            printf("\t dst_addr : %s\n",tmp);

            tmp_addr = tmp_addr->next;
        }

        t = t->next;
    }
}
 */
void ip_handler(const u_char *packet){
    struct iphdr *ipHeader = (struct iphdr *)packet;
    struct in_addr addr;
    fprintf(stdout,"\t\tversion : %x\n",ipHeader->version);
    addr.s_addr = ipHeader->saddr;
    fprintf(stdout,"\t\tsource ip :%s\n",inet_ntoa(addr));
    addr.s_addr = ipHeader->daddr;
    fprintf(stdout,"\t\tdest ip :%s\n",inet_ntoa(addr));
    fflush(stdout);
}
void ipv6_handler(const u_char * ip6_packet){


}
void ipv4_handler(const u_char * ip4_packet){


}

void ether_handler(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char*packet){
    static int count = 1;
    fprintf(stdout,"==============%d==================\n",count++);
    fprintf(stdout,"[+] len : %u\n",pkthdr->len);
    fprintf(stdout,"[+] capt_len : %u\n",pkthdr->caplen);
    fprintf(stdout,"[+] capt_time : %ld\n",pkthdr->ts.tv_sec);
    struct ether_header* etherHeader =( struct ether_header*)packet;
    fflush(stdout);
    fprintf(stdout,"\t[+] ethertype : %x\n",etherHeader->ether_type);
    fprintf(stdout,"\t[+] source mac : %s\n",ether_ntoa((const struct ether_addr *)&etherHeader->ether_shost));
    fprintf(stdout,"\t[+] destination mac : %s\n",ether_ntoa((const struct ether_addr *)&etherHeader->ether_dhost));
    int ether_header_size = sizeof( struct ether_header);
   //SAVE

    switch ((etherHeader->ether_type)){
        default:
            fprintf(stdout,"%s\n","????[-] no description is provided for this type");
            break;
        case ETHERTYPE_IPV6 :
            ip_handler(&packet[ether_header_size]);
            break;


    }

    fflush(stdout);
}

int main(int argc,char**argv) {
    char *device = "wlp2s0";
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_if_t* pcapIf;

    /* Find a device */
    int ret = pcap_findalldevs(&pcapIf,error_buffer);
    if(ret == -1) {
        fprintf(stderr,"Error pcap_findalldevs :"
               "%s\n",error_buffer);
        exit(1);
    }
    pcap_if_t* t = pcapIf;
    //display_all_int(t);
    pcap_t * p_cature = pcap_open_live(device,BUFSIZ,0,-1,error_buffer);
    if(p_cature == NULL){
        fprintf(stderr,"[-] Error pcap_open_live :\n"
                       "%s\n",error_buffer);
        exit(1);
    }

    int count = 10;
    pcap_loop(p_cature,count,ether_handler,NULL);

    return 0;
}