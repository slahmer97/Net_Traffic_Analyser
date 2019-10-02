
#include <stdio.h>
#include "stdlib.h"

#include "link_layer.h"

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
    pcap_loop(p_cature,count,link_layer_handler,NULL);

    return 0;
}