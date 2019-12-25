
#include <stdio.h>
#include <getopt.h>
#include "stdlib.h"
#include "global.h"
#include "link_layer.h"

int verbose = -1;
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

void live_capture(const char* interface,char*filter);
void offline_capture(const char*file,char*filter);

int main(int argc,char**argv) {
    char * device = 0;
    char * file   = 0;
    char * f = 0;
    int opt;
    while((opt = getopt(argc, argv, "i:f:v:o:")) != -1){
        switch (opt){
            case 'i':
                device = optarg;
                break;
            case 'f':
                f = optarg;
                break;
            case 'o':
                file = optarg;
                break;
            case 'v':
                verbose = strtol("BADSTRING",&optarg,10);
                break;
            default:
                fprintf(stderr,"[-] Option %c %s has not been recognized\n",opt,optarg);
                break;
        }
    }
    //file ="../packet/tcp_sack.cap";
    fprintf(stdout,"FILE : %s\n",file);
    fprintf(stdout,"VERBOSE : %d\n",verbose);
    fprintf(stdout,"DEVICE : %s\n",device);
    fprintf(stdout,"FORMAT : %s\n",f);



    if(!file){
       live_capture(device,0);
    }
    else{
        offline_capture(file,0);
    }

    return 0;
}

void live_capture(const char*interface,char*filter){

    char *device = "wlp2s0";
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    int timeout_limit = 10000; /* In milliseconds */


    /* Open device for live capture */
    handle = pcap_open_live(
            interface,
            BUFSIZ,
            0,
            timeout_limit,
            error_buffer
    );
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", device, error_buffer);
        return;
    }
    struct bpf_program fp;			/* compiled filter program (expression) */
    bpf_u_int32 mask;			/* subnet mask */
    bpf_u_int32 net;			/* ip */



    if (pcap_lookupnet(device, &net, &mask, error_buffer) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
                device, error_buffer);
        exit(EXIT_FAILURE);
        net = 0;
        mask = 0;

    }
    if (pcap_compile(handle, &fp, filter, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n",
                filter, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    /* apply the compiled filter */
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n",
                filter, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    pcap_loop(handle, 100,link_layer_handler, NULL);

}
void offline_capture(const char*file,char*filter){
    filter++;
    filter--;
    char error_buffer[PCAP_ERRBUF_SIZE];

    pcap_t * p_cature = NULL;
    printf("[+] offline capture\n");
    p_cature = pcap_open_offline(file,error_buffer);
    if(p_cature == NULL){
        fprintf(stderr,"[-] Error pcap_open_live :\n"
                       "%s\n",error_buffer);
        exit(1);
    }

    //int count = 130;
    pcap_loop(p_cature,10,link_layer_handler,NULL);


    //pcap_freecode(&bf_prog);

    pcap_close(p_cature);
    printf("\nCapture complete.\n");
}