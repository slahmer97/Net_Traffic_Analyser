//
// Created by sidahmedlahmer on 10/2/19.
//

#ifndef NETWORK_ANA_LINK_LAYER_H
#define NETWORK_ANA_LINK_LAYER_H
#include "linux/if_arp.h"
#include "includes.h"



void link_layer_handler(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char*packet);
static void arp_handler(const u_char*packet);
static void rarp_handler(const u_char*packet);


#endif //NETWORK_ANA_LINK_LAYER_H


