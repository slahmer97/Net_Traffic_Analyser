//
// Created by sidahmedlahmer on 10/2/19.
//

#ifndef NETWORK_ANA_INTERNET_LAYER_H
#define NETWORK_ANA_INTERNET_LAYER_H

#include "includes.h"
#include "linux/icmp.h"


void internet_layer_handler(const u_char* packet,int version);
static void  ipv6_handler(const u_char*);
static void  ipv4_handler(const u_char*);
static void  icmp_handler(const u_char*);
static void  igmp_handler(const u_char*);
static void  ospf_handler(const u_char*);
static void  rib_handler (const u_char*);

#endif //NETWORK_ANA_INTERNET_LAYER_H
