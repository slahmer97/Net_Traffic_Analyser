//
// Created by sidahmedlahmer on 10/2/19.
//

#ifndef NETWORK_ANA_TRANSPORT_LAYER_H
#define NETWORK_ANA_TRANSPORT_LAYER_H

#include "includes.h"
void transport_layer_handler(const u_char*,u_char protocol);
void udp_handler(const u_char*);
void tcp_handler(const u_char*,unsigned int);

void bootp_handler(const u_char*);
//static const char* port_str(unsigned short src, unsigned short dest);

#endif //NETWORK_ANA_TRANSPORT_LAYER_H
