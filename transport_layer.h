//
// Created by sidahmedlahmer on 10/2/19.
//

#ifndef NETWORK_ANA_TRANSPORT_LAYER_H
#define NETWORK_ANA_TRANSPORT_LAYER_H

#include "includes.h"
void transport_layer_handler(const u_char*);
void udp_handler(const u_char*);
void tcp_handler(const u_char*);


#endif //NETWORK_ANA_TRANSPORT_LAYER_H
