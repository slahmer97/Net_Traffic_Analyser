//
// Created by sidahmedlahmer on 10/2/19.
//

#include <zconf.h>

#ifndef NETWORK_ANA_APPLICATION_LAYER_H
#define NETWORK_ANA_APPLICATION_LAYER_H


void http_parser(const u_char* data,unsigned int);
void smtp_parser(const u_char* data,unsigned int);
void dns_parser(const u_char*  data, unsigned int);




#endif //NETWORK_ANA_APPLICATION_LAYER_H
