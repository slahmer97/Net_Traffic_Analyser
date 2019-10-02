//
// Created by sidahmedlahmer on 10/2/19.
//

#ifndef NETWORK_ANA_INCLUDES_H
#define NETWORK_ANA_INCLUDES_H
#include <pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <linux/ip.h>
#define ONESPACE "    "
#define TWOSPACES "        "
#define THREESPACES "            "
extern char *ether_ntoa (__const struct ether_addr *__addr) __THROW;

#endif //NETWORK_ANA_INCLUDES_H
