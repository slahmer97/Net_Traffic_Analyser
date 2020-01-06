//
// Created by slahmer on 11/9/19.
//

#ifndef NET_TRAFFIC_ANALYSER_BOOTPH_H
#define NET_TRAFFIC_ANALYSER_BOOTPH_H
/************************************************************************
          Copyright 1988, 1991 by Carnegie Mellon University

                          All Rights Reserved

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted, provided
that the above copyright notice appear in all copies and that both that
copyright notice and this permission notice appear in supporting
documentation, and that the name of Carnegie Mellon University not be used
in advertising or publicity pertaining to distribution of the software
without specific, written prior permission.

CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS
SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS.
IN NO EVENT SHALL CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL
DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
SOFTWARE.
************************************************************************/

/*
 * Bootstrap Protocol (BOOTP).  RFC951 and RFC1395.
 *
 * $FreeBSD: head/libexec/bootpd/bootp.h 83941 2001-09-25 21:02:10Z iedowse $
 *
 *
 * This file specifies the "implementation-independent" BOOTP protocol
 * information which is common to both client and server.
 *
 */

#include <netinet/in.h>
#define BP_CHADDR_LEN	 16
#define BP_SNAME_LEN	 64
#define BP_FILE_LEN	128
#define BP_VEND_LEN	 64

struct bootp {
    unsigned char    bp_op;			/* packet opcode type */
    unsigned char    bp_htype;			/* hardware addr type */
    unsigned char    bp_hlen;			/* hardware addr length */
    unsigned char    bp_hops;			/* gateway hops */
    unsigned int	     bp_xid;			/* transaction ID */
    unsigned short   bp_secs;			/* seconds since boot began */
    unsigned short   bp_flags;			/* RFC1532 broadcast, etc. */
    struct in_addr   bp_ciaddr;			/* client IP address */
    struct in_addr   bp_yiaddr;			/* 'your' IP address */
    struct in_addr   bp_siaddr;			/* server IP address */
    struct in_addr   bp_giaddr;			/* gateway IP address */
    unsigned char    bp_chaddr[BP_CHADDR_LEN];	/* client hardware address */
    char	     bp_sname[BP_SNAME_LEN];	/* server host name */
    char	     bp_file[BP_FILE_LEN];	/* boot file name */
    unsigned char    bp_vend[BP_VEND_LEN];	/* vendor-specific area */
    /* note that bp_vend can be longer, extending to end of packet. */
};



#include <ctype.h>
/*
static void print_box_hex(const char*padding,const char*input,int size){
    int i = 0;
    for (; i <size ;) {
        printf("%s",padding);
        int k = i;
        for (int j = 0; j < 16; ++j,i++) {
            char c = input[i];
            if(!isprint(c) || i >= size)
                c = '.';
            printf("%c",c);
            fflush(stdout);
        }
        i = k;
        printf("\t");
        for (int j = 0; j < 16; ++j,i++) {
            char c = input[i];
            if(i >= size)
                printf("00 ");
            else{
                //if(c < 15)
                printf("%02hhX ",c);
                // else
                //     printf("%x ",c);
            }
            fflush(stdout);
        }
        printf("\n");
        fflush(stdout);
    }
}
 */

#define END 255
#define REQUESTED_IP 50
#define LEASE_TIME 51
#define OVERLOAD 52
#define DHCP_MSG_TYPE 53
#define DHCP_SERVER_ID 54
#define PARAMETER_LIST 55
#define DHCP_MSG 56
#define DHCP_MAX_MSG_SIZE 57
#define RENEWAL_TIME 58
#define REBINDING_TIME 59
#define ROUTER_DISCOVERY 31
#define ROUTER_REQUEST 32
#define STATIC_ROUTE 33
#define SUBNET_MASK 1
#define CLIENT_IDENTIFIER 61





#endif //NET_TRAFFIC_ANALYSER_BOOTPH_H
