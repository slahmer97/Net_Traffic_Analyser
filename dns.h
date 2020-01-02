//
// Created by slahmer on 12/27/19.
//

#ifndef NET_ANALYS_DNS_H
#define NET_ANALYS_DNS_H
/*
    DNS Header for packet forging
    Copyright (C) 2016 unh0lys0da

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#define DNS_OPCODE_QUERY	0
#define DNS_OPCODE_IQUERY	1
#define DNS_OPCODE_STATUS	2
#define DNS_OPCODE_NOTIFY	4
#define DNS_OPCODE_UPGRADE	5

#define DNS_RCODE_NOERROR	0
#define DNS_RCODE_FORMERR	1
#define DNS_RCODE_SERVFAIL	2
#define DNS_RCODE_NXDOMAIN	3
#define DNS_RCODE_NOTIMP	4
#define DNS_RCODE_REFUSED	5
#define DNS_RCODE_YXDOMAIN	6
#define DNS_RCODE_YXRRSET	7
#define DNS_RCODE_NXRRSET	8
#define DNS_RCODE_NOTAUTH	9
#define DNS_RCODE_NOTZONE	10
#define DNS_RCODE_BADVERS	16
#define DNS_RCODE_BADSIG	16
#define DNS_RCODE_BADKEY	17
#define DNS_RCODE_BADTIME	18
#define DNS_RCODE_BADMODE	19
#define DNS_RCODE_BADNAME	20
#define DNS_RCODE_BADALG	21
#define DNS_RCODE_BADTRUNC	22
#define DNS_RCODE_BADCOOKIE	23

#include <endian.h>
#include <stdint.h>
#include <strings.h>
#include <stdlib.h>
#include <stdio.h>
typedef struct {
    uint16_t length;
    uint16_t id;

    uint16_t rd:1; //Recursion Desired
    uint16_t tc:1; //was the received message truncated
    uint16_t aa:1; // meaningful just for response, shows if the authoritative ns is responding
    uint16_t opcode:4; //A four bit field that specifies kind of query in this message
    uint16_t qr:1; //query or request
    uint16_t rcode:4;
    /*
     * RCODEResponse code - this 4 bit field is set as part of responses.
     * The values have the followinginterpretation:
     * 0 No error condition
     * 1 Format error - The name server was unable to interpret the query.
     * 2 Server failure - The name server was unable to process this query due to a problem withthe name server.
     * 3 Name Error - Meaningful only for responses from an authoritative name server, this codesignifies that the domain name referenced in the query does not exist.
     * 4 Not Implemented - The name server does not support the requested kind of query.
     * 5 Refused - The name server refuses to perform the specified operation for policy reasons
     */
    uint16_t zero:3; // Reserved for future use
    uint16_t ra:1;//Recursion Available
    uint16_t qcount;	/* question count */
    uint16_t ancount;	/* Answer record count */
    uint16_t nscount;	/* Name Server (Autority Record) Count */
    uint16_t adcount;	/* Additional Record Count */
} dnshdr;
#include <ctype.h>

/* DNS QTYPES */
#define DNS_QTYPE_A		1
#define DNS_QTYPE_NS		2
#define DNS_QTYPE_CNAME		5
#define DNS_QTYPE_SOA		6
#define DNS_QTYPE_PTR		12
#define DNS_QTYPE_MX		15
#define DNS_QTYPE_TXT		16
#define DNS_QTYPE_RP		17
#define DNS_QTYPE_AFSDB		18
#define DNS_QTYPE_SIG		24
#define DNS_QTYPE_KEY		25
#define DNS_QTYPE_AAAA		28
#define DNS_QTYPE_LOC		29
#define DNS_QTYPE_SRV		33
#define DNS_QTYPE_NAPTR		35
#define DNS_QTYPE_KX		36
#define DNS_QTYPE_CERT		37
#define DNS_QTYPE_DNAME		39
#define DNS_QTYPE_OPT		41
#define DNS_QTYPE_APL		42
#define DNS_QTYPE_DS		43
#define DNS_QTYPE_SSHFP		44
#define DNS_QTYPE_IPSECKEY	45
#define DNS_QTYPE_RRSIG		46
#define DNS_QTYPE_NSEC		47
#define DNS_QTYPE_DNSKEY	48
#define DNS_QTYPE_DHCID		49
#define DNS_QTYPE_NSEC3		50
#define DNS_QTYPE_NSEC3PARAM	51
#define DNS_QTYPE_TLSA		52
#define DNS_QTYPE_HIP		55
#define DNS_QTYPE_CDS		59
#define DNS_QTYPE_CDNSKEY	60
#define DNS_QTYPE_TKEY		249
#define DNS_QTYPE_TSIG		250
#define DNS_QTYPE_IXFR		251
#define DNS_QTYPE_AXFR		252
#define DNS_QTYPE_ALL		255 /* AKA: * QTYPE */
#define DNS_QTYPE_URI		256
#define DNS_QTYPE_CAA		257
#define DNS_QTYPE_TA		32768
#define DNS_QTYPE_DLV		32769

/* DNS QCLASS */
#define DNS_QCLASS_RESERVED	0
#define DNS_QCLASS_IN		1
#define DNS_QCLASS_CH		3
#define DNS_QCLASS_HS		4
#define DNS_QCLASS_NONE		254
#define DNS_QCLASS_ANY		255

/*
	Function to change url to dns format
	For example: www.google.com would become:
	3www6google3com0
	size, can be used if you want to know the size of the returned pointer,
	because strlen reads until nullbyte and therefore doesnt include  qtype and qclass.
*/


char* qclass_to_string(uint16_t type){
    switch (type) {
        case DNS_QCLASS_IN:
            return "IN";
        case DNS_QCLASS_ANY:
            return "ANY";
        case DNS_QCLASS_CH:
            return "CH";
        case DNS_QCLASS_RESERVED:
            return "RESERVERD";
        case DNS_QCLASS_HS:
            return "HS";
        case DNS_QCLASS_NONE:
            return "NONE";
        default:
            return "INVALID";
    }

}

char* qtype_to_string(uint16_t type){
        switch (type){
            case DNS_QTYPE_A:
                return "A";
            case DNS_QTYPE_CNAME:
                return "CNAME";
            case DNS_QTYPE_AAAA:
                return "AAAA";
            case DNS_QTYPE_DNAME:
                return "DNAME";
            case DNS_QTYPE_MX:
                return "MX";
            case DNS_QTYPE_NS:
                return "NS";
            case DNS_QTYPE_SOA:
                return "SOA";
            case DNS_QTYPE_PTR:
                return "PTR";
            default:
                return "NOT SUPP YET";
        }
}


char* print_url(char*name){

    char *url = name;
    uint16_t t;
    t = htons(*((uint16_t* )url));
    if(t == 0xc00){
        printf("@\n");
        return 0;
    }

    while (*url){
        t = htons(*((uint16_t* )url));
        if(t == 0xc00c){
            printf("@\n");
            return 0;
        }
        char c = *url;
        if(isprint(c))
            printf("%c",c);
        else
            printf(".");
        url++;
        fflush(stdout);
    }
    printf("\n");

    return url+1;
}


char* print_url2(char*name){

    char *url = name;
    uint16_t t;
    t = htons(*((uint16_t* )url));
    if(t == 0xc000){
        printf("@\n");
        return 0;
    }

    while (*url){
        int tmp = (char)*url;
        url++;
        while (tmp){
            t = htons(*((uint16_t* )url));
            if(t == 0xc00c){
                printf("@\n");
                return 0;
            }
            char c = *url;
            if(isprint(c))
                printf("%c",c);
            else
                printf(".");
            url++;
            tmp--;
            fflush(stdout);
            if(*url == 0)
                break;
        }
        printf(".");
        fflush(stdout);
    }
    printf("\n");
    url++;

    return url+1;
}
struct question{
    unsigned short qtype;
    unsigned short qclass;
};
struct answer{
    uint16_t type;
    uint16_t _class;
    uint32_t ttl;
    uint16_t data_len;
};
#endif //NET_ANALYS_DNS_H
