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

unsigned char* dns_format ( char *url, int *size, unsigned short int qtype, unsigned short int qclass )
{
    int i, c = 0, len = strlen(url);
    char *buf = (char *) malloc(len+6);

    buf[len+1] = 0;
    for(i=len;i>=0;i--){
        if(url[i] == '.') {
            buf[i+1] = c;
            c = 0;
        }
        else {
            buf[i+1] = url[i];
            c++;
        }
    }
    buf[0] = c;

    uint16_t* qt = (uint16_t *) (buf + len + 2);
    *qt = qtype;
    uint16_t* qc = (uint16_t *) (buf + len + 4);
    *qc = qclass;

    if(size) *size = len+6;
    return (unsigned char*)buf;
}

u_char* dns_to_url(unsigned char* reader,unsigned char* buffer,int* count)
{
    unsigned char *name;
    unsigned int p=0,jumped=0,offset;
    int i , j;

    *count = 1;
    name = (unsigned char*)malloc(256);

    name[0]='\0';

    //read the names in 3www6google3com format
    while(*reader!=0)
    {
        if(*reader>=192)
        {
            offset = (*reader)*256 + *(reader+1) - 49152; //49152 = 11000000 00000000 ;)
            reader = buffer + offset - 1;
            jumped = 1; //we have jumped to another location so counting wont go up!
        }
        else
        {
            name[p++]=*reader;
        }

        reader = reader+1;

        if(jumped==0)
        {
            *count = *count + 1; //if we havent jumped to another location then we can count up
        }
    }

    name[p]='\0'; //string complete
    if(jumped==1)
    {
        *count = *count + 1; //number of steps we actually moved forward in the packet
    }

    //now convert 3www6google3com0 to www.google.com
    for(i=0;i<(int)strlen((const char*)name);i++)
    {
        p=name[i];
        for(j=0;j<(int)p;j++)
        {
            name[i]=name[i+1];
            i=i+1;
        }
        name[i]='.';
    }
    name[i-1]='\0'; //remove the last dot
    return name;
}

char* print_url(char*url){

    while (*url){
        if(isprint(*url))
            printf("%c",*url);
        else
            printf(".");
        url++;
    }
    printf("\n");
    return 0;
    short t = *((short*)url);
    //printf("%x",t);
    if(t == 0xcc0){
       printf("@\n");
        return url+1; //c00c+00

    }
    while (*url){
        int tmp = (int)*url;
        url++;
        while (tmp--){
            t = *((short*)url);
            if(t ==  0xcc0){
                printf("@\n");
                return url+1; //c00c+00
            }
            printf("%c",*(url++));
            fflush(stdout);
        }
        printf(".");
        fflush(stdout);
    }
    printf("\n");
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
