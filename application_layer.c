//
// Created by sidahmedlahmer on 10/2/19.
//

#include <stdio.h>
#include "application_layer.h"
#include "includes.h"
#include <string.h>
#include "dns.h"
#include <ctype.h>
#include <stdlib.h>
static void print_box_hex(const char*padding,const char*input,int size){
    //printf("size : %d\n",size);
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
/*
static void printf_ray_hex(const u_char *padding,const u_char* txt,int len){
    printf("%s",padding);
    int space = len;
    for (int i = 0; i < len ; ++i) {
        u_char c = txt[i];
        if(c == '\n' || c=='\r' || c == '\t' || c == 0)
            c = '.';
        if(c == 4)
            space = i;
        if(i < space)
            printf("%c",c);
        else
            printf(" ");
    }
    printf("\t");
    for (int i = 0; i < len ; ++i) {
        u_char c = txt[i];
        if(i < space){
             if(c < 15)
                printf("0%x ",c);
             else
                printf("%x ",c);
        }
        else
            printf(" ");

    }
    printf("\n");

}
 */
void http_parser(const u_char* data, unsigned int len){
    len++;
    len--;

    char *string =(char*) data;
    char * token = strtok(string, "\r\n");
    int rest =(int)len;
    while( token != NULL ) {
        //printf( "%s%s\n",TWOSPACES,token ); //printing each token
        int k;
        if(strncmp(token,"HTTP",4) == 0){
            //Response Server->Client
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token,"GET",3) == 0 || strncmp(token,"HEAD",4) == 0 || strncmp(token,"POST",4) == 0 ||
                strncmp(token,"PUT",3) == 0 || strncmp(token,"DELETE",6) == 0 || strncmp(token,"TRACE",5) == 0 ||
                strncmp(token,"CONNECT",7) == 0 ){
            //Request Client->Server
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token,"Host",4) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token,"Content-Length",14) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token,"Content-Type",12) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token,"Last-Modified",13) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token,"Accept-Charset",14) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token,"Accept-Encoding",15) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token,"Authorization",13) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token,"Expect",6) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token,"Accept-Language",15) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token,"P3P",3) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token,"From",4) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token,"X-Powered-By",12) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token,"Cache-Expires",13) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token,"X-UA-Compatible",15) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token,"Cache-Control",13) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token,"Connection",10) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token,"User-Agent",10) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token,"Accept",6) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token,"Keep-Alive",10) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token,"Referer",7) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token,"If-Match",8) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token,"If-Modified-Since",17) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token,"If-None-Match",13) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token,"If-Range",8) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token,"If-Unmodified-Since",19) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token,"Max-Forwards",12) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token,"Proxy-Authorization",19) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token,"TE",2) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token,"If-Unmodified-Since",19) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token,"Accept-Ranges",13) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token,"Age",3) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token,"ETag",4) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token,"Location",8) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token,"Proxy-Authenticate",18) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token,"Retry-After",11) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token,"Server",6) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token,"Vary",4) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token,"WWW-Authenticate",16) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token,"Via",3) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token,"Date",4) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token,"Cookie",6) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token,"Set-Cookie",10) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token,"Pragma",6) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token,"X-C",3) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token,"Cache-Control",13) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token,"Expires",7) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token,"xserver",7) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token,"Transfer-Encoding",17) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token,"x-flash-version",15) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token,"x-amz-id-2",10) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token,"x-amz-request-id",16) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }


        else
            goto data_found;
        rest -= k;
        rest -=2;
        token = strtok(NULL, "\r\n");
    }
    printf("###############rest : %d\n",rest);
    return ;

    data_found:
    rest -=2;
    char* input;
    input = token;
    printf("DATA:\n");
    print_box_hex(TWOSPACES,input,rest);
    /*
    for (int i=0;input[i] != 0;i += 16){
       printf_ray_hex((const u_char *)TWOSPACES,(const u_char *)&input[i],20);

    }
     */
}

void smtp_parser(const u_char* data,unsigned int len ){
    char *string =(char*) data;
    char * token = strtok(string, "\r\n");
    int rest = (int)len;
    while( token != NULL && rest > 0) {
        int k = 0;
        if(strncmp(token, "HELO", 4) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token, "MAIL FROM:", 10) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);

        }
        else if(strncmp(token, "EHLO", 4) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);

        }
        else if(strncmp(token, "RCPT TO:", 8) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);

        }
        else if(strncmp(token, "DATA", 4) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);

        }
        else if(strncmp(token, ".\r\n", 3) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);

        }
        else if(strncmp(token-5, "\r\n.\r\n", 5) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);

        }
        else if(strncmp(token, "QUIT", 4) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else {
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }

        rest -= k;
        token = strtok(NULL, "\r\n");
    }


}

void dns_parser(const u_char*  data,unsigned int len){
    len++;
   // print_box_hex("-->   ",(const char*)data,16);
    //return;
    dnshdr* dnsHeader = (dnshdr*)data;
    int transaction_id = htons(dnsHeader->id);
    int is_query = (htons(!dnsHeader->qr));
    int op_code = htons(dnsHeader->opcode);
    int question_count = htons(dnsHeader->qcount);
    int answer_count = htons(dnsHeader->ancount);
    int ns_count = htons(dnsHeader->nscount);
    int add_records_count = htons(dnsHeader->adcount);
    fprintf(stdout,"%s[..] Transaction ID         : 0x%x\n",THREESPACES,transaction_id);
    fprintf(stdout,"%s[..] Message is             : %s\n",THREESPACES,is_query?"Query":"Answer");
    fprintf(stdout,"%s[..] Opcode                 : 0x%x\n",THREESPACES,op_code);
    fprintf(stdout,"%s[..] Truncated              : Message is%s truncated\n",THREESPACES,(dnsHeader->tc >= 1)?"":" NOT");
    fprintf(stdout,"%s[..] Recursion Desired      : Do%s query recursively\n",THREESPACES,(dnsHeader->rd >= 1)?"":" NOT");
    fprintf(stdout,"%s[..] Reserved               : 0x%x\n",THREESPACES,(dnsHeader->zero ));
    fprintf(stdout,"%s[..] Non-Autheritative Data : %sacceptable\n",THREESPACES,(dnsHeader->aa >= 1)?"":" Un");

    fprintf(stdout,"%s[..] Questions Count        : 0x%x\n",THREESPACES,question_count);
    fprintf(stdout,"%s[..] Answer Count           : 0x%x\n",THREESPACES,answer_count);
    fprintf(stdout,"%s[..] NamedS Rec Count       : 0x%x\n",THREESPACES,ns_count);
    fprintf(stdout,"%s[..] Additional Rec Count   : 0x%x\n",THREESPACES,add_records_count);
    fprintf(stdout,"%s[..]---------------------------------\n",THREESPACES);

    char * input = (char*)&data[sizeof(dnshdr)];

    char * url = input;
    while (question_count-->0){
        int qlen = strlen(url)+1;
        url = input;
        struct question* quest = (struct question* )&url[qlen];
        fprintf(stdout,"%s[..] Question Hex  -> \n",THREESPACES);
        print_box_hex(EXTRASPACES,(const char*)quest,16);
        fprintf(stdout,"%s[..] Question Url    : ",THREESPACES);
        print_url2(url);
        url =(char*)(sizeof(struct question)+(char*)quest);
        fprintf(stdout,"%s[..] Question Type   : %s\t[0x%04x]\n",THREESPACES,qtype_to_string(htons(quest->qtype)),htons(quest->qtype));
        fprintf(stdout,"%s[..] Question Class  : %s\t[0x%04x]\n",THREESPACES,qclass_to_string(htons(quest->qclass)),htons(quest->qclass));
        question_count--;
        fprintf(stdout,"%s[..]---------------------------------\n",THREESPACES);
    }
    //url++;
    while (answer_count-- > 0){
        int qlen = strlen(url);
        struct answer* answer = (struct answer* )&url[qlen];
        //print_box_hex(THREESPACES,(char*)answer,16);

        //fprintf(stdout,"\n%s[..] Answer        : ",THREESPACES);
        //print_url(url);
        uint16_t type = htons(answer->type);
        uint16_t class = htons(answer->_class);
        uint16_t data_len = htons(answer->data_len);
        uint16_t  ttl = htonl(answer->ttl);
        //print_box_hex("--> ",url,16);
        fprintf(stdout,"%s[..] Answer Type   : %s\t[0x%04x]\n",THREESPACES,qtype_to_string(type),type);
        fprintf(stdout,"%s[..] Answer class  : %s\t[0x%04x]\n",THREESPACES,qclass_to_string(class),class);
        fprintf(stdout,"%s[..] Answer len    : %d\n",THREESPACES,data_len);
        fprintf(stdout,"%s[..] Answer ttl    : %d\n",THREESPACES,ttl);
        fprintf(stdout,"%s[..] Answer Hex    : \n",THREESPACES);
        print_box_hex(EXTRASPACES,(char*)answer+sizeof(struct answer)-2,data_len);
        fprintf(stdout,"%s[--]---------------------------------\n",THREESPACES);

        url =(char*)answer+sizeof(struct answer)+data_len;

    }


    //fprintf(stdout,"%sDNS :  %s\n",TWOSPACES,data);
}
