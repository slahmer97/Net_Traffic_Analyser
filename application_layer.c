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

/**
 * @brief this is the main function which is used by all application parsers defined here
 *          in order to print ascii and hex dump of any data
 * @param padding  defines how much spaces to pad output with
 * @param input    defines data to be displayed
 * @param size     defined maximum length to be dumped
 *
 * @remarks : if size is not multiple of 16, this function will add null bytes in order
 *              to form the required shape!
 */
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

/**
 * @brief this function parses http messages.
 *        it's possible that this functions doesn't
 *        contain all messages defined in http RFC
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
        else if(strncmp(token,"Cache-control",13) == 0){
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
        else if(strncmp(token,"Content-Encoding",16) == 0){
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
/**
 * @brief this function parses smtp messages.
 *        it's possible that this functions doesn't
 *        contain all messages defined in smtp RFC
 */
void smtp_parser(const u_char* data,unsigned int len ){
    char *string =(char*) data;
    char * token = strtok(string, "\r\n");
    int rest = (int)len;
    while( token != NULL && rest > 0) {
        int k = 0;
        //printf("===> : %c %c %c\n",token[0],token[1],token[2]);
        if( '1'<=token[0] && token[0]<= '5' && '0'<=token[1] && token[1]<= '9' && '0'<=token[2] && token[2]<= '9'){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token, "HELO", 4) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token, "AUTH", 4) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token, "Username", 8) == 0){
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
        else if(strncmp(token, "From", 4) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token, "To", 2) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token, "Subject", 7) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token, "Date", 4) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token, "Message-ID", 10) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token, "MIME-Version", 12) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token, "Content-Type", 12) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token, "\tboundary", 9) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token, "X-Mailer", 8) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token, "Subject", 7) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token, "Thread-Index",12) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token, "Content-Language", 16) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token, "x-cr-hashedpuzzle", 17) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token, "x-cr-puzzleid", 13) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token, "Subject", 7) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token, "\tcharset", 8) == 0) {
            k = printf("%s%s\n", TWOSPACES, token) - (TWOSIZE + 1);
        }
        else if(strncmp(token, "Content-Transfer-Encoding",25) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }

        else
            goto data_found;

        rest -= k;
        token = strtok(NULL, "\r\n");
    }
    return;
    data_found:
        rest -=2;
        char* input;
        input = token;
        printf("DATA:\n");
        print_box_hex(TWOSPACES,input,rest);


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
/**
 * @brief this function parses pop3 messages.
 *        it's possible that this functions doesn't
 *        contain all messages defined in pop3 RFC
 */
void pop_parser(const u_char* data, unsigned int len){
    char *string =(char*) data;
    char * token = strtok(string, "\r\n");
    int rest =(int)len;
    while( token != NULL ) {
        int k;
        if(strncmp(token,"+OK",3) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token,"-ERR",4) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token,"QUIT",4) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token,"DELE",4) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token,"NOOP",4) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token,"CAPA",4) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token,"TOP",3) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token,"USER",4) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token,"PASS",4) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token,"APOP",4) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token,"UIDL",4) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token,"CAPA",4) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token,"STLS",4) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token,"SASL",4) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token,"PLAIN",5) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token,"IMPLEMENTATION",14) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token, ".\r\n", 3) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
            return;
        }
        else if(strncmp(token-5, "\r\n.\r\n", 5) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token, ".",1) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token, "AUTH",4) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token, "STAT",4) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token, "LIST",4) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token, "RETR",4) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token, "Return-Path",11) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token, "Delivery-Date",13) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token, "Received",8) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token, "DKIM-Signature",14) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token, "MIME-Version",12) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token, "To",2) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token, "From",4) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token, "Subject",7) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token, "Content-Type",12) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token, "X-Message-Id",12) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token, "Message-Id",10) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token, "Message-Id",10) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token, "Date",4) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token, "X-Provags-Id",12) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token, "xt/plain",8) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token, "Content-Transfer-Encoding",25) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token, "E-Version",9) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token, "X-OriginatorOrg",15) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token, "X-FOPE-CONNECTOR",16) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token, "Envelope-To",11) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token, "Delivered-To",10) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else
            goto data_found;
        rest -= k;
        rest -=2;
        token = strtok(NULL, "\r\n");
    }
    return ;
    data_found:
    rest -=2;
    char* input;
    input = token;
    printf("DATA:\n");
    print_box_hex(TWOSPACES,input,rest);
}

/**
 * @brief this function parses imap messages.
 *        it's possible that this functions doesn't
 *        contain all messages defined in imap RFC
 */
void imap_parser(const u_char*data,unsigned int len){
    char *string =(char*) data;
    char * token = strtok(string, "\r\n");
    int rest =(int)len;
    static int i=0;
    i++;
    while( token != NULL ) {
        int k;
        if(i == 9)
            printf(" ");
        if(strncmp(token,"Date",4) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
            goto last;
        }
        else if(strncmp(token,"From",4) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
            goto last;
        }
        else if(strncmp(token,"Subject",7) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
            goto last;
        }
        else if(strncmp(token,"To",2) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
            goto last;
        }
        else if(strncmp(token,"Message-ID",10) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
            goto last;
        }
        else if(strncmp(token,"Content-Type",12) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
            goto last;
        }
        else if(strncmp(token,"Reply-To",8) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
            goto last;
        }
        else if(strncmp(token,"\t",1) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
            goto last;
        }
        char* tmp = token;
        while (*(tmp++) != ' ');
        //tmp++;
        if(*tmp <= '9' && *(tmp)>=0){
            tmp++;
            while (*(tmp) <= '9' && *(tmp++) >= '0');
        }
        if(strncmp(tmp,"OK",2) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(tmp,"CAPABILITY",10) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(tmp,"LOGIN",5) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(tmp,"LIST",4) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(tmp,"SELECT",6) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(tmp,"LOGIN",5) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(tmp,"EXISTS",6) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(tmp,"RECENT",6) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(tmp,"FLAGS",5) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(tmp,"FETCH",5) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }


        else
            goto data_found;

        last:
        rest -= k;
        rest -=2;
        token = strtok(NULL, "\r\n");
    }
    return ;
    data_found:
    rest -=2;
    char* input;
    input = token;
    printf("DATA:\n");
    print_box_hex(TWOSPACES,input,rest);
}

/**
 * @brief this function parses FTP messages which are exchanged in control connection
 */
void ftp_parser(const u_char*data,unsigned int len) {
    char *string =(char*) data;
    char * token = strtok(string, "\r\n");
    int rest = (int)len;
    while( token != NULL && rest > 0) {
        int k = 0;
        //printf("===> : %c %c %c\n",token[0],token[1],token[2]);
        if( '1'<=token[0] && token[0]<= '5' && '0'<=token[1] && token[1]<= '9' && '0'<=token[2] && token[2]<= '9'){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token, "USER", 4) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token, "PASS", 4) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token, "SYST", 4) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token, "FEAT", 4) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token, "CLNT", 4) == 0 || strncmp(token+1, "CLNT", 4) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token, "MDTM", 4) == 0 || strncmp(token+1, "MDTM", 4) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token, "PASV", 4) == 0 || strncmp(token+1, "PASV", 4) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token, "REST", 4) == 0|| strncmp(token+1, "REST", 4) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token, "SIZE", 4) == 0 || strncmp(token+1, "SIZE", 4) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token, "FEAT", 4) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token, "PWD", 3) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token, "CWD", 3) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token, "TYPE", 4) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else if(strncmp(token, "RETR", 4) == 0){
            k = printf( "%s%s\n",TWOSPACES,token ) - (TWOSIZE+1);
        }
        else
            goto data_found;

        rest -= k;
        token = strtok(NULL, "\r\n");
    }
    return;
    data_found:
    rest -=2;
    char* input;
    input = token;
    printf("DATA:\n");
    print_box_hex(TWOSPACES,input,rest);
}

void telnet_parser(const u_char*data,unsigned int len) {

    if (data[0] != IAC) {
        print_box_hex(THREESPACES, (const char *) data, (int) len);
        return;
    }
    int i;
    for (i = 0; i <(int)len; ++i) {
        unsigned char c = data[i];
        if(c == IAC){
            printf( "%s[+] ",TWOSPACES);
            i++;
            unsigned char next_c = data[i];
            switch (next_c){
                case WILL:
                    fprintf(stdout,"WILL ");
                    goto one_arg;
                case WILL_NOT:
                    fprintf(stdout,"WON'T ");
                    goto one_arg;
                case DO:
                    fprintf(stdout,"DO ");
                    goto one_arg;
                case DO_NOT:
                    fprintf(stdout,"DON'T ");
                    goto one_arg;
                case SB:
                    fprintf(stdout,"SUBOPT ");
                    goto two_args;
                case SE:
                    fprintf(stdout,"SUBOPTEND");
                    break;
                case GO_AHEAD:
                    fprintf(stdout,"GO AHEAD ");
                    goto one_arg;
                case ERASE_LINE:
                    fprintf(stdout,"ERASE LINE ");
                    goto one_arg;
                case ERASE_CHARACTER:
                    fprintf(stdout,"ERASE CHARACTER");
                    goto one_arg;
                case ARE_YOU_THERE:
                    fprintf(stdout,"ARE YOU THERE ");
                    goto one_arg;
                case ABORT_OUTPUT:
                    fprintf(stdout,"ABORT OUTPUT ");
                    goto one_arg;
                case INTERRUPT_PROCESS:
                    fprintf(stdout,"INTERRUPT PROCESS");
                    goto one_arg;
                case BREAK:
                    fprintf(stdout,"BREAK ");
                    break;
                case DATA_MARK:
                    fprintf(stdout,"DATA MARK ");
                    goto one_arg;
                case NOP:
                    fprintf(stdout,"NO OPERATION ");
                    break;
                default:
                    fprintf(stdout,"COMMAND IS NOT RECOGNIZED");

            }

        }

        end_loop:
        printf("\n");
    }

    return;

    one_arg:
    i++;
    unsigned char tmp = data[i];
    switch (tmp){
        case ECHO:
            fprintf(stdout,"ECHO ");
            break;
        case GO_AHEAD:
            fprintf(stdout,"GO AHEAD ");
            break;
        case TERMINAL_TYPE:
            fprintf(stdout,"TERMINAL TYPE ");
            break;
        case WINDOW_SIZE:
            fprintf(stdout,"WINDOW SIZE ");
            break;
        case TERMINAL_SPEED:
            fprintf(stdout,"TERMINAL SPEED ");
            break;
        case REMOTE_FLOW_CONTROL:
            fprintf(stdout,"REMOTE FLOW CONTROL ");
            break;
        case LINE_MODE:
            fprintf(stdout,"LINE MODE ");
            break;
        case X_ENVIRONMENT_OPTION:
            fprintf(stdout,"NEW ENVIREMENT OPTION ");
            break;
        case STATUS:
            fprintf(stdout,"STATUS ");
            break;
        case X_DISPLAY_LOCATION:
            fprintf(stdout,"X-DISPLAY LOCATION ");
            break;

        case SUPPRESS_GO_AHEAD:
            fprintf(stdout,"SUPPRESS GO AHEAD ");
            break;
        case ENVIRONMENT_VARIABLES:
            fprintf(stdout,"ENVIREMENT VARIABLE ");
            break;
        case ENCRYPTION_OPTION:
            fprintf(stdout,"ENCRYPTION OPTION ");
            break;
        case AUTHENTICATION_OPTION:
            fprintf(stdout,"AUTHENTIFICATION OPTION ");
            break;
        case TIMING_MARK:
            fprintf(stdout,"TIMING MARKER");
            break;
    }
    goto end_loop;

    two_args:
        i++;
        i++;
        goto end_loop;

}
void ftp_data_parser(const char* data,unsigned int data_len){
    print_box_hex(THREESPACES,data,(int)data_len);
}