//
// Created by sidahmedlahmer on 10/2/19.
//

#include <stdio.h>
#include "application_layer.h"
#include "includes.h"
#include <string.h>

static void print_box_hex(const char*padding,const char*input,int size){
    int i = 0;
    for (; i <size ;) {
        printf("%s",padding);
        int k = i;
        for (int j = 0; j < 16; ++j,i++) {
            char c = input[i];
            if(c == '\n' || c=='\r' || c == '\t' || c == 0 || i >= size)
                c = '.';
            printf("%c",c);
        }
        i = k;
        printf("\t");
        for (int j = 0; j < 16; ++j,i++) {
            char c = input[i];
            if(i >= size)
              printf("00 ");
            else{
                if(c < 15)
                    printf("0%x ",c);
                else
                    printf("%x ",c);
            }
        }
        printf("\n");
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
        else if(strncmp(token,"Date",4) == 0){
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
/*
void dns_parser(const u_char*  data){
    fprintf(stdout,"%s[..] Data : %s\n",TWOSPACES,data);
}
*/