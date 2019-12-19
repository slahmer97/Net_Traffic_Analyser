//
// Created by sidahmedlahmer on 10/2/19.
//

#include <stdio.h>
#include "application_layer.h"
#include "includes.h"
#include <string.h>

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
void http_parser(const u_char* data, unsigned int len){
    len++;
    len--;
    char *string =(char*) data;
    char * token = strtok(string, "\r\n");
    while( token != NULL ) {
        //printf( "%s%s\n",TWOSPACES,token ); //printing each token
        token = strtok(NULL, "\r\n");
        if(strncmp(token,"HTTP",4) == 0){
            printf( "%s%s\n",TWOSPACES,token ); //printing each token
        }
        if(strncmp(token,"GET",3) == 0){
            printf( "%s%s\n",TWOSPACES,token ); //printing each token
        }
        if(strncmp(token,"POST",4) == 0){
            printf( "%s%s\n",TWOSPACES,token ); //printing each token
        }
        else if(strncmp(token,"Content-Length",14) == 0){
            printf( "%s%s\n",TWOSPACES,token ); //printing each token
        }
        else if(strncmp(token,"Content-Type",12) == 0){
            printf( "%s%s\n",TWOSPACES,token ); //printing each token
        }
        else if(strncmp(token,"Last-Modified",13) == 0){
            printf( "%s%s\n",TWOSPACES,token ); //printing each token
        }
        else if(strncmp(token,"Accept-Ranges",13) == 0){
            printf( "%s%s\n",TWOSPACES,token ); //printing each token
        }
        else if(strncmp(token,"ETag",4) == 0){
            printf( "%s%s\n",TWOSPACES,token ); //printing each token
        }
        else if(strncmp(token,"Server",6) == 0){
            printf( "%s%s\n",TWOSPACES,token ); //printing each token
        }
        else if(strncmp(token,"P3P",3) == 0){
            printf( "%s%s\n",TWOSPACES,token ); //printing each token
        }
        else if(strncmp(token,"From",4) == 0){
            printf( "%s%s\n",TWOSPACES,token ); //printing each token
        }
        else if(strncmp(token,"X-Powered-By",12) == 0){
            printf( "%s%s\n",TWOSPACES,token ); //printing each token
        }
        else if(strncmp(token,"Cache-Expires",13) == 0){
            printf( "%s%s\n",TWOSPACES,token ); //printing each token
        }
        else if(strncmp(token,"X-UA-Compatible",15) == 0){
            printf( "%s%s\n",TWOSPACES,token ); //printing each token
        }
        else if(strncmp(token,"Cache-Control",13) == 0){
            printf( "%s%s\n",TWOSPACES,token ); //printing each token
        }
        else if(strncmp(token,"Date",4) == 0){
            printf( "%s%s\n",TWOSPACES,token ); //printing each token
        }
        else if(strncmp(token,"Connection",10) == 0){
            printf( "%s%s\n",TWOSPACES,token ); //printing each token
        }
        else
            goto data_found;
    }
    return ;

    char* input;
    data_found:
    input = token;
    printf("DATA:\n");
    for (int i=0;input[i] != 0;i += 16){
        printf_ray_hex((const u_char *)TWOSPACES,(const u_char *)&input[i],20);
    }
}

void smtp_parser(const u_char* data,unsigned int len ){
    int rest = (int)len;
    //fprintf(stdout,"%s[..] Data \n",TWOSPACES,len);

    char *string =(char*) data;
    char* last = string;
    char * token = strtok(string, "\r\n");
    while( token != NULL && rest > 0) {
        printf( "%s%s\n",TWOSPACES,token ); //printing each token

        last = token;
        rest -= (int) (token - last);
        token = strtok(NULL, "\r\n");

    }


}
/*
void dns_parser(const u_char*  data){
    fprintf(stdout,"%s[..] Data : %s\n",TWOSPACES,data);
}
*/