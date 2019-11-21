//
// Created by sidahmedlahmer on 10/2/19.
//

#include <stdio.h>
#include "application_layer.h"
#include "includes.h"
#include <string.h>
void http_parser(const u_char* data, unsigned int len){
    unsigned text_index = 0;
    char* input = (char*)data;
    printf("%s",TWOSPACES);
    if(strncmp((const char*)data,"HTTP",4) == 0 || strncmp((const char*)data,"POST",4) == 0 || strncmp((const char*)data,"GET",3) == 0 ){
        while (text_index < len){
            while(*input != '\r' && *(input+1) != '\n'){
                printf("%c",*input++);
                text_index++;
                fflush(stdout);
            }
            text_index +=2;
            input +=2;
            printf("\n%s",TWOSPACES);
            fflush(stdout);
        }
    }





    //fprintf(stdout,"%s[..] Data : %c%c%c%c%c\n",THREESPACES,data[0],data[1],data[2],data[3],data[4]);
}
/*
void smtp_parser(const u_char* data){
    fprintf(stdout,"%s[..] Data : %s\n",TWOSPACES,data);


}
void dns_parser(const u_char*  data){
    fprintf(stdout,"%s[..] Data : %s\n",TWOSPACES,data);
}
*/