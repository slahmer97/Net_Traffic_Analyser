//
// Created by sidahmedlahmer on 10/2/19.
//

#include <zconf.h>

#ifndef NETWORK_ANA_APPLICATION_LAYER_H
#define NETWORK_ANA_APPLICATION_LAYER_H

#define IAC 255
#define DO_NOT 254
#define DO 253
#define WILL_NOT 252
#define WILL 251
#define SB 250
#define SE 240
#define GO_AHEAD 249
#define ERASE_LINE 248
#define ERASE_CHARACTER 247
#define ARE_YOU_THERE 246
#define ABORT_OUTPUT 245
#define INTERRUPT_PROCESS 244
#define BREAK 243
#define DATA_MARK 242
#define NOP 241




#define SUPPRESS_GO_AHEAD 3
#define ENVIRONMENT_VARIABLES 36
#define ECHO 1
#define ENCRYPTION_OPTION 38
#define STATUS 5
#define AUTHENTICATION_OPTION 37
#define WINDOW_SIZE 31
#define TERMINAL_SPEED 32
#define REMOTE_FLOW_CONTROL 33
#define TIMING_MARK 6
#define TERMINAL_TYPE 24
#define LINE_MODE 34
#define X_DISPLAY_LOCATION 35
#define X_ENVIRONMENT_OPTION 39

void http_parser(const u_char* data,unsigned int);
void smtp_parser(const u_char* data,unsigned int);
void dns_parser(const u_char*  data, unsigned int);
void pop_parser(const u_char* data, unsigned int);
void imap_parser(const u_char*data, unsigned int);
void ftp_parser(const u_char*data,unsigned int );
void telnet_parser(const u_char*data,unsigned int );


#endif //NETWORK_ANA_APPLICATION_LAYER_H
