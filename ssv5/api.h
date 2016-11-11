
#include <jni.h>
#include <stdint.h>

#include "tun.h"

#ifndef _API_H
#define _API_H

typedef struct {
    /*  Required  */
    char *remote_host;    // hostname or ip of remote server
    char *local_addr;     // local ip to bind
    char *method;         // encryption method
    char *password;       // password of remote server
    int remote_port;      // port number of remote server
    int local_port;       // port number of local server
    int timeout;          // connection timeout

    /*  Optional, set NULL if not valid   */
    char *acl;            // file path to acl
    char *log;            // file path to log
    int fast_open;        // enable tcp fast open
    int mode;             // enable udp relay
    int auth;             // enable one-time authentication
    int verbose;          // verbose mode
} profile_t;

#ifdef __cplusplus
extern "C" {
#endif

int start_vpn(int tunfd, profile_t profile);
void stop_vpn();

#ifdef __cplusplus
}
#endif

#endif // _API_H
