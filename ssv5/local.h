

#ifndef _LOCAL_H
#define _LOCAL_H

#include <ev.h>
#include <libcork/ds.h>

#include "encrypt.h"
#include "jconf.h"
#include "common.h"
#include "tun.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct listen_ctx {
    ev_io io;
    char *iface;
    int remote_num;
    int method;
    int timeout;
    int fd;
    struct sockaddr **remote_addr;
} listen_ctx_t;

typedef struct server_ctx {
    ev_io io;
    int connected;
    struct server *server;
} server_ctx_t;

typedef struct server {
    int fd;
    buffer_t *buf;
    char stage;
    struct enc_ctx *e_ctx;
    struct enc_ctx *d_ctx;
    struct server_ctx *recv_ctx;
    struct server_ctx *send_ctx;
    struct listen_ctx *listener;
    struct remote *remote;

    struct cork_dllist_item entries;
} server_t;

typedef struct remote_ctx {
    ev_io io;
    ev_timer watcher;
    int connected;
    struct remote *remote;
} remote_ctx_t;

typedef struct remote {
    int fd;
    buffer_t *buf;
    int direct;
    struct remote_ctx *recv_ctx;
    struct remote_ctx *send_ctx;
    struct server *server;
    struct sockaddr_storage addr;
    int addr_len;
    uint32_t counter;
} remote_t;


#ifdef __cplusplus
}
#endif

#endif // _LOCAL_H
