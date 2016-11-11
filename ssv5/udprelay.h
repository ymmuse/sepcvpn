
#ifndef _UDPRELAY_H
#define _UDPRELAY_H

#include <ev.h>
#include <time.h>

#include "encrypt.h"
#include "jconf.h"

#ifdef MODULE_REMOTE
#include "resolv.h"
#endif

#include "cache.h"

#include "common.h"

#define MAX_UDP_PACKET_SIZE (65507)

#define MTU 1397 // 1492 - 1 - 28 - 2 - 64 = 1397, the default MTU for UDP relay

typedef struct server_ctx {
    ev_io io;
    int fd;
    int method;
    int auth;
    int timeout;
    const char *iface;
    struct cache *conn_cache;
#ifdef MODULE_LOCAL
    const struct sockaddr *remote_addr;
    int remote_addr_len;
#ifdef MODULE_TUNNEL
    ss_addr_t tunnel_addr;
#endif
#endif
#ifdef MODULE_REMOTE
    struct ev_loop *loop;
#endif
} server_ctx_t;

#ifdef MODULE_REMOTE
typedef struct query_ctx {
    struct ResolvQuery *query;
    struct sockaddr_storage src_addr;
    buffer_t *buf;
    int addr_header_len;
    char addr_header[384];
    struct server_ctx *server_ctx;
    struct remote_ctx *remote_ctx;
} query_ctx_t;
#endif

typedef struct remote_ctx {
    ev_io io;
    ev_timer watcher;
    int af;
    int fd;
    int addr_header_len;
    char addr_header[384];
    struct sockaddr_storage src_addr;
    struct server_ctx *server_ctx;
} remote_ctx_t;

#endif // _UDPRELAY_H
