
#ifndef SPECUID_CLIENT_TUN_H
#define SPECUID_CLIENT_TUN_H

#include <ev.h>
#include <stdio.h>
#include <uthash.h>

#include "encrypt.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int src_port; // as a key

    uint32_t dst_ip;
    int dst_port;

    UT_hash_handle hh;
}routes_t;

typedef struct {
    ev_io       io;
    int         fd;
    buffer_t    *buf;
    int         local_address;
    uint16_t    local_port;
}tun_ctx_t;

void tun_read_cb(EV_P_ ev_io *w, int revents);

#ifdef __cplusplus
}
#endif

#endif //SPECUID_CLIENT_TUN_H
