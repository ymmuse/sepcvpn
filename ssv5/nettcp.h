
#ifndef SPECUID_CLIENT_NETTCP_H
#define SPECUID_CLIENT_NETTCP_H

#include <ev.h>
#include <stdio.h>
#include <netinet/in.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    ev_io       io;
    FILE        *fp;
}nettcp4_ctx_t;


typedef struct {
       unsigned int protocol;  /*!< IPv4 protocol */
       struct in6_addr ip_src; /*!< Local address IPv4 */
       unsigned short port_src;      /*!< Local address port */
       struct in6_addr ip_dst; /*!< Remote address IPv4 */
       unsigned short port_dst;      /*!< Remote address port */
       unsigned long uid;      /*!< User identifier */
       unsigned long inode;    /*!< Inode */
       unsigned int retransmit;      /*!< Retransmit */
       time_t createtime;      /*!< Creation time (Epoch format) */
} nettcp_conn_t;

void nettcp4_read_cb(EV_P_ ev_io *w, int revents);

#ifdef __cplusplus
}
#endif

#endif //SPECUID_CLIENT_NETTCP_H
