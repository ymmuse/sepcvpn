
#include <stdio.h>
#include <uthash.h>
#include <netinet/in.h>
#include <unistd.h>

#include "common.h"
#include "utils.h"
#include "../packet/packet.h"
#include "tun.h"
#include "api.h"

extern routes_t *g_tun_routes;

void tun_read_cb(EV_P_ ev_io *w, int revents)
{
    tun_ctx_t *tun_ctx = (tun_ctx_t*)w;
    buffer_t *buf = tun_ctx->buf;

    ssize_t readn = read(tun_ctx->fd, buf->array, buf->capacity); 
    if (readn <= 0) {
        return;
    }
    
    ip_t *packet = (ip_t*)buf->array;

    if (IPVer(packet) != 4) {
        LOGD("not support ipv6");
        return;
    }

    if (packet->protocol != 0x06) {
        LOGD("not support protocol: %d", packet->protocol);
        return;
    }

    if (packet->srcAddress != tun_ctx->local_address) {
        return;
    }

    tcp_t *tcp_header = (tcp_t*)(buf->array+IPHeaderLength(packet));

    uint32_t src_ip, dst_ip;
    int src_port, dst_port;

    src_ip = packet->srcAddress;
    dst_ip = packet->destAddress;
    src_port = tcp_header->src_port;
    dst_port = tcp_header->dest_port;
    
    uint8_t checksum_write_back = 0;
    if (ntohs(src_port) == tun_ctx->local_port) {
        routes_t *routes;
        HASH_FIND_INT(g_tun_routes, &dst_port, routes);
        if (routes != NULL) {
            packet->destAddress = tun_ctx->local_address;
            
            packet->srcAddress = routes->dst_ip;
            tcp_header->src_port = routes->dst_port;
            
            checksum_write_back = 1;
        } else {
            LOGI("never execute to here ):");
        }
    } else {
        routes_t *routes = NULL;
        HASH_FIND_INT(g_tun_routes, &src_port, routes);
        if (routes == NULL || routes->dst_ip != dst_ip || routes->dst_port != dst_port) {
            if (routes != NULL) {
                LOGD("store replace port %d", ntohs(src_port));
                HASH_DEL(g_tun_routes, routes);
                free(routes);
            } 
            
            routes = malloc(sizeof(routes_t));
            routes->src_port = src_port;
            routes->dst_ip = dst_ip;
            routes->dst_port = dst_port;
            HASH_ADD_INT(g_tun_routes, src_port, routes);
        }

        packet->srcAddress = packet->destAddress;
        tcp_header->src_port = src_port;
        
        packet->destAddress = tun_ctx->local_address;
        tcp_header->dest_port = htons(tun_ctx->local_port);
        
        checksum_write_back = 1;
    }
    
    if (checksum_write_back) {
        packet->checksum = 0;
        tcp_header->check_sum = 0;

        packet->checksum = ip_checksum((const void*)packet, IPHeaderLength(packet));
        tcp_header->check_sum = tcp_checksum((const void*)tcp_header, (ntohs(packet->total_len) - IPHeaderLength(packet)),
                                             packet->srcAddress, packet->destAddress);
        write(tun_ctx->fd, buf->array, readn);
    }
}
