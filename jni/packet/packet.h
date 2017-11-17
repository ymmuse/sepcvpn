
#include <stdint.h>

#ifndef SPECUID_CLIENT_PACKET_H
#define SPECUID_CLIENT_PACKET_H

typedef struct {
    //	unsigned char preamble[7];
    //	unsigned char delimiter;

    unsigned char destAddress[6];
    unsigned char srcAddress[6];
    // if value < 1500(max allowed frame size); specifies length - ver802.2
    // else value > 1536; specifies which protocol is encapsulated in the payload - Ethernet II framing
    unsigned char etherType[2];
}ethernet_t;

typedef struct
{
    /*need these to compute packet lengths*/
    uint8_t v_ihl; //internet header length
    uint8_t service; //Type of service - used to define the way routers handle the datagram
    uint16_t total_len; //16 bits, max packet size - 2^16 - 65,536

    uint16_t identification; //Used along with src address to uniquely id a datagram
    uint16_t offset; // 00000xxx {Reserved = 0, Don't Fragment, Fragment} 00000000
    uint8_t ttl; //no. of hops
    uint8_t protocol; //http://bit.ly/c0xBMt list of ip protocols
    uint16_t checksum;
    uint32_t srcAddress;
    uint32_t  destAddress;
}ip_t;

typedef  struct {
    uint16_t src_port;
    uint16_t dest_port;
    uint32_t seq_num;
    uint32_t ack;
    uint16_t offset_res_flag;
    uint16_t window_size;
    uint16_t check_sum;
    uint16_t urgent;
    uint32_t option;		//this char just indicates the first 4 bytes of the optional section. We me need to have a
}tcp_t;

#define IP_ADDRESS(a, b, c, d)	((a) | (b) << 8 | (c) << 16 | (d) << 24)
//! Get the 1st most significant byte of a host-format IP address.
#define IP_A(ip)		((uint8_t) ((ip) >> 24))
//! Get the 2nd most significant byte of a host-format IP address.
#define IP_B(ip)		((uint8_t) ((ip) >> 16))
//! Get the 3rd most significant byte of a host-format IP address.
#define IP_C(ip)		((uint8_t) ((ip) >>  8))
//! Get the less significant byte of a host-format IP address.
#define IP_D(ip)		((uint8_t) ((ip) >>  0))

#define IPVer(P) (P->v_ihl >> 4)
#define IPHeaderLength(P) ((P->v_ihl & 0x0f)*4)

uint16_t ip_checksum(const void *buf, size_t hdr_len);
uint16_t tcp_checksum(const void *buff, size_t len, uint32_t src_addr, uint32_t dest_addr);

#endif //SPECUID_CLIENT_PACKET_H
