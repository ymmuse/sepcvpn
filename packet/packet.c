
#include "packet.h"
#include "utils.h"
#include <netinet/in.h>

uint16_t ip_checksum(const void *buf, size_t hdr_len)
{
    unsigned long sum = 0;
    const uint16_t *ip1;

    ip1 = buf;
    while (hdr_len > 1)
    {
        sum += *ip1++;
        if (sum & 0x80000000)
            sum = (sum & 0xFFFF) + (sum >> 16);
        hdr_len -= 2;
    }

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return(~sum);
}

uint16_t tcp_checksum(const void *buff, size_t len, uint32_t src_addr, uint32_t dest_addr)
{
    const uint16_t *buf=buff;
    uint16_t *ip_src=(void *)&src_addr, *ip_dst=(void *)&dest_addr;
    uint32_t sum;
    size_t length=len;

    // Calculate the sum						//
    sum = 0;
    while (len > 1)
    {
        sum += *buf++;
        if (sum & 0x80000000)
            sum = (sum & 0xFFFF) + (sum >> 16);
        len -= 2;
    }

    if ( len & 1 )
        // Add the padding if the packet lenght is odd		//
        sum += *((uint8_t *)buf);

    // Add the pseudo-header					//
    sum += *(ip_src++);
    sum += *ip_src;
    sum += *(ip_dst++);
    sum += *ip_dst;
    sum += htons(IPPROTO_TCP);
    sum += htons(length);

    // Add the carries						//
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    // Return the one's complement of sum				//
    return ( (uint16_t)(~sum)  );
}
