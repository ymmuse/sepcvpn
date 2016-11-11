
#ifndef _NETUTILS_H
#define _NETUTILS_H

size_t get_sockaddr_len(struct sockaddr *addr);
size_t get_sockaddr(char *host, char *port, struct sockaddr_storage *storage, int block);
int set_reuseport(int socket);

#endif
