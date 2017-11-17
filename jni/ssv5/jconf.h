

#ifndef _JCONF_H
#define _JCONF_H

#define MAX_PORT_NUM 1024
#define MAX_REMOTE_NUM 10
#define MAX_CONF_SIZE 128 * 1024
#define MAX_DNS_NUM 4
#define MAX_CONNECT_TIMEOUT 10
#define MIN_UDP_TIMEOUT 10

typedef struct {
    char *host;
    char *port;
} ss_addr_t;

typedef struct {
    char *port;
    char *password;
} ss_port_password_t;

typedef struct {
    int remote_num;
    ss_addr_t remote_addr[MAX_REMOTE_NUM];
    int port_password_num;
    ss_port_password_t port_password[MAX_PORT_NUM];
    char *remote_port;
    char *local_addr;
    char *local_port;
    char *password;
    char *method;
    char *timeout;
    int auth;
    int fast_open;
    int nofile;
    char *nameserver;
} jconf_t;

jconf_t *read_jconf(const char *file);
void parse_addr(const char *str, ss_addr_t *addr);
void free_addr(ss_addr_t *addr);

#endif // _JCONF_H
