
#include <jni.h>

#ifndef _COMMON_H
#define _COMMON_H

// only enable TCP_FASTOPEN on linux
#if defined(__linux__)

/*  conditional define for TCP_FASTOPEN */
#ifndef TCP_FASTOPEN
#define TCP_FASTOPEN   23
#endif

/*  conditional define for MSG_FASTOPEN */
#ifndef MSG_FASTOPEN
#define MSG_FASTOPEN   0x20000000
#endif

#elif !defined(__APPLE__)

#ifdef TCP_FASTOPEN
#undef TCP_FASTOPEN
#endif

#endif


#ifndef SOL_TCP
#define SOL_TCP IPPROTO_TCP
#endif

#define TCP_ONLY     0
#define TCP_AND_UDP  1
#define UDP_ONLY     3

#if defined(MODULE_TUNNEL) || defined(MODULE_REDIR)
#define MODULE_LOCAL
#endif

int init_udprelay(const char *server_host, const char *server_port,
#ifdef MODULE_LOCAL
                  const struct sockaddr *remote_addr, const int remote_addr_len,
#ifdef MODULE_TUNNEL
                  const ss_addr_t tunnel_addr,
#endif
#endif
                  int method, int auth, int timeout, const char *iface);

void free_udprelay(void);

#ifdef ANDROID
int protect_socket(JNIEnv *env, jobject vpnservice_instance, int fd);
int send_traffic_stat(uint64_t tx, uint64_t rx);
#endif

#endif // _COMMON_H
