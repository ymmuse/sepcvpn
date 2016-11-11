
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <locale.h>
#include <signal.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>

#if defined(HAVE_SYS_IOCTL_H) && defined(HAVE_NET_IF_H) && defined(__linux__)
#include <net/if.h>
#include <sys/ioctl.h>
#define SET_INTERFACE
#endif

#include "libcork/core.h"
#include <udns.h>

#include "api.h"
#include "netutils.h"
#include "utils.h"
#include "socks5.h"
#include "acl.h"
#include "tun.h"
#include "nettcp.h"
#include "utarray.h"
#include "local.h"

#ifndef EAGAIN
#define EAGAIN EWOULDBLOCK
#endif

#ifndef EWOULDBLOCK
#define EWOULDBLOCK EAGAIN
#endif

#ifndef BUF_SIZE
#define BUF_SIZE 2048
#endif

int verbose = 0;
uint64_t tx = 0;
uint64_t rx = 0;
ev_tstamp last = 0;

static int acl = 0;
static int mode = TCP_ONLY;

static int fast_open = 0;
#ifdef HAVE_SETRLIMIT
#ifndef LIB_ONLY
static int nofile = 0;
#endif
#endif

static int auth = 0;

static void server_recv_cb(EV_P_ ev_io *w, int revents);
static void server_send_cb(EV_P_ ev_io *w, int revents);
static void remote_recv_cb(EV_P_ ev_io *w, int revents);
static void remote_send_cb(EV_P_ ev_io *w, int revents);
static void accept_cb(EV_P_ ev_io *w, int revents);
static void signal_cb(EV_P_ ev_signal *w, int revents);

static int create_and_bind(const char *addr, const char *port);
static remote_t *create_remote(listen_ctx_t *listener, struct sockaddr *addr);
static void free_remote(remote_t *remote);
static void close_and_free_remote(EV_P_ remote_t *remote);
static void free_server(server_t *server);
static void close_and_free_server(EV_P_ server_t *server);

static remote_t *new_remote(int fd, int timeout);
static server_t *new_server(int fd, int method);

static struct cork_dllist connections;

extern JNIEnv *g_vm_env;
extern jobject g_vpnsrv_instance;
extern routes_t *g_tun_routes;
extern UT_array *g_select_uids;

#ifndef __MINGW32__
int setnonblocking(int fd) {
  int flags;
  if (-1 == (flags = fcntl(fd, F_GETFL, 0))) {
    flags = 0;
  }
  return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

#endif

#ifdef SET_INTERFACE
int setinterface(int socket_fd, const char *interface_name) {
  struct ifreq interface;
  memset(&interface, 0, sizeof(interface));
  strncpy(interface.ifr_name, interface_name, IFNAMSIZ);
  int res = setsockopt(socket_fd, SOL_SOCKET, SO_BINDTODEVICE, &interface,
                       sizeof(struct ifreq));
  return res;
}

#endif

int create_and_bind(const char *addr, const char *port) {
  struct addrinfo hints;
  struct addrinfo *result, *rp;
  int s, listen_sock;

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;     /* Return IPv4 and IPv6 choices */
  hints.ai_socktype = SOCK_STREAM; /* We want a TCP socket */

  s = getaddrinfo(addr, port, &hints, &result);
  if (s != 0) {
    LOGD("getaddrinfo: %s", gai_strerror(s));
    return -1;
  }

  for (rp = result; rp != NULL; rp = rp->ai_next) {
    listen_sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (listen_sock == -1) {
      continue;
    }

    int opt = 1;
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
    setsockopt(listen_sock, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif
    int err = set_reuseport(listen_sock);
    if (err == 0) {
      LOGD("tcp port reuse enabled");
    }

    s = bind(listen_sock, rp->ai_addr, rp->ai_addrlen);
    if (s == 0) {
      /* We managed to bind successfully! */
      break;
    } else {
      ERROR("bind");
    }

    close(listen_sock);
  }

  if (rp == NULL) {
    LOGE("Could not bind");
    return -1;
  }

  freeaddrinfo(result);

  return listen_sock;
}

static void free_connections(struct ev_loop *loop) {
  struct cork_dllist_item *curr, *next;
  cork_dllist_foreach_void(&connections, curr, next) {
    server_t *server = cork_container_of(curr, server_t, entries);
    remote_t *remote = server->remote;
    close_and_free_server(loop, server);
    close_and_free_remote(loop, remote);
  }
}

static void server_recv_cb(EV_P_ ev_io *w, int revents) {
  server_ctx_t *server_recv_ctx = (server_ctx_t *)w;
  server_t *server = server_recv_ctx->server;
  remote_t *remote = server->remote;
  buffer_t *buf;

  if (remote == NULL) {
    buf = server->buf;
  } else {
    buf = remote->buf;
  }

  ssize_t r;

  r = recv(server->fd, buf->array, BUF_SIZE, 0);
  if (r == 0) {
    // connection closed
    close_and_free_remote(EV_A_ remote);
    close_and_free_server(EV_A_ server);
    return;
  } else if (r < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      // no data
      // continue to wait for recv
      return;
    } else {
      if (verbose)
        ERROR("server_recv_cb_recv");
      close_and_free_remote(EV_A_ remote);
      close_and_free_server(EV_A_ server);
      return;
    }
  }

  buf->len = r;
  while (1) {
    // local socks5 server
    if (server->stage == 5) {
      if (remote == NULL) {
        LOGE("invalid remote");
        close_and_free_server(EV_A_ server);
        return;
      }

      if (!remote->direct && remote->send_ctx->connected && auth) {
        ss_gen_hash(remote->buf, &remote->counter, server->e_ctx, BUF_SIZE);
      }

      // insert shadowsocks header
      if (!remote->direct) {
        tx += remote->buf->len;

        int err = ss_encrypt(remote->buf, server->e_ctx, BUF_SIZE);

        if (err) {
          LOGE("invalid password or cipher");
          close_and_free_remote(EV_A_ remote);
          close_and_free_server(EV_A_ server);
          return;
        }
      }

      if (!remote->send_ctx->connected) {
#ifdef ANDROID
        if (!protect_socket(g_vm_env, g_vpnsrv_instance, remote->fd)) {
          ERROR("protect_socket");
          close_and_free_remote(EV_A_ remote);
          close_and_free_server(EV_A_ server);
          return;
        }
#endif

        remote->buf->idx = 0;

        if (!fast_open || remote->direct) {
          // connecting, wait until connected
          connect(remote->fd, (struct sockaddr *)&(remote->addr),
                  remote->addr_len);

          // wait on remote connected event
          ev_io_stop(EV_A_ & server_recv_ctx->io);
          ev_io_start(EV_A_ & remote->send_ctx->io);
          ev_timer_start(EV_A_ & remote->send_ctx->watcher);
        } else {
#ifdef TCP_FASTOPEN
#ifdef __APPLE__
          ((struct sockaddr_in *)&(remote->addr))->sin_len =
              sizeof(struct sockaddr_in);
          sa_endpoints_t endpoints;
          bzero((char *)&endpoints, sizeof(endpoints));
          endpoints.sae_dstaddr = (struct sockaddr *)&(remote->addr);
          endpoints.sae_dstaddrlen = remote->addr_len;

          int s =
              connectx(remote->fd, &endpoints, SAE_ASSOCID_ANY,
                       CONNECT_RESUME_ON_READ_WRITE | CONNECT_DATA_IDEMPOTENT,
                       NULL, 0, NULL, NULL);
          if (s == 0) {
            s = send(remote->fd, remote->buf->array, remote->buf->len, 0);
          }
#else
          int s = sendto(remote->fd, remote->buf->array, remote->buf->len,
                         MSG_FASTOPEN, (struct sockaddr *)&(remote->addr),
                         remote->addr_len);
#endif
          if (s == -1) {
            if (errno == EINPROGRESS) {
              // in progress, wait until connected
              remote->buf->idx = 0;
              ev_io_stop(EV_A_ & server_recv_ctx->io);
              ev_io_start(EV_A_ & remote->send_ctx->io);
              return;
            } else {
              ERROR("sendto");
              if (errno == ENOTCONN) {
                LOGE("fast open is not supported on this platform");
                // just turn it off
                fast_open = 0;
              }
              close_and_free_remote(EV_A_ remote);
              close_and_free_server(EV_A_ server);
              return;
            }
          } else if (s <= remote->buf->len) {
            remote->buf->len -= s;
            remote->buf->idx = s;
          }

          // Just connected
          remote->send_ctx->connected = 1;
          ev_timer_stop(EV_A_ & remote->send_ctx->watcher);
          ev_io_start(EV_A_ & remote->recv_ctx->io);
#else
          // if TCP_FASTOPEN is not defined, fast_open will always be 0
          LOGE("can't come here");
          exit(1);
#endif
        }
      } else {
        int s = send(remote->fd, remote->buf->array, remote->buf->len, 0);
        if (s == -1) {
          if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // no data, wait for send
            remote->buf->idx = 0;
            ev_io_stop(EV_A_ & server_recv_ctx->io);
            ev_io_start(EV_A_ & remote->send_ctx->io);
            return;
          } else {
            ERROR("server_recv_cb_send");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
          }
        } else if (s < remote->buf->len) {
          remote->buf->len -= s;
          remote->buf->idx = s;
          ev_io_stop(EV_A_ & server_recv_ctx->io);
          ev_io_start(EV_A_ & remote->send_ctx->io);
          return;
        }
      }

      // all processed
      return;
    } else if (server->stage == 0) {
      struct sockaddr_in rmt;
      socklen_t rmt_len = sizeof(rmt);
      getpeername(server->fd, (struct sockaddr *)&rmt, &rmt_len);

      routes_t *routes;
      int find_port = (int)rmt.sin_port;
      HASH_FIND_INT(g_tun_routes, &find_port, routes);
      if (routes == NULL) {
        LOGD("never execute to here at localsrv stage=0");
        return;
      }

      int direct = 1;
      if (g_select_uids != NULL && utarray_len(g_select_uids) > 0) {
        direct = select_connection(routes->dst_ip, ntohs(routes->dst_port));
      }

      struct socks5_request request = {0x05, 0x01, 0x00, 0x01};

      int udp_assc = 0;

      if (mode != TCP_ONLY && request.cmd == 3) {
        udp_assc = 1;
        struct sockaddr_in sock_addr;
        memset(&sock_addr, 0, sizeof(sock_addr));
        socklen_t addr_len = sizeof(sock_addr);
        getsockname(server->fd, (struct sockaddr *)&sock_addr, &addr_len);
        if (verbose) {
          LOGD("udp assc request accepted");
        }
      } else if (request.cmd != 1) {
        LOGE("unsupported cmd: %d", request.cmd);
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
      } else {
        char host[256] = {0}, port[16] = {0};

        buffer_t ss_addr_to_send;
        buffer_t *abuf = &ss_addr_to_send;
        balloc(abuf, BUF_SIZE);

        abuf->array[abuf->len++] = request.atyp;

        // get remote addr and port
        if (request.atyp == 1) {
          // IP V4
          uint16_t p = ntohs(routes->dst_port);
          sprintf(port, "%d", p);
          dns_ntop(AF_INET, (const void *)&routes->dst_ip, host,
                   INET_ADDRSTRLEN);

          *(uint32_t *)(abuf->array + abuf->len) = routes->dst_ip;
          abuf->len += sizeof(uint32_t);
          *(uint16_t *)(abuf->array + abuf->len) = routes->dst_port;
          abuf->len += sizeof(uint16_t);
        } else if (request.atyp == 3) {
          // Domain name
          uint8_t name_len = *(uint8_t *)(buf->array + 4);
          abuf->array[abuf->len++] = name_len;
          memcpy(abuf->array + abuf->len, buf->array + 4 + 1, name_len + 2);
          abuf->len += name_len + 2;

          if (acl || verbose) {
            uint16_t p = ntohs(*(uint16_t *)(buf->array + 4 + 1 + name_len));
            memcpy(host, buf->array + 4 + 1, name_len);
            host[name_len] = '\0';
            sprintf(port, "%d", p);
          }
        } else if (request.atyp == 4) {
          // IP V6
          size_t in6_addr_len = sizeof(struct in6_addr);
          memcpy(abuf->array + abuf->len, buf->array + 4, in6_addr_len + 2);
          abuf->len += in6_addr_len + 2;

          if (acl || verbose) {
            uint16_t p = ntohs(*(uint16_t *)(buf->array + 4 + in6_addr_len));
            dns_ntop(AF_INET6, (const void *)(buf->array + 4), host,
                     INET6_ADDRSTRLEN);
            sprintf(port, "%d", p);
          }
        } else {
          bfree(abuf);
          LOGE("unsupported addrtype: %d", request.atyp);
          close_and_free_remote(EV_A_ remote);
          close_and_free_server(EV_A_ server);
          return;
        }

        server->stage = 5;

        if (verbose) {
          LOGD("connect to %s:%s", host, port);
        }

        if (direct || (acl && (request.atyp == 1 || request.atyp == 4) &&
                       acl_match_ip(host))) {
          if (verbose) {
            LOGD("bypass %s:%s", host, port);
          }
          struct sockaddr_storage storage;
          memset(&storage, 0, sizeof(struct sockaddr_storage));
          if (get_sockaddr(host, port, &storage, 0) != -1) {
            remote =
                create_remote(server->listener, (struct sockaddr *)&storage);
            remote->direct = 1;
          }
        } else {
          // go through proxy
          remote = create_remote(server->listener, NULL);
        }

        if (remote == NULL) {
          bfree(abuf);
          LOGE("invalid remote addr");
          close_and_free_server(EV_A_ server);
          return;
        }

        if (!remote->direct) {
          if (auth) {
            abuf->array[0] |= ONETIMEAUTH_FLAG;
            ss_onetimeauth(abuf, server->e_ctx->evp.iv, BUF_SIZE);
          }

          brealloc(remote->buf, abuf->len + buf->len, BUF_SIZE);
          memcpy(remote->buf->array, abuf->array, abuf->len);
          remote->buf->len = abuf->len;

          if (buf->len > 0) {
            if (auth) {
              ss_gen_hash(buf, &remote->counter, server->e_ctx, BUF_SIZE);
            }
            memcpy(remote->buf->array + remote->buf->len, buf->array, buf->len);
            remote->buf->len += buf->len;
          }
        } else {
          if (buf->len > 0) {
            memcpy(remote->buf->array, buf->array, buf->len);
            remote->buf->len = buf->len;
          }
        }

        server->remote = remote;
        remote->server = server;

        bfree(abuf);
      }

      if (udp_assc) {
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
      }
    }
  }
}

static void server_send_cb(EV_P_ ev_io *w, int revents) {
  server_ctx_t *server_send_ctx = (server_ctx_t *)w;
  server_t *server = server_send_ctx->server;
  remote_t *remote = server->remote;
  if (server->buf->len == 0) {
    // close and free
    close_and_free_remote(EV_A_ remote);
    close_and_free_server(EV_A_ server);
    return;
  } else {
    // has data to send
    ssize_t s = send(server->fd, server->buf->array + server->buf->idx,
                     server->buf->len, 0);
    if (s < 0) {
      if (errno != EAGAIN && errno != EWOULDBLOCK) {
        ERROR("server_send_cb_send");
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
      }
      return;
    } else if (s < server->buf->len) {
      // partly sent, move memory, wait for the next time to send
      server->buf->len -= s;
      server->buf->idx += s;
      return;
    } else {
      // all sent out, wait for reading
      server->buf->len = 0;
      server->buf->idx = 0;
      ev_io_stop(EV_A_ & server_send_ctx->io);
      ev_io_start(EV_A_ & remote->recv_ctx->io);
      return;
    }
  }
}

static void stat_update_cb(struct ev_loop *loop) {
  ev_tstamp now = ev_now(loop);
  if (now - last > 1.0) {
    onNetTrafficChange(g_vm_env, g_vpnsrv_instance, tx, rx);
    last = now;
  }
}

static void remote_timeout_cb(EV_P_ ev_timer *watcher, int revents) {
  remote_ctx_t *remote_ctx =
      (remote_ctx_t *)(((void *)watcher) - sizeof(ev_io));
  remote_t *remote = remote_ctx->remote;
  server_t *server = remote->server;

  if (verbose) {
    LOGD("TCP connection timeout");
  }

  close_and_free_remote(EV_A_ remote);
  close_and_free_server(EV_A_ server);
}

static void remote_recv_cb(EV_P_ ev_io *w, int revents) {
  remote_ctx_t *remote_recv_ctx = (remote_ctx_t *)w;
  remote_t *remote = remote_recv_ctx->remote;
  server_t *server = remote->server;

  ev_timer_again(EV_A_ & remote->recv_ctx->watcher);

  if (!remote->direct) {
    stat_update_cb(loop);
  }

  ssize_t r = recv(remote->fd, server->buf->array, BUF_SIZE, 0);

  if (r == 0) {
    // connection closed
    close_and_free_remote(EV_A_ remote);
    close_and_free_server(EV_A_ server);
    return;
  } else if (r < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      // no data
      // continue to wait for recv
      return;
    } else {
      ERROR("remote_recv_cb_recv");
      close_and_free_remote(EV_A_ remote);
      close_and_free_server(EV_A_ server);
      return;
    }
  }

  server->buf->len = r;

  if (!remote->direct) {
    rx += server->buf->len;

    int err = ss_decrypt(server->buf, server->d_ctx, BUF_SIZE);
    if (err) {
      LOGE("invalid password or cipher");
      close_and_free_remote(EV_A_ remote);
      close_and_free_server(EV_A_ server);
      return;
    }
  }

  int s = send(server->fd, server->buf->array, server->buf->len, 0);

  if (s == -1) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      // no data, wait for send
      server->buf->idx = 0;
      ev_io_stop(EV_A_ & remote_recv_ctx->io);
      ev_io_start(EV_A_ & server->send_ctx->io);
      return;
    } else {
      ERROR("remote_recv_cb_send");
      close_and_free_remote(EV_A_ remote);
      close_and_free_server(EV_A_ server);
      return;
    }
  } else if (s < server->buf->len) {
    server->buf->len -= s;
    server->buf->idx = s;
    ev_io_stop(EV_A_ & remote_recv_ctx->io);
    ev_io_start(EV_A_ & server->send_ctx->io);
    return;
  }
}

static void remote_send_cb(EV_P_ ev_io *w, int revents) {
  remote_ctx_t *remote_send_ctx = (remote_ctx_t *)w;
  remote_t *remote = remote_send_ctx->remote;
  server_t *server = remote->server;

  if (!remote_send_ctx->connected) {
    struct sockaddr_storage addr;
    socklen_t len = sizeof addr;
    int r = getpeername(remote->fd, (struct sockaddr *)&addr, &len);
    if (r == 0) {
      remote_send_ctx->connected = 1;
      ev_timer_stop(EV_A_ & remote_send_ctx->watcher);
      ev_timer_start(EV_A_ & remote->recv_ctx->watcher);
      ev_io_start(EV_A_ & remote->recv_ctx->io);

      // no need to send any data
      if (remote->buf->len == 0) {
        ev_io_stop(EV_A_ & remote_send_ctx->io);
        ev_io_start(EV_A_ & server->recv_ctx->io);
        return;
      }
    } else {
      // not connected
      ERROR("getpeername");
      close_and_free_remote(EV_A_ remote);
      close_and_free_server(EV_A_ server);
      return;
    }
  }

  if (remote->buf->len == 0) {
    // close and free
    close_and_free_remote(EV_A_ remote);
    close_and_free_server(EV_A_ server);
    return;
  } else {
    // has data to send
    ssize_t s = send(remote->fd, remote->buf->array + remote->buf->idx,
                     remote->buf->len, 0);
    if (s < 0) {
      if (errno != EAGAIN && errno != EWOULDBLOCK) {
        ERROR("remote_send_cb_send");
        // close and free
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
      }
      return;
    } else if (s < remote->buf->len) {
      // partly sent, move memory, wait for the next time to send
      remote->buf->len -= s;
      remote->buf->idx += s;
      return;
    } else {
      // all sent out, wait for reading
      remote->buf->len = 0;
      remote->buf->idx = 0;
      ev_io_stop(EV_A_ & remote_send_ctx->io);
      ev_io_start(EV_A_ & server->recv_ctx->io);
    }
  }
}

static remote_t *new_remote(int fd, int timeout) {
  remote_t *remote;
  remote = malloc(sizeof(remote_t));

  memset(remote, 0, sizeof(remote_t));

  remote->buf = malloc(sizeof(buffer_t));
  remote->recv_ctx = malloc(sizeof(remote_ctx_t));
  remote->send_ctx = malloc(sizeof(remote_ctx_t));
  remote->recv_ctx->connected = 0;
  remote->send_ctx->connected = 0;
  remote->fd = fd;
  remote->recv_ctx->remote = remote;
  remote->send_ctx->remote = remote;

  ev_io_init(&remote->recv_ctx->io, remote_recv_cb, fd, EV_READ);
  ev_io_init(&remote->send_ctx->io, remote_send_cb, fd, EV_WRITE);
  ev_timer_init(&remote->send_ctx->watcher, remote_timeout_cb,
                min(MAX_CONNECT_TIMEOUT, timeout), 0);
  ev_timer_init(&remote->recv_ctx->watcher, remote_timeout_cb,
                min(MAX_CONNECT_TIMEOUT, timeout), timeout);

  balloc(remote->buf, BUF_SIZE);

  return remote;
}

static void free_remote(remote_t *remote) {
  if (remote->server != NULL) {
    remote->server->remote = NULL;
  }
  if (remote->buf != NULL) {
    bfree(remote->buf);
    free(remote->buf);
  }
  free(remote->recv_ctx);
  free(remote->send_ctx);
  free(remote);
}

static void close_and_free_remote(EV_P_ remote_t *remote) {
  if (remote != NULL) {
    ev_timer_stop(EV_A_ & remote->send_ctx->watcher);
    ev_timer_stop(EV_A_ & remote->recv_ctx->watcher);
    ev_io_stop(EV_A_ & remote->send_ctx->io);
    ev_io_stop(EV_A_ & remote->recv_ctx->io);
    close(remote->fd);
    free_remote(remote);
  }
}

static server_t *new_server(int fd, int method) {
  server_t *server;
  server = malloc(sizeof(server_t));

  memset(server, 0, sizeof(server_t));

  server->recv_ctx = malloc(sizeof(server_ctx_t));
  server->send_ctx = malloc(sizeof(server_ctx_t));
  server->buf = malloc(sizeof(buffer_t));
  server->recv_ctx->connected = 0;
  server->send_ctx->connected = 0;
  server->fd = fd;
  server->recv_ctx->server = server;
  server->send_ctx->server = server;

  if (method) {
    server->e_ctx = malloc(sizeof(struct enc_ctx));
    server->d_ctx = malloc(sizeof(struct enc_ctx));
    enc_ctx_init(method, server->e_ctx, 1);
    enc_ctx_init(method, server->d_ctx, 0);
  } else {
    server->e_ctx = NULL;
    server->d_ctx = NULL;
  }

  ev_io_init(&server->recv_ctx->io, server_recv_cb, fd, EV_READ);
  ev_io_init(&server->send_ctx->io, server_send_cb, fd, EV_WRITE);

  balloc(server->buf, BUF_SIZE);

  cork_dllist_add(&connections, &server->entries);

  return server;
}

static void free_server(server_t *server) {
  cork_dllist_remove(&server->entries);

  if (server->remote != NULL) {
    server->remote->server = NULL;
  }
  if (server->e_ctx != NULL) {
    cipher_context_release(&server->e_ctx->evp);
    free(server->e_ctx);
  }
  if (server->d_ctx != NULL) {
    cipher_context_release(&server->d_ctx->evp);
    free(server->d_ctx);
  }
  if (server->buf != NULL) {
    bfree(server->buf);
    free(server->buf);
  }
  free(server->recv_ctx);
  free(server->send_ctx);
  free(server);
}

static void close_and_free_server(EV_P_ server_t *server) {
  if (server != NULL) {
    ev_io_stop(EV_A_ & server->send_ctx->io);
    ev_io_stop(EV_A_ & server->recv_ctx->io);
    close(server->fd);
    free_server(server);
  }
}

static remote_t *create_remote(listen_ctx_t *listener, struct sockaddr *addr) {
  struct sockaddr *remote_addr;

  int index = rand() % listener->remote_num;
  if (addr == NULL) {
    remote_addr = listener->remote_addr[index];
  } else {
    remote_addr = addr;
  }

  int remotefd = socket(remote_addr->sa_family, SOCK_STREAM, IPPROTO_TCP);

  if (remotefd < 0) {
    ERROR("socket");
    return NULL;
  }

  int opt = 1;
  setsockopt(remotefd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
  setsockopt(remotefd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif

  // Setup
  setnonblocking(remotefd);
#ifdef SET_INTERFACE
  if (listener->iface) {
    setinterface(remotefd, listener->iface);
  }
#endif

  remote_t *remote = new_remote(remotefd, listener->timeout);
  remote->addr_len = get_sockaddr_len(remote_addr);
  memcpy(&(remote->addr), remote_addr, remote->addr_len);

  return remote;
}

static void signal_cb(EV_P_ ev_signal *w, int revents) {
  if (revents & EV_SIGNAL) {
    switch (w->signum) {
    case SIGINT:
    case SIGTERM:
      ev_unloop(EV_A_ EVUNLOOP_ALL);
    }
  }
}

void accept_cb(EV_P_ ev_io *w, int revents) {
  listen_ctx_t *listener = (listen_ctx_t *)w;
  int serverfd = accept(listener->fd, NULL, NULL);
  if (serverfd == -1) {
    ERROR("accept");
    return;
  }

  setnonblocking(serverfd);
  int opt = 1;
  setsockopt(serverfd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
  setsockopt(serverfd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif

  server_t *server = new_server(serverfd, listener->method);
  server->listener = listener;

  ev_io_start(EV_A_ & server->recv_ctx->io);
}

int start_vpn(int tunfd, profile_t profile) {
  srand(time(NULL));

  char *remote_host = profile.remote_host;
  char *local_addr = profile.local_addr;
  char *method = profile.method;
  char *password = profile.password;
  int remote_port = profile.remote_port;
  int local_port = profile.local_port;
  int timeout = profile.timeout;

  auth = profile.auth;
  mode = profile.mode;
  fast_open = profile.fast_open;
  verbose = profile.verbose;

  char local_port_str[16];
  char remote_port_str[16];
  sprintf(remote_port_str, "%d", remote_port);

  if (profile.acl != NULL) {
    acl = !init_acl(profile.acl, BLACK_LIST);
  }

  if (local_addr == NULL) {
    ERROR("local_addr NULL");
    return -1;
  }

  // check tun
  if (setnonblocking(tunfd) < 0) {
    ERROR("tun error");
    return -1;
  }

  // ignore SIGPIPE
  signal(SIGPIPE, SIG_IGN);
  signal(SIGABRT, SIG_IGN);

  struct ev_signal sigint_watcher;
  struct ev_signal sigterm_watcher;
  ev_signal_init(&sigint_watcher, signal_cb, SIGINT);
  ev_signal_init(&sigterm_watcher, signal_cb, SIGTERM);
  ev_signal_start(EV_DEFAULT, &sigint_watcher);
  ev_signal_start(EV_DEFAULT, &sigterm_watcher);

  // Setup keys
  LOGD("using ciphers... %s", method);
  int m = enc_init(password, method);

  struct sockaddr_storage *storage = malloc(sizeof(struct sockaddr_storage));
  memset(storage, 0, sizeof(struct sockaddr_storage));
  if (get_sockaddr(remote_host, remote_port_str, storage, 1) == -1) {
    return -1;
  }

  // Setup proxy context
  struct ev_loop *loop = EV_DEFAULT;
  listen_ctx_t listen_ctx;

  listen_ctx.remote_num = 1;
  listen_ctx.remote_addr = malloc(sizeof(struct sockaddr *));
  listen_ctx.remote_addr[0] = (struct sockaddr *)storage;
  listen_ctx.timeout = timeout;
  listen_ctx.method = m;
  listen_ctx.iface = NULL;

  // Setup socket
  int listenfd;
  listenfd = create_and_bind(local_addr, "0");
  if (listenfd < 0) {
    ERROR("bind()");
    return -1;
  }

  struct sockaddr listenaddr;
  socklen_t listenaddr_len = sizeof(listenaddr);
  getsockname(listenfd, &listenaddr, &listenaddr_len);
  local_port = ntohs(((struct sockaddr_in *)&listenaddr)->sin_port);

  sprintf(local_port_str, "%d", local_port);

  if (listen(listenfd, SOMAXCONN) == -1) {
    ERROR("listen()");
    return -1;
  }
  setnonblocking(listenfd);

  listen_ctx.fd = listenfd;

  ev_io_init(&listen_ctx.io, accept_cb, listenfd, EV_READ);
  ev_io_start(loop, &listen_ctx.io);

  // Setup UDP
  if (mode != TCP_ONLY) {
    LOGD("udprelay enabled");
    struct sockaddr *addr = (struct sockaddr *)storage;
    init_udprelay(local_addr, local_port_str, addr, get_sockaddr_len(addr), m,
                  auth, timeout, NULL);
  }

  LOGD("listening at %s:%s", local_addr, local_port_str);

  // Init connections
  cork_dllist_init(&connections);

  struct sockaddr_in local_address;
  inet_aton(local_addr, &local_address.sin_addr);

  // init tun
  tun_ctx_t tun_ctx;
  tun_ctx.fd = tunfd;
  tun_ctx.local_address = local_address.sin_addr.s_addr;
  tun_ctx.local_port = local_port;

  tun_ctx.buf = malloc(sizeof(buffer_t));
  balloc(tun_ctx.buf, 4096); // mtu = 1500

  ev_io_init(&tun_ctx.io, tun_read_cb, tunfd, EV_READ);
  ev_io_start(loop, &tun_ctx.io);

  // Enter the loop
  ev_run(loop, 0);

  ev_io_stop(loop, &tun_ctx.io);

  if (verbose) {
    LOGD("closed gracefully");
  }

  // Clean up
  if (mode != TCP_ONLY) {
    free_udprelay();
  }

  ev_io_stop(loop, &listen_ctx.io);
  free_connections(loop);
  close(listen_ctx.fd);
  free(listen_ctx.remote_addr);

  bfree(tun_ctx.buf);
  free(tun_ctx.buf);

  g_vm_env = NULL;
  g_vpnsrv_instance = NULL;

  // clear all routes
  routes_t *current_routes, *tmp_routes;
  HASH_ITER(hh, g_tun_routes, current_routes, tmp_routes) {
    HASH_DEL(g_tun_routes, current_routes);
    free(current_routes);
  }
  g_tun_routes = NULL;

  ev_signal_stop(EV_DEFAULT, &sigint_watcher);
  ev_signal_stop(EV_DEFAULT, &sigterm_watcher);

  // cannot reach here
  return 0;
}

void stop_vpn() { raise(SIGTERM); }