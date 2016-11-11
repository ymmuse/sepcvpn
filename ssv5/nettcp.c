#include "utils.h"
#include "nettcp.h"
#include "utarray.h"

extern UT_array *g_select_uids;

void nettcp4_read_cb(EV_P_ ev_io *w, int revents) {
  nettcp4_ctx_t *tcp4_ctx = (nettcp4_ctx_t *)w;
}

int select_connection(uint32_t rem_ip, uint32_t rem_port) {

  char buf[1024];
  nettcp_conn_t c;

  FILE *fp = fopen("/proc/net/tcp", "r");
  // drop header
  fgets(buf, sizeof(buf), fp);

  uint32_t src, dst;
  int ssret, direct = 1;
  while (fgets(buf, sizeof(buf), fp) != NULL) {
    ssret = sscanf(buf, "%*d: "
                        "%X:%hx "
                        "%X:%hx "
                        "%*x %*x:%*x %*x:%*x %x "
                        "%lu %*d %lu",
                   &src, &c.port_src, &dst, &c.port_dst, &c.retransmit, &c.uid,
                   &c.inode);
    if (ssret != 7) {
      continue;
    }

    if (dst == rem_ip && c.port_dst == rem_port) {
      int *p = NULL;
      for (p = (int *)utarray_front(g_select_uids); p != NULL; p = (int *)utarray_next(g_select_uids, p)) {
        if (*p == (int)c.uid) {
          direct = 0;
          goto RETURN;
        }
      }
    }
    
  }// while

RETURN:
  fclose(fp);
  return direct;
}