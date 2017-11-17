
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <locale.h>
#include <signal.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <errno.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <jni.h>
#include <sys/un.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "netutils.h"
#include "utils.h"

int protect_socket(JNIEnv *env, jobject vpnservice_instance, int fd)
{
    jclass cls = (*env)->FindClass(env, "com/spec/uid/vpn/LocalVpnService");
    jmethodID protect = (*env)->GetMethodID(env, cls, "protect", "(I)Z");
    return (*env)->CallBooleanMethod(env, vpnservice_instance, protect, fd);    
}

void onNetTrafficChange(JNIEnv *env, jobject vpnservice_instance, uint64_t up, uint64_t down)
{
    jclass cls = (*env)->FindClass(env, "com/spec/uid/vpn/LocalVpnService");
    jmethodID net_traffic = (*env)->GetMethodID(env, cls, "onNetTrafficChange", "(JJ)V");
    (*env)->CallVoidMethod(env, vpnservice_instance, net_traffic, up, down);    
}

int send_traffic_stat(uint64_t tx, uint64_t rx)
{
    int sock;
    struct sockaddr_un addr;

    if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        LOGE("[android] socket() failed: %s (socket fd = %d)\n", strerror(errno), sock);
        return -1;
    }

    // Set timeout to 1s
    struct timeval tv;
    tv.tv_sec  = 1;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(struct timeval));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&tv, sizeof(struct timeval));

    const char path[] = "/data/data/com.spec.uid/tun_stat";

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        LOGE("[android] connect() failed: %s (socket fd = %d)\n", strerror(errno), sock);
        close(sock);
        return -1;
    }

    uint64_t stat[2] = { tx, rx };

    if (send(sock, stat, sizeof(stat), 0) == -1) {
        ERROR("[android] send");
        close(sock);
        return -1;
    }

    char ret = 0;

    if (recv(sock, &ret, 1, 0) == -1) {
        ERROR("[android] recv");
        close(sock);
        return -1;
    }

    close(sock);
    return ret;
}
