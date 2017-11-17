
#ifndef _UTILS_H
#define _UTILS_H

#include <stdio.h>
#include <time.h>
#include <android/log.h>

#define PORTSTRLEN 16
#define SS_ADDRSTRLEN (INET6_ADDRSTRLEN + PORTSTRLEN + 1)

#define USE_TTY()
#define USE_SYSLOG(ident)

#define LOGD(...)                                                \
    ((void)__android_log_print(ANDROID_LOG_DEBUG, "specuid-faster", \
                               __VA_ARGS__))

#define LOGI(...)                                                \
    ((void)__android_log_print(ANDROID_LOG_INFO, "specuid-faster", \
                               __VA_ARGS__))
#define LOGE(...)                                                \
    ((void)__android_log_print(ANDROID_LOG_ERROR, "specuid-faster", \
                               __VA_ARGS__))

#define STR(x) # x
#define TOSTR(x) STR(x)

void ERROR(const char *s);
char *ss_itoa(int i);
int run_as(const char *user);
void FATAL(const char *msg);
char *ss_strndup(const char *s, size_t n);
#ifdef HAVE_SETRLIMIT
int set_nofile(int nofile);
#endif

#endif // _UTILS_H
