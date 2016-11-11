
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "utils.h"

#ifdef HAVE_SETRLIMIT
#include <sys/time.h>
#include <sys/resource.h>
#endif

#define INT_DIGITS 19           /* enough for 64 bit integer */

#ifdef HAS_SYSLOG
int use_syslog = 0;
#endif

void ERROR(const char *s)
{
    char *msg = strerror(errno);
    LOGE("%s: %s", s, msg);
}

int use_tty = 1;

char *ss_itoa(int i)
{
    /* Room for INT_DIGITS digits, - and '\0' */
    static char buf[INT_DIGITS + 2];
    char *p = buf + INT_DIGITS + 1;     /* points to terminating '\0' */
    if (i >= 0) {
        do {
            *--p = '0' + (i % 10);
            i   /= 10;
        } while (i != 0);
        return p;
    } else {                     /* i < 0 */
        do {
            *--p = '0' - (i % 10);
            i   /= 10;
        } while (i != 0);
        *--p = '-';
    }
    return p;
}

/*
 * setuid() and setgid() for a specified user.
 */
int run_as(const char *user)
{
#ifndef __MINGW32__
    if (user[0]) {
#ifdef HAVE_GETPWNAM_R
        struct passwd pwdbuf, *pwd;
        size_t buflen;
        int err;

        for (buflen = 128;; buflen *= 2) {
            char buf[buflen];  /* variable length array */

            /* Note that we use getpwnam_r() instead of getpwnam(),
             * which returns its result in a statically allocated buffer and
             * cannot be considered thread safe. */
            err = getpwnam_r(user, &pwdbuf, buf, buflen, &pwd);

            if (err == 0 && pwd) {
                /* setgid first, because we may not be allowed to do it anymore after setuid */
                if (setgid(pwd->pw_gid) != 0) {
                    LOGE(
                        "Could not change group id to that of run_as user '%s': %s",
                        user, strerror(errno));
                    return 0;
                }

                if (setuid(pwd->pw_uid) != 0) {
                    LOGE(
                        "Could not change user id to that of run_as user '%s': %s",
                        user, strerror(errno));
                    return 0;
                }
                break;
            } else if (err != ERANGE) {
                if (err) {
                    LOGE("run_as user '%s' could not be found: %s", user, strerror(
                             err));
                } else {
                    LOGE("run_as user '%s' could not be found.", user);
                }
                return 0;
            } else if (buflen >= 16 * 1024) {
                /* If getpwnam_r() seems defective, call it quits rather than
                 * keep on allocating ever larger buffers until we crash. */
                LOGE(
                    "getpwnam_r() requires more than %u bytes of buffer space.",
                    (unsigned)buflen);
                return 0;
            }
            /* Else try again with larger buffer. */
        }
#else
        /* No getpwnam_r() :-(  We'll use getpwnam() and hope for the best. */
        struct passwd *pwd;

        if (!(pwd = getpwnam(user))) {
            LOGE("run_as user %s could not be found.", user);
            return 0;
        }
        /* setgid first, because we may not allowed to do it anymore after setuid */
        if (setgid(pwd->pw_gid) != 0) {
            LOGE("Could not change group id to that of run_as user '%s': %s",
                 user, strerror(errno));
            return 0;
        }
        if (setuid(pwd->pw_uid) != 0) {
            LOGE("Could not change user id to that of run_as user '%s': %s",
                 user, strerror(errno));
            return 0;
        }
#endif
    }

#endif // __MINGW32__
    return 1;
}

char *ss_strndup(const char *s, size_t n)
{
    size_t len = strlen(s);
    char *ret;

    if (len <= n) {
        return strdup(s);
    }

    ret = malloc(n + 1);
    strncpy(ret, s, n);
    ret[n] = '\0';
    return ret;
}

void FATAL(const char *msg)
{
    LOGE("%s", msg);
    exit(-1);
}

#ifdef HAVE_SETRLIMIT
int set_nofile(int nofile)
{
    struct rlimit limit = { nofile, nofile }; /* set both soft and hard limit */

    if (nofile <= 0) {
        FATAL("nofile must be greater than 0\n");
    }

    if (setrlimit(RLIMIT_NOFILE, &limit) < 0) {
        if (errno == EPERM) {
            LOGE(
                "insufficient permission to change NOFILE, not starting as root?");
            return -1;
        } else if (errno == EINVAL) {
            LOGE("invalid nofile, decrease nofile and try again");
            return -1;
        } else {
            LOGE("setrlimit failed: %s", strerror(errno));
            return -1;
        }
    }

    return 0;
}

#endif
