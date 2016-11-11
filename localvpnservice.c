#include <jni.h>
#include <android/log.h>

#include "utarray.h"
#include "utils.h"
#include "ssv5/api.h"
#include "common.h"

JNIEnv *g_vm_env = NULL;
jobject g_vpnsrv_instance = NULL;
routes_t *g_tun_routes = NULL;
UT_array *g_select_uids = NULL;

JNIEXPORT void JNICALL Java_com_spec_uid_vpn_LocalVpnService_startVPN(
    JNIEnv *env, jobject instance, jint fd, jstring localAddress_,
    jstring srvAddress_, jint srvPort, jstring method_, jstring srvpwd_) {
  const char *localAddress = (*env)->GetStringUTFChars(env, localAddress_, 0);
  const char *srvAddress = (*env)->GetStringUTFChars(env, srvAddress_, 0);
  const char *method = (*env)->GetStringUTFChars(env, method_, 0);
  const char *srvpwd = (*env)->GetStringUTFChars(env, srvpwd_, 0);

  profile_t config;
  config.method = method;
  config.password = srvpwd;
  config.remote_port = srvPort;
  config.remote_host = srvAddress;
  config.local_addr = localAddress;
  config.verbose = 0;
  config.fast_open = 0;
  config.auth = 0;
  config.mode = TCP_ONLY;

  config.acl = NULL;
  config.log = NULL;

  g_vm_env = env;
  g_vpnsrv_instance = instance;

  start_vpn(fd, config);

  (*env)->ReleaseStringUTFChars(env, localAddress_, localAddress);
  (*env)->ReleaseStringUTFChars(env, srvAddress_, srvAddress);
  (*env)->ReleaseStringUTFChars(env, method_, method);
  (*env)->ReleaseStringUTFChars(env, srvpwd_, srvpwd);
}

JNIEXPORT void JNICALL Java_com_spec_uid_vpn_LocalVpnService_stopVPN(
    JNIEnv *env, jobject instance) {
  stop_vpn();
}

JNIEXPORT void JNICALL Java_com_spec_uid_vpn_LocalVpnService_setUID(
    JNIEnv *env, jobject instance, jint uid, jboolean remove) {
  if (g_select_uids == NULL) {
    utarray_new(g_select_uids, &ut_int_icd);
  }

  int *p = (int *)utarray_front(g_select_uids);
  for (; p != NULL; p = (int *)utarray_next(g_select_uids, p)) {
    if (*p == uid)
      break;
  }

  if (remove == JNI_TRUE) {
    if (p != NULL) {
      int idx = utarray_eltidx(g_select_uids, p);
      utarray_erase(g_select_uids, idx, 1);
    }
  } else if (p == NULL) {
    utarray_push_back(g_select_uids, &uid);
  }
}