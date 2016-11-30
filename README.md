# sepcvpn

Only support tcp stream for now

## Expose API in java 

```java
    // onNetTrafficChange will be called in jni
    public void onNetTrafficChange(long up, long down) {
    
    }

    public native void startVPN(int fd, String localAddress, String srvAddress, int srvPort , String method, String srvPWD);
    public native void stopVPN();

    // you need to find app uid to want 'Allowed' or 'Disallowed'
    public static native void addAllowedApplication(int appUID);
    public static native void addDisallowedApplication(int appUID);
```
