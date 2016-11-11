# sepcvpn

## expose apis for java 

```java
    public void onNetTrafficChange(long up, long down) {
    
    }

    private native void startVPN(int fd, String localAddress, String srvAddress, int srvPort , String method, String srvPWD);
    private native void stopVPN();
    public static native void setUID(int uid, boolean remove);
```
