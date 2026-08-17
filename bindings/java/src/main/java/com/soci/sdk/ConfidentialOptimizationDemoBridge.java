package com.soci.sdk;

/** Demo-only JNI bridge to the Phase 1-5 confidential optimizer. */
public final class ConfidentialOptimizationDemoBridge implements AutoCloseable {
  static { System.loadLibrary("soci_demo_bridge"); }
  private long handle;
  public ConfidentialOptimizationDemoBridge(String mode, String runtimeDir,
      String cpEnclave, String keyDirectory, String cspHost, int cspPort) {
    handle=nativeCreate(mode,runtimeDir,cpEnclave,keyDirectory,cspHost,cspPort);
    if(handle==0)throw new SociException("confidential demo bridge create failed");
  }
  private void check(){if(handle==0)throw new SociException("demo bridge is closed");}
  public synchronized byte[] encrypt(long value){check();return nativeEncrypt(handle,value);}
  public synchronized ConfidentialOptimizationResult optimize(byte[][][] costs,
      long thresholdScaled,String strategy,int gridSize,String sessionId){
    check();return nativeOptimize(handle,costs,thresholdScaled,strategy,gridSize,sessionId);
  }
  public synchronized String mode(){check();return nativeMode(handle);}
  public synchronized void close(){if(handle!=0){nativeClose(handle);handle=0;}}
  private static native long nativeCreate(String mode,String runtimeDir,
      String cpEnclave,String keyDirectory,String cspHost,int cspPort);
  private static native void nativeClose(long handle);
  private static native byte[] nativeEncrypt(long handle,long value);
  private static native ConfidentialOptimizationResult nativeOptimize(long handle,
      byte[][][] costs,long thresholdScaled,String strategy,int gridSize,String sessionId);
  private static native String nativeMode(long handle);
}
