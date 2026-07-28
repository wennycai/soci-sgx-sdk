package com.soci.sdk;
public final class SociRuntime implements AutoCloseable {
  static { System.loadLibrary("soci_jni"); }
  private long handle;
  public SociRuntime(String runtimeDir){handle=nativeCreate(runtimeDir);if(handle==0)throw new SociException("native create failed");}
  private void check(){if(handle==0)throw new SociException("runtime is closed");}
  public synchronized void createKey(String id,int bits){check();nativeCreateKey(handle,id,bits);}
  public synchronized byte[] encrypt(String value){check();return nativeEncrypt(handle,value);}
  public synchronized String decrypt(byte[] ciphertext){check();return nativeDecrypt(handle,ciphertext);}
  public synchronized byte[] add(byte[] a,byte[] b){check();return nativeBinary(handle,0,a,b);}
  public synchronized byte[] scalarMul(byte[] a,String k){check();return nativeScalarMul(handle,a,k);}
  public synchronized byte[] secureMul(byte[] a,byte[] b){check();return nativeBinary(handle,1,a,b);}
  public synchronized byte[] secureCompare(byte[] a,byte[] b){check();return nativeBinary(handle,2,a,b);}
  public synchronized byte[] secureSignBit(byte[] a){check();return nativeUnary(handle,0,a);}
  public synchronized byte[] secureAbs(byte[] a){check();return nativeUnary(handle,1,a);}
  public synchronized SociDivisionResult secureDiv(byte[] a,byte[] b){check();byte[][] v=nativeDiv(handle,a,b);return new SociDivisionResult(new SociCiphertext(v[0]),new SociCiphertext(v[1]));}
  @Override public synchronized void close(){if(handle!=0){nativeClose(handle);handle=0;}}
  private static native long nativeCreate(String dir); private static native void nativeClose(long h);
  private static native void nativeCreateKey(long h,String id,int bits);
  private static native byte[] nativeEncrypt(long h,String value); private static native String nativeDecrypt(long h,byte[] c);
  private static native byte[] nativeBinary(long h,int op,byte[] a,byte[] b);
  private static native byte[] nativeUnary(long h,int op,byte[] a);
  private static native byte[] nativeScalarMul(long h,byte[] a,String k);
  private static native byte[][] nativeDiv(long h,byte[] a,byte[] b);
}
