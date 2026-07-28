package com.soci.sdk;
import java.nio.file.Files;
import java.util.*;
public final class BindingBenchmark {
  interface Op { byte[] run(); }
  static void metric(SociRuntime r,String name,Op op,String expected,int warm,int count){
    long[] v=new long[count];byte[] out=null;
    for(int i=-warm;i<count;i++){long t=System.nanoTime();out=op.run();long u=(System.nanoTime()-t)/1000;if(i>=0)v[i]=u;}
    Arrays.sort(v);double mean=0;for(long x:v)mean+=x;mean/=count;
    boolean ok=expected==null||expected.equals(r.decrypt(out));
    System.out.printf(Locale.ROOT,"%s{\"operation\":\"%s\",\"samples\":%d,\"mean_us\":%.3f,\"p50_us\":%d,\"p95_us\":%d,\"correct\":%s}",
      first?"":",\n",name,count,mean,v[(count-1)/2],v[Math.max(0,(int)Math.ceil(.95*count)-1)],ok);first=false;
  }
  static boolean first=true;
  public static void main(String[] args)throws Exception{
    int warm=Integer.parseInt(System.getenv().getOrDefault("BINDING_WARMUP","5"));
    int count=Integer.parseInt(System.getenv().getOrDefault("BINDING_SAMPLES","20"));
    try(SociRuntime r=new SociRuntime(Files.createTempDirectory("soci-java").toString())){
      r.createKey("binding",3072);byte[] a=r.encrypt("12345"),b=r.encrypt("-67");
      System.out.printf("{\"binding\":\"Java/JNI\",\"security_bits\":128,\"warmup\":%d,\"metrics\":[\n",warm);
      metric(r,"Encrypt",()->r.encrypt("12345"),null,warm,count);
      metric(r,"Decrypt",()->{r.decrypt(a);return a;},"12345",warm,count);
      metric(r,"SADD",()->r.add(a,b),"12278",warm,count);
      metric(r,"ScalarMul",()->r.scalarMul(a,"19"),"234555",warm,count);
      metric(r,"SMUL",()->r.secureMul(a,b),"-827115",warm,count);
      metric(r,"SCMP",()->r.secureCompare(a,b),"1",warm,count);
      metric(r,"SABS",()->r.secureAbs(b),"67",warm,count);
      SociDivisionResult d=r.secureDiv(a,r.encrypt("100"));
      System.out.printf(",\n{\"operation\":\"SDIV\",\"samples\":1,\"correct\":%s}\n]}%n",
        r.decrypt(d.quotient.toBytes()).equals("123")&&r.decrypt(d.remainder.toBytes()).equals("45"));
    }
  }
}
