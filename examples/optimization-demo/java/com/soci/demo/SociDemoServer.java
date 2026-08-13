package com.soci.demo;

import com.soci.sdk.OptimizationResult;
import com.soci.sdk.SociOptimizer;
import com.soci.sdk.SociRuntime;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/** OFF-mode demo adapter: browser HTTP -> Java -> JNI -> SOCI SDK. */
public final class SociDemoServer implements AutoCloseable {
  private final SociRuntime runtime;
  private final SociOptimizer optimizer;
  private final HttpServer server;
  private final Path webRoot;
  private final Map<String,byte[][][]> jobs=new ConcurrentHashMap<>();

  private SociDemoServer(Path webRoot, Path runtimeDir, int port) throws IOException {
    this.webRoot = webRoot.toAbsolutePath().normalize();
    runtime = new SociRuntime(runtimeDir.toString());
    runtime.createKey("demo", 3072);
    optimizer = new SociOptimizer(runtime);
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 0);
    server.createContext("/api/health", x -> json(x, 200, "{\"mode\":\"OFF\",\"jni\":true}"));
    server.createContext("/api/encrypt", this::encrypt);
    server.createContext("/api/optimize", this::optimizeEncryptedDirect);
    server.createContext("/api/workflow/optimize", this::optimizeEncryptedDirect);
    server.createContext("/api/workflow/encrypt", this::encryptWorkflow);
    server.createContext("/api/workflow/compute", this::computeWorkflow);
    server.createContext("/api/workflow/decrypt", this::decryptResult);
    server.createContext("/", this::staticFile);
  }

  private static final class Input {
    final String[] ids;
    final Double[][] costs;
    final double threshold;
    Input(String[] ids, Double[][] costs, double threshold) { this.ids=ids;this.costs=costs;this.threshold=threshold; }
  }

  // Wire format: threshold on line 1, then id<TAB>cost1<TAB>cost2<TAB>cost3.
  private static Input input(HttpExchange x) throws IOException {
    String body = new String(readAll(x.getRequestBody()), StandardCharsets.UTF_8);
    String[] lines = body.split("\\R");
    if (lines.length < 2) throw new IllegalArgumentException("cost matrix is empty");
    double threshold = Double.parseDouble(lines[0]);
    String[] ids = new String[lines.length-1];
    Double[][] costs = new Double[lines.length-1][3];
    for (int i=1;i<lines.length;i++) {
      String[] cells=lines[i].split("\\t",-1);
      if(cells.length!=4)throw new IllegalArgumentException("each row needs id and three costs");
      ids[i-1]=cells[0];
      for(int j=0;j<3;j++)if(!cells[j+1].isEmpty())costs[i-1][j]=Double.valueOf(cells[j+1]);
    }
    return new Input(ids,costs,threshold);
  }

  private void encrypt(HttpExchange x) throws IOException {
    try {
      requirePost(x);Input in=input(x);StringBuilder out=new StringBuilder("{\"rows\":[");
      for(int i=0;i<in.costs.length;i++){
        if(i>0)out.append(',');out.append('[');
        for(int j=0;j<3;j++){
          if(j>0)out.append(',');Double v=in.costs[i][j];
          out.append(v==null?"null":quote(b64(runtime.encrypt(fixed(v)))));
        }out.append(']');
      }
      out.append("]}");json(x,200,out.toString());
    }catch(Exception e){error(x,e);}
  }

  private void encryptWorkflow(HttpExchange x) throws IOException {
    try{
      requirePost(x);Input in=input(x);String jobId=UUID.randomUUID().toString();byte[][][] encrypted=new byte[in.costs.length][3][];
      StringBuilder out=new StringBuilder("{\"jobId\":").append(quote(jobId)).append(",\"rows\":[");
      for(int i=0;i<in.costs.length;i++){
        if(i>0)out.append(',');out.append('[');
        for(int j=0;j<3;j++){if(j>0)out.append(',');Double v=in.costs[i][j];if(v==null)out.append("null");else{encrypted[i][j]=runtime.encrypt(fixed(v));out.append(quote(b64(encrypted[i][j])));}}out.append(']');
      }jobs.put(jobId,encrypted);out.append("]}");json(x,200,out.toString());
    }catch(Exception e){error(x,e);}
  }

  private void computeWorkflow(HttpExchange x) throws IOException {
    try{
      requirePost(x);String body=new String(readAll(x.getRequestBody()),StandardCharsets.UTF_8).trim();
      String[] fields=body.split("\\t",-1);if(fields.length!=2)throw new IllegalArgumentException("job id and threshold required");
      byte[][][] encrypted=jobs.get(fields[0]);if(encrypted==null)throw new IllegalArgumentException("unknown or expired encrypted job");
      double threshold=Double.parseDouble(fields[1]);byte[][] result=optimizer.optimizeEncrypted(encrypted,threshold);
      StringBuilder out=new StringBuilder("{\"ciphertexts\":[");
      for(int i=0;i<result.length;i++){if(i>0)out.append(',');out.append(quote(b64(result[i])));}out.append("]}");json(x,200,out.toString());
    }catch(Exception e){error(x,e);}
  }

  private void optimizeEncryptedDirect(HttpExchange x) throws IOException {
    try{
      requirePost(x);Input in=input(x);byte[][][] encrypted=new byte[in.costs.length][3][];
      for(int i=0;i<in.costs.length;i++)for(int j=0;j<3;j++)if(in.costs[i][j]!=null)encrypted[i][j]=runtime.encrypt(fixed(in.costs[i][j]));
      byte[][] result=optimizer.optimizeEncrypted(encrypted,in.threshold);
      StringBuilder out=new StringBuilder("{\"ciphertexts\":[");
      for(int i=0;i<result.length;i++){if(i>0)out.append(',');out.append(quote(b64(result[i])));}out.append("]}");json(x,200,out.toString());
    }catch(Exception e){error(x,e);}
  }

  private void decryptResult(HttpExchange x) throws IOException {
    try {
      requirePost(x);String body=new String(readAll(x.getRequestBody()),StandardCharsets.UTF_8).trim();
      String[] values=body.split("\\n");if(values.length<4)throw new IllegalArgumentException("incomplete encrypted result");
      BigDecimal total=new BigDecimal(runtime.decrypt(Base64.getDecoder().decode(values[0]))).movePointLeft(6);
      BigDecimal c12=new BigDecimal(runtime.decrypt(Base64.getDecoder().decode(values[1]))),c3=new BigDecimal(runtime.decrypt(Base64.getDecoder().decode(values[2])));double ratio=c12.divide(c12.add(c3),12,RoundingMode.HALF_UP).doubleValue();
      StringBuilder out=new StringBuilder("{\"totalCost\":").append(total.stripTrailingZeros().toPlainString()).append(",\"ratio\":").append(ratio).append(",\"solution\":[");
      for(int i=3;i<values.length;i++){if(i>3)out.append(',');out.append(runtime.decrypt(Base64.getDecoder().decode(values[i])));}out.append("]}");json(x,200,out.toString());
    }catch(Exception e){error(x,e);}
  }

  private void staticFile(HttpExchange x) throws IOException {
    String requested=x.getRequestURI().getPath();if(requested.equals("/"))requested="/index.html";
    Path file=webRoot.resolve(requested.substring(1)).normalize();
    if(!file.startsWith(webRoot)||!Files.isRegularFile(file)){text(x,404,"not found","text/plain");return;}
    String type=requested.endsWith(".html")?"text/html":requested.endsWith(".js")?"text/javascript":requested.endsWith(".css")?"text/css":"application/octet-stream";
    byte[] data=Files.readAllBytes(file);x.getResponseHeaders().set("Content-Type",type+"; charset=utf-8");x.sendResponseHeaders(200,data.length);x.getResponseBody().write(data);x.close();
  }
  private static void requirePost(HttpExchange x){if(!"POST".equals(x.getRequestMethod()))throw new IllegalArgumentException("POST required");}
  private static byte[] readAll(InputStream in)throws IOException{ByteArrayOutputStream out=new ByteArrayOutputStream();byte[] buffer=new byte[8192];for(int n;(n=in.read(buffer))>=0;)out.write(buffer,0,n);return out.toByteArray();}
  private static String fixed(double v){
    if(!Double.isFinite(v)||v<0)throw new IllegalArgumentException("invalid cost");
    try{return BigDecimal.valueOf(v).movePointRight(6).setScale(0,RoundingMode.UNNECESSARY).toPlainString();}
    catch(ArithmeticException e){throw new IllegalArgumentException("cost supports at most six decimal places");}
  }
  private static String b64(byte[] b){return Base64.getEncoder().encodeToString(b);}
  private static String quote(String s){return "\""+s.replace("\\","\\\\").replace("\"","\\\"")+"\"";}
  private static void error(HttpExchange x,Exception e)throws IOException{json(x,400,"{\"error\":"+quote(e.getMessage()==null?e.getClass().getSimpleName():e.getMessage())+"}");}
  private static void json(HttpExchange x,int code,String body)throws IOException{text(x,code,body,"application/json");}
  private static void text(HttpExchange x,int code,String body,String type)throws IOException{byte[] b=body.getBytes(StandardCharsets.UTF_8);x.getResponseHeaders().set("Content-Type",type+"; charset=utf-8");x.sendResponseHeaders(code,b.length);x.getResponseBody().write(b);x.close();}
  public void start(){server.start();}
  @Override public void close(){server.stop(0);runtime.close();}
  public static void main(String[] args)throws Exception{
    Path root=Paths.get(args.length>0?args[0]:"examples/optimization-demo");int port=args.length>1?Integer.parseInt(args[1]):8080;
    Path state=Paths.get(args.length>2?args[2]:"runtime/off/demo");Files.createDirectories(state);
    SociDemoServer app=new SociDemoServer(root,state,port);Runtime.getRuntime().addShutdownHook(new Thread(app::close));app.start();System.out.println("SOCI JNI demo: http://127.0.0.1:"+port);
  }
}
