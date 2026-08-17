package com.soci.demo;

import com.soci.sdk.ConfidentialOptimizationDemoBridge;
import com.soci.sdk.ConfidentialOptimizationResult;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/** Demo-only HTTP/Java/JNI adapter for the Phase 1-5 confidential runtime. */
public final class SociDemoServer implements AutoCloseable {
  private final ConfidentialOptimizationDemoBridge bridge;
  private final HttpServer server;
  private final Path webRoot;
  private final String mode;
  private final String bindAddress;
  private final Map<String,Job> jobs=new ConcurrentHashMap<>();
  private final Map<String,AuthorizedResult> results=new ConcurrentHashMap<>();

  private static final class Input {
    final String[] ids; final Long[][] costs; final long threshold;
    final String strategy; final int gridSize;
    Input(String[] ids,Long[][] costs,long threshold,String strategy,int gridSize){
      this.ids=ids;this.costs=costs;this.threshold=threshold;
      this.strategy=strategy;this.gridSize=gridSize;
    }
  }
  private static final class Job {
    final Long[][] plain; final byte[][][] encrypted;
    Job(Long[][] plain,byte[][][] encrypted){this.plain=plain;this.encrypted=encrypted;}
  }
  private static final class AuthorizedResult {
    final Long[][] costs; final ConfidentialOptimizationResult result;
    AuthorizedResult(Long[][] costs,ConfidentialOptimizationResult result){
      this.costs=costs;this.result=result;
    }
  }

  private SociDemoServer(Path webRoot,int port,String requestedMode,
      Path runtimeDir,String cp,String keys,String host,int cspPort)throws IOException{
    this.webRoot=webRoot.toAbsolutePath().normalize();
    bridge=new ConfidentialOptimizationDemoBridge(requestedMode,
        runtimeDir.toString(),cp,keys,host,cspPort);
    mode=bridge.mode();
    String configuredBind=System.getenv("SOCI_DEMO_BIND");
    bindAddress=configuredBind==null||configuredBind.isBlank()?"127.0.0.1":configuredBind;
    server=HttpServer.create(new InetSocketAddress(bindAddress,port),0);
    server.createContext("/api/health",x->json(x,200,"{\"mode\":"+quote(mode)+",\"jni\":true,\"pipeline\":\"ThresholdConfidentialRuntime/ConfidentialOptimizer\"}"));
    server.createContext("/api/encrypt",this::encryptDirect);
    server.createContext("/api/optimize",this::optimizeDirect);
    server.createContext("/api/workflow/optimize",this::optimizeDirect);
    server.createContext("/api/workflow/encrypt",this::encryptWorkflow);
    server.createContext("/api/workflow/compute",this::computeWorkflow);
    server.createContext("/api/workflow/decrypt",this::authorizeResult);
    server.createContext("/",this::staticFile);
  }

  // First line: threshold<TAB>strategy<TAB>K; then id and three costs.
  private static Input input(HttpExchange x)throws IOException{
    String[] lines=new String(readAll(x.getRequestBody()),StandardCharsets.UTF_8).split("\\R");
    if(lines.length<2)throw new IllegalArgumentException("cost matrix is empty");
    String[] options=lines[0].split("\\t",-1);
    double threshold=Double.parseDouble(options[0]);
    if(!(threshold>=0&&threshold<1))throw new IllegalArgumentException("threshold must satisfy 0 <= T < 1");
    String strategy=options.length>1&&!options[1].isEmpty()?options[1]:"current_suffix";
    int grid=options.length>2?Integer.parseInt(options[2]):3;
    String[] ids=new String[lines.length-1];Long[][] costs=new Long[ids.length][3];
    for(int i=1;i<lines.length;i++){
      String[] cells=lines[i].split("\\t",-1);
      if(cells.length!=4)throw new IllegalArgumentException("each row needs id and three costs");
      ids[i-1]=cells[0];
      for(int j=0;j<3;j++)if(!cells[j+1].isEmpty())costs[i-1][j]=fixed(cells[j+1]);
    }
    if(ids.length>64)throw new IllegalArgumentException("Demo supports at most 64 rows");
    return new Input(ids,costs,Math.round(threshold*1_000_000),strategy,grid);
  }
  private byte[][][] encrypt(Long[][] costs){
    byte[][][] encrypted=new byte[costs.length][3][];
    for(int i=0;i<costs.length;i++)for(int j=0;j<3;j++)
      if(costs[i][j]!=null)encrypted[i][j]=bridge.encrypt(costs[i][j]);
    return encrypted;
  }
  private void encryptDirect(HttpExchange x)throws IOException{
    try{requirePost(x);Input in=input(x);json(x,200,encryptedJson(null,encrypt(in.costs)));}
    catch(Exception e){error(x,e);}
  }
  private void encryptWorkflow(HttpExchange x)throws IOException{
    try{requirePost(x);Input in=input(x);String id=UUID.randomUUID().toString();
      byte[][][] encrypted=encrypt(in.costs);jobs.put(id,new Job(in.costs,encrypted));
      json(x,200,encryptedJson(id,encrypted));
    }catch(Exception e){error(x,e);}
  }
  private ConfidentialOptimizationResult solve(byte[][][] encrypted,long threshold,
      String strategy,int grid){
    return bridge.optimize(encrypted,threshold,strategy,grid,
        "demo-"+UUID.randomUUID().toString());
  }
  private void optimizeDirect(HttpExchange x)throws IOException{
    try{requirePost(x);Input in=input(x);byte[][][] encrypted=encrypt(in.costs);
      sendResult(x,in.costs,solve(encrypted,in.threshold,in.strategy,in.gridSize),in.strategy,in.gridSize);
    }catch(Exception e){error(x,e);}
  }
  private void computeWorkflow(HttpExchange x)throws IOException{
    try{requirePost(x);String[] f=new String(readAll(x.getRequestBody()),StandardCharsets.UTF_8).trim().split("\\t",-1);
      if(f.length<2)throw new IllegalArgumentException("job id and threshold required");
      Job job=jobs.get(f[0]);if(job==null)throw new IllegalArgumentException("unknown or expired encrypted job");
      long threshold=Math.round(Double.parseDouble(f[1])*1_000_000);
      String strategy=f.length>2?f[2]:"current_suffix";int grid=f.length>3?Integer.parseInt(f[3]):3;
      sendResult(x,job.plain,solve(job.encrypted,threshold,strategy,grid),strategy,grid);
    }catch(Exception e){error(x,e);}
  }
  private void sendResult(HttpExchange x,Long[][] costs,ConfidentialOptimizationResult r,
      String strategy,int grid)throws IOException{
    if(!r.feasible)throw new IllegalArgumentException("no feasible solution");
    String resultId=UUID.randomUUID().toString();results.put(resultId,new AuthorizedResult(costs,r));
    StringBuilder out=new StringBuilder("{\"resultId\":").append(quote(resultId))
      .append(",\"mode\":").append(quote(mode)).append(",\"strategy\":").append(quote(strategy))
      .append(",\"gridSize\":").append(grid).append(",\"solution\":[");
    for(int i=0;i<r.solution.length;i++){if(i>0)out.append(',');out.append(r.solution[i]);}
    out.append("],\"ciphertexts\":[");for(int i=0;i<r.ciphertexts.length;i++){if(i>0)out.append(',');out.append(quote(b64(r.ciphertexts[i])));}
    out.append("],\"stats\":{").append("\"visited_nodes\":").append(r.visitedNodes)
      .append(",\"pruned_nodes\":").append(r.prunedNodes)
      .append(",\"candidate_count\":").append(r.candidateCount)
      .append(",\"prune_predicates\":").append(r.prunePredicates)
      .append(",\"accept_predicates\":").append(r.acceptPredicates)
      .append(",\"scmp_logical_items\":").append(r.scmpLogicalItems)
      .append(",\"scmp_dispatches\":").append(r.scmpDispatches)
      .append(",\"smul_logical_items\":").append(r.smulLogicalItems)
      .append(",\"smul_dispatches\":").append(r.smulDispatches)
      .append(",\"cp_ecalls\":").append(r.cpEcalls)
      .append(",\"csp_ecalls\":").append(r.cspEcalls)
      .append(",\"csp_requests\":").append(r.cspRequests)
      .append(",\"predicate_reveals\":").append(r.predicateReveals)
      .append(",\"secure_bit_and_items\":").append(r.secureBitAndItems)
      .append(",\"predicate_csp_encryptions\":").append(r.predicateCspEncryptions)
      .append(",\"predicate_final_threshold_decrypts\":").append(r.predicateFinalThresholdDecrypts)
      .append(",\"host_encrypt_calls\":").append(r.hostEncryptCalls)
      .append(",\"host_scalar_powm_calls\":").append(r.hostScalarPowmCalls)
      .append(",\"host_encrypt_seconds\":").append(r.hostEncryptSeconds)
      .append(",\"host_scalar_powm_seconds\":").append(r.hostScalarPowmSeconds)
      .append(",\"cp_enclave_seconds\":").append(r.cpEnclaveSeconds)
      .append(",\"csp_enclave_seconds\":").append(r.cspEnclaveSeconds)
      .append(",\"network_seconds\":").append(r.networkSeconds)
      .append(",\"csp_request_seconds\":").append(r.cspRequestSeconds)
      .append(",\"csp_encrypt_seconds\":").append(r.cspEncryptSeconds)
      .append(",\"csp_parse_serialize_seconds\":").append(r.cspParseSerializeSeconds)
      .append(",\"csp_socket_send_seconds\":").append(r.cspSocketSendSeconds)
      .append(",\"fused_cp_rsa_private_powm_seconds\":").append(r.fusedCpRsaPrivatePowmSeconds)
      .append(",\"fused_csp_rsa_public_powm_seconds\":").append(r.fusedCspRsaPublicPowmSeconds)
      .append(",\"fused_garble_seconds\":").append(r.fusedGarbleSeconds)
      .append(",\"fused_circuit_evaluate_seconds\":").append(r.fusedCircuitEvaluateSeconds)
      .append(",\"fused_f_request_seconds\":").append(r.fusedFRequestSeconds)
      .append(",\"fused_g_request_seconds\":").append(r.fusedGRequestSeconds)
      .append(",\"preprocessing_seconds\":").append(r.preprocessingSeconds)
      .append(",\"search_seconds\":").append(r.searchSeconds)
      .append(",\"total_seconds\":").append(r.totalSeconds).append("}}");
    json(x,200,out.toString());
  }
  private void authorizeResult(HttpExchange x)throws IOException{
    try{requirePost(x);String id=new String(readAll(x.getRequestBody()),StandardCharsets.UTF_8).trim();
      AuthorizedResult a=results.get(id);if(a==null)throw new IllegalArgumentException("unknown or expired authorized result");
      long total=0,c12=0,c3=0;for(int i=0;i<a.result.solution.length;i++){
        long value=a.costs[i][a.result.solution[i]-1];total=Math.addExact(total,value);
        if(a.result.solution[i]<3)c12=Math.addExact(c12,value);else c3=Math.addExact(c3,value);
      }
      StringBuilder out=new StringBuilder("{\"totalCost\":").append(total/1_000_000.0)
        .append(",\"ratio\":").append((double)c12/(c12+c3)).append(",\"solution\":[");
      for(int i=0;i<a.result.solution.length;i++){if(i>0)out.append(',');out.append(a.result.solution[i]);}
      out.append("]}");json(x,200,out.toString());
    }catch(Exception e){error(x,e);}
  }
  private static String encryptedJson(String jobId,byte[][][] rows){StringBuilder out=new StringBuilder("{");
    if(jobId!=null)out.append("\"jobId\":").append(quote(jobId)).append(',');out.append("\"rows\":[");
    for(int i=0;i<rows.length;i++){if(i>0)out.append(',');out.append('[');for(int j=0;j<3;j++){if(j>0)out.append(',');out.append(rows[i][j]==null?"null":quote(b64(rows[i][j])));}out.append(']');}
    return out.append("]}").toString();}
  private void staticFile(HttpExchange x)throws IOException{String requested=x.getRequestURI().getPath();if(requested.equals("/"))requested="/index.html";Path file=webRoot.resolve(requested.substring(1)).normalize();if(!file.startsWith(webRoot)||!Files.isRegularFile(file)){text(x,404,"not found","text/plain");return;}String type=requested.endsWith(".html")?"text/html":requested.endsWith(".js")?"text/javascript":requested.endsWith(".css")?"text/css":"application/octet-stream";byte[] data=Files.readAllBytes(file);x.getResponseHeaders().set("Content-Type",type+"; charset=utf-8");x.sendResponseHeaders(200,data.length);x.getResponseBody().write(data);x.close();}
  private static long fixed(String value){try{long fixed=new java.math.BigDecimal(value).movePointRight(6).longValueExact();if(fixed<0||fixed>=(1L<<36))throw new ArithmeticException();return fixed;}catch(Exception e){throw new IllegalArgumentException("cost must be non-negative, below 68719.476736, with at most six decimals");}}
  private static void requirePost(HttpExchange x){if(!"POST".equals(x.getRequestMethod()))throw new IllegalArgumentException("POST required");}
  private static byte[] readAll(InputStream in)throws IOException{ByteArrayOutputStream out=new ByteArrayOutputStream();byte[] b=new byte[8192];for(int n;(n=in.read(b))>=0;)out.write(b,0,n);return out.toByteArray();}
  private static String b64(byte[] b){return Base64.getEncoder().encodeToString(b);}private static String quote(String s){return "\""+s.replace("\\","\\\\").replace("\"","\\\"")+"\"";}
  private static void error(HttpExchange x,Exception e)throws IOException{json(x,400,"{\"error\":"+quote(e.getMessage()==null?e.getClass().getSimpleName():e.getMessage())+"}");}
  private static void json(HttpExchange x,int code,String body)throws IOException{text(x,code,body,"application/json");}private static void text(HttpExchange x,int code,String body,String type)throws IOException{byte[] b=body.getBytes(StandardCharsets.UTF_8);x.getResponseHeaders().set("Content-Type",type+"; charset=utf-8");x.sendResponseHeaders(code,b.length);x.getResponseBody().write(b);x.close();}
  public void start(){server.start();}public void close(){server.stop(0);bridge.close();}
  public static void main(String[] args)throws Exception{
    if(args.length<4)throw new IllegalArgumentException("WEB_ROOT PORT MODE RUNTIME_DIR [CP KEY_DIR HOST CSP_PORT]");
    Path root=Paths.get(args[0]);int port=Integer.parseInt(args[1]);String mode=args[2];Path runtime=Paths.get(args[3]);Files.createDirectories(runtime);
    String cp=args.length>4?args[4]:"";String keys=args.length>5?args[5]:"";String host=args.length>6?args[6]:"127.0.0.1";int csp=args.length>7?Integer.parseInt(args[7]):0;
    SociDemoServer app=new SociDemoServer(root,port,mode,runtime,cp,keys,host,csp);Runtime.getRuntime().addShutdownHook(new Thread(app::close));app.start();System.out.println("SOCI confidential demo ["+app.mode+"] listening on "+app.bindAddress+":"+port);
  }
}
