package com.soci.sdk;

public final class SociOptimizer {
  private final SociRuntime runtime;

  public SociOptimizer(SociRuntime runtime) {
    if (runtime == null) throw new IllegalArgumentException("runtime must not be null");
    this.runtime = runtime;
  }

  public OptimizationResult optimize(Double[][] costs) { return optimize(costs, 0.6); }

  public OptimizationResult optimize(Double[][] costs, double ratioThreshold) {
    if (costs == null) throw new IllegalArgumentException("costs must not be null");
    return runtime.optimize(costs, ratioThreshold);
  }

  public OptimizationResult optimizeCsv(String path, double ratioThreshold) {
    if (path == null) throw new IllegalArgumentException("path must not be null");
    return runtime.optimizeCsv(path, ratioThreshold);
  }

  /** Returns encrypted total, encrypted C12, encrypted C3, then encrypted methods. */
  public byte[][] optimizeEncrypted(byte[][][] costs,double ratioThreshold){
    if(costs==null)throw new IllegalArgumentException("encrypted costs must not be null");
    return runtime.optimizeEncrypted(costs,ratioThreshold);
  }
}
