package com.soci.sdk;

public final class OptimizationResult {
  public final double totalCost;
  public final double ratio;
  public final int[] solution;

  public OptimizationResult(double totalCost, double ratio, int[] solution) {
    this.totalCost = totalCost;
    this.ratio = ratio;
    this.solution = solution.clone();
  }
}
