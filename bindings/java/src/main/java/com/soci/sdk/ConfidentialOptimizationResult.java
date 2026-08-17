package com.soci.sdk;

/** Minimal Demo bridge result; not part of the stable Phase 7 Java API. */
public final class ConfidentialOptimizationResult {
  public final boolean feasible;
  public final int[] solution;
  public final byte[][] ciphertexts;
  public final long visitedNodes, prunedNodes, candidateCount;
  public final long prunePredicates, acceptPredicates;
  public final long scmpLogicalItems, scmpDispatches, smulLogicalItems,
      smulDispatches, cpEcalls, cspEcalls, cspRequests, predicateReveals;
  public final long secureBitAndItems, predicateCspEncryptions,
      predicateFinalThresholdDecrypts;
  public final double preprocessingSeconds, searchSeconds, totalSeconds;
  public final double hostEncryptSeconds, hostScalarPowmSeconds,
      cpEnclaveSeconds, cspEnclaveSeconds, networkSeconds;
  public final double cspRequestSeconds, cspEncryptSeconds,
      cspParseSerializeSeconds, cspSocketSendSeconds;
  public final long hostEncryptCalls, hostScalarPowmCalls;

  public ConfidentialOptimizationResult(boolean feasible, int[] solution,
      byte[][] ciphertexts, long visitedNodes, long prunedNodes,
      long candidateCount, long prunePredicates, long acceptPredicates,
      long scmpLogicalItems, long scmpDispatches, long smulLogicalItems,
      long smulDispatches, long cpEcalls, long cspEcalls, long cspRequests,
      long predicateReveals,
      long secureBitAndItems,long predicateCspEncryptions,
      long predicateFinalThresholdDecrypts,
      long hostEncryptCalls,long hostScalarPowmCalls,
      double hostEncryptSeconds,double hostScalarPowmSeconds,
      double cpEnclaveSeconds,double cspEnclaveSeconds,double networkSeconds,
      double cspRequestSeconds,double cspEncryptSeconds,
      double cspParseSerializeSeconds,double cspSocketSendSeconds,
      double preprocessingSeconds,
      double searchSeconds,double totalSeconds) {
    this.feasible=feasible; this.solution=solution.clone();
    this.ciphertexts=ciphertexts.clone(); this.visitedNodes=visitedNodes;
    this.prunedNodes=prunedNodes; this.candidateCount=candidateCount;
    this.prunePredicates=prunePredicates;
    this.acceptPredicates=acceptPredicates;
    this.scmpLogicalItems=scmpLogicalItems;this.scmpDispatches=scmpDispatches;
    this.smulLogicalItems=smulLogicalItems;this.smulDispatches=smulDispatches;
    this.cpEcalls=cpEcalls;this.cspEcalls=cspEcalls;
    this.cspRequests=cspRequests;this.predicateReveals=predicateReveals;
    this.secureBitAndItems=secureBitAndItems;
    this.predicateCspEncryptions=predicateCspEncryptions;
    this.predicateFinalThresholdDecrypts=predicateFinalThresholdDecrypts;
    this.hostEncryptCalls=hostEncryptCalls;
    this.hostScalarPowmCalls=hostScalarPowmCalls;
    this.hostEncryptSeconds=hostEncryptSeconds;
    this.hostScalarPowmSeconds=hostScalarPowmSeconds;
    this.cpEnclaveSeconds=cpEnclaveSeconds;
    this.cspEnclaveSeconds=cspEnclaveSeconds;
    this.networkSeconds=networkSeconds;
    this.cspRequestSeconds=cspRequestSeconds;
    this.cspEncryptSeconds=cspEncryptSeconds;
    this.cspParseSerializeSeconds=cspParseSerializeSeconds;
    this.cspSocketSendSeconds=cspSocketSendSeconds;
    this.preprocessingSeconds=preprocessingSeconds;
    this.searchSeconds=searchSeconds; this.totalSeconds=totalSeconds;
  }
}
