# Encrypted optimizer architecture

## Model and deterministic search

Every row selects exactly one public-available method. Method1 and method2 add
their encrypted cost to C12; method3 adds it to C3. With `alpha = SCALE - T`,
their encrypted linear contributions are:

```text
method1:  alpha * cost
method2:  alpha * cost
method3: -T * cost
```

The complete assignment must satisfy `linear >= 0` and `C3 > 0`. The objective
orders feasible assignments by total cost, then C12. An exact tie does not
replace the incumbent, so the fixed method1, method2, method3 DFS retains its
lexicographic-first solution. Method1 and method2 remain independent choices:
a more expensive C12 method can be required for ratio feasibility.

## Multiple-choice Lagrangian relaxation

For public `Q > 0` and public `mu[k] >= 0`, define:

```text
score(i,j,k) = Q * cost(i,j) - mu[k] * linear(i,j)
row_lb(i,k)  = min_j score(i,j,k)
suffix_lb(d,k) = sum(row_lb(i,k), i >= d)
```

The minimum is computed with SecureMin; its comparison bit is never revealed.
Each DFS node maintains encrypted `lag_prefix[k]`. A child only adds its
precomputed method score:

```text
lag_prefix_child[k] = lag_prefix[k] + score(depth, method, k)
LB(d,k) = lag_prefix[k] + suffix_lb(d,k)
```

For any completion `z`, row minimization gives:

```text
LB(d,k) <= Q * cost(z) - mu[k] * linear(z)
```

If the completion is feasible, `linear(z) >= 0`; since `mu[k] >= 0`:

```text
LB(d,k) <= Q * cost(z)
```

Thus every `LB(d,k)` is sound. The optimizer does not compute a strongest LB.
When an incumbent exists, `PredicateEngine` evaluates in fixed grid order:

```text
linear_upper < 0
OR OR_k(LB(d,k) > Q * incumbent_cost)
```

Only the final PRUNE bit is revealed. Equality is not pruned because an equal
total may improve C12. Without an incumbent, all objective comparisons are
skipped. `mu=0` reduces exactly to Q times the old row-min cost suffix bound.

## Normalized public grid

The dimensionless multiplier is `rho = lambda * SCALE`. With public integer
denominator D:

```text
Q = SCALE * D
mu = r
rho = r / D
```

The deterministic builder includes zero and public anchors derived from
`SCALE/(SCALE-T)` and, for nonzero T, `SCALE/T`. It caps the request at 16 grid
points and discards/truncates anchors beyond the NumericDomain-supported mu.
For `T=0`, the grid is exactly `{0}`.

## Numeric bounds

Let encrypted costs satisfy `0 <= cost < 2^b_cost`, N be max rows, and:

```text
G = max_k(abs(Q - mu[k] * alpha), Q + mu[k] * T)
```

Then a score has magnitude below `G * 2^b_cost`. SecureMin selection can
multiply a bit by the difference of two scores, conservatively requiring:

```text
b_score_delta = b_cost + ceil_log2(G) + 1 <= 127
```

A node LB contains at most one score per row:

```text
b_bound = b_cost + ceil_log2(G) + ceil_log2(N)
b_bound <= compare_operand_bits <= 127
```

There is no bound-delta requirement because bounds are compared independently
with the scaled incumbent and their encrypted comparison bits are ORed. Larger
homomorphic scalar-multiplication intermediates do not enter SMUL/SCMP, but all
public arithmetic and Paillier-domain assumptions must still be checked.

## Production wiring

```text
ThresholdConfidentialRuntime
  -> ThresholdSecureOps
  -> ConfidentialOptimizer
  -> PredicateEngine
  -> EncryptedBranchAndBoundSolver
```

The solver has no decryptor or predicate resolver. `PredicateEngine` remains
the sole PRUNE/ACCEPT control-flow reveal boundary. The old
`Optimizer::optimize_encrypted` remains OFF-only compatibility code and cannot
enter SIM/HW production wiring.

Production defaults to the current suffix bound. Lagrangian pruning is enabled
explicitly through `EncryptedBranchAndBoundConfig`; SIM/HW callers pass that
configuration through `ThresholdConfidentialConfig::solver_config`. This
conservative default reflects the measured result that K=3 reduces search
nodes but currently increases total protocol time.
