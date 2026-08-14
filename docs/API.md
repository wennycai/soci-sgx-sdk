# C API

`include/soci/soci.h` is the stable version-1 C ABI. Every operation returns a
`soci_status_t`; C++ exceptions are caught internally. Variable-length output
uses the standard two-call pattern: pass a null output to obtain the required
size, allocate, and call again. Plaintexts/scalars are decimal UTF-8 strings.
Ciphertexts and public keys are versioned binary objects carrying their mode.

Encrypted control predicates are evaluated separately from optimization via
`PredicateEngine`. Callers provide a `PredicateContext` containing
`session_id`, `operation_id`, `predicate_type`, `depth`, and `node_id`.
Only the typed `pruneNode` and `acceptCandidate` entry points are exposed, and
each operation ID is consumed once per session. The engine returns one
authorized boolean and does not expose the predicate plaintext or a general
decryption API. Callers provide encrypted numeric `PruneInputs` or
`AcceptInputs`; they cannot provide an already-computed relation bit. The
engine constructs `linear_upper < 0 || OR_k(cost_lower[k] > incumbent_cost)`
for prune (and skips every objective comparison before an incumbent exists),
and constructs feasibility plus the `(cost, c12)` incumbent ordering for
acceptance entirely through `SecureOps` before revealing exactly one final bit.

The C++ RAII wrapper is `include/soci/soci.hpp`. Python and Java call only this
untrusted SDK layer, never ECALLs.

## Optimization operator

`include/soci/optimization.hpp` provides the fixed `n x 3` optimization model.
Costs are decimal strings (up to six fractional digits) or `std::nullopt` for an
unavailable method. `soci::optimization::Optimizer` encrypts the cost matrix and
uses homomorphic addition/scalar multiplication to verify the authorized final
result. `optimize_plain` is the independent reference solver.

The model follows PuLP `LpProblem` semantics: one binary variable `x[i,j]` per
available method, an exactly-one constraint for every row, a linear minimum-cost
objective, and the linearized ratio constraint. The encrypted implementation
keeps the fixed method1, method2, method3 DFS order and defaults to a
multiple-choice Lagrangian suffix relaxation. It does not compress method1 and
method2 or depend on Python/PuLP at runtime.

`EncryptedBranchAndBoundConfig::cost_bound` selects the production
`lagrangian` bound or the compatibility/benchmark `current_suffix` bound.
`LagrangianGridConfig` contains the public deterministic normalized-grid
parameters: `denominator`, `requested_size` (1 through 16), and `span_factor`.
The builder uses `Q = SCALE * denominator`, represents `mu` as an integer, and
always includes zero. A threshold of zero reduces the grid to `{0}`. Grid
parameters affect only performance, not feasibility, optimality, DFS order, or
tie-breaking. Production defaults to `current_suffix`; Lagrangian is an
explicit opt-in because the current benchmark reduces nodes but increases
end-to-end latency. `ThresholdConfidentialConfig::solver_config` exposes the
same choice and grid parameters to SIM/HW callers.

`EncryptedOptimizationStats` reports visited/pruned/candidate and predicate
counts plus preprocessing, search, and total seconds. Timing and structural
counts are public metadata under the documented security model.

Python exposes `Optimizer`, `OptimizationResult`, `optimize_plain`, and
`optimize_csv_plain`. Java exposes `SociOptimizer` and `OptimizationResult`.
