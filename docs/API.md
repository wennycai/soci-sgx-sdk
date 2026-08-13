# C API

`include/soci/soci.h` is the stable version-1 C ABI. Every operation returns a
`soci_status_t`; C++ exceptions are caught internally. Variable-length output
uses the standard two-call pattern: pass a null output to obtain the required
size, allocate, and call again. Plaintexts/scalars are decimal UTF-8 strings.
Ciphertexts and public keys are versioned binary objects carrying their mode.

Encrypted control predicates are evaluated separately from optimization via
`PredicateEngine`. Callers provide a `PredicateContext` containing
`session_id`, `operation_id`, `predicate_type`, `depth`, and `node_id`.
Only `PRUNE_NODE` and `ACCEPT_CANDIDATE` are accepted, and each operation ID is
consumed once per session. The engine returns one authorized boolean and does
not expose the predicate plaintext or a general decryption API.

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
objective, and the linearized ratio constraint. The implementation solves that
model with deterministic branch-and-bound and suffix bounds; it does not depend
on Python or PuLP at runtime.

Python exposes `Optimizer`, `OptimizationResult`, `optimize_plain`, and
`optimize_csv_plain`. Java exposes `SociOptimizer` and `OptimizationResult`.
