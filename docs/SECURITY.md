# Security status

OFF is a test-only backend. Its private key is stored in a local integrity-
checked file and is not confidential. OFF data lives under `runtime/off` and
must never be used in SIM or HW.

The migrated Paillier operations are public-key encryption, homomorphic add,
scalar multiply, and full decryption. OFF remains a single-process test backend,
but its secure operations simulate the SOCI-plus message flow and decrypt only
masked operands, randomized comparison differences, or encrypted predicate
results. The SIM/HW CP/CSP runtime follows the
SOCI-plus semi-honest protocol structure: SMUL masks both operands and packs
them into one threshold-decrypted ciphertext; SCMP
decrypts only a randomized, randomly-oriented difference; SABS composes SCMP
and SMUL; and SDIV composes per-bit SCMP and SMUL rounds. CSP no longer receives
an unmasked SCMP or SDIV operand. Outside the fused predicate path, these
protocols still lack replay protection and a formal malicious-security proof,
and callers must enforce their declared
plaintext and bit-length bounds.

SIM now implements 3072-bit Paillier key generation, full decryption, SGX
randomness, sealing/unsealing, sensitive-state wiping, and role-bound
Provisioning/CP/CSP enclave images. GMP 6.2.1 is rebuilt as a trusted static
library with fixed baseline x86_64 assembly and no runtime CPUID dispatch.
GMP's standard `mpz_powm` and prime generation have not been demonstrated
constant-time and therefore are not yet production side-channel hardened.
Allocation/assertion failures abort inside the enclave and never OCALL or log
secret-bearing state.

Production gaps: authenticated provisioning of CP (`lambda1`) and CSP
(`lambda2`, `mu`) shares and their partial/combine decrypt modes, TLS 1.3 mTLS
transport with request/session/sequence binding, remote attestation binding,
and a deployment-backed anti-rollback key-version store. No secret shares are
exported as a workaround.

`PredicateEngine` is the only application-facing conversion from an
`EncryptedBit` to control-flow `bool`. Every evaluation carries a validated
session ID, operation ID, predicate type (`PRUNE_NODE` or
`ACCEPT_CANDIDATE`), depth, and node ID. Authorization happens before the
privileged final-bit resolver is invoked, and `(session_id, operation_id)` is
single-use even when resolution fails. The threshold resolver uses the
predicate-only `P` protocol; CSP rejects any combined plaintext other than
exactly 0 or 1 and never returns general plaintext on that path. The `P` frame
carries predicate type, session ID, operation ID, depth, and node ID alongside
the ciphertext and CP partial share, preserving purpose/context binding at the
protocol boundary. This is a capability and
protocol-layer boundary; deployment authorization still depends on the future
authenticated transport and attestation work listed above.

### M2B fused predicate path

In SIM/HW, optimizer predicates use a dedicated semi-honest fused path instead
of converting every SCMP result back into a Paillier `EncryptedBit`.  Paillier
SCMP naturally leaves the two parties with XOR shares: CP retains the fresh
random orientation bit and CSP retains only the randomized comparison bit, so
`compare_bit = cp_share XOR csp_share`.  CP garbles the fixed, public
`PRUNE_NODE` or `ACCEPT_CANDIDATE` Boolean circuit.  Fresh 3072-bit RSA-OT
(`RSA_F4`) transfers exactly one input label for each CSP share; OT nonces,
shares, masks, wire labels, and garbling randomness are independently sampled
for every predicate and are not reused.  XOR and NOT are local free-XOR
operations, while each Boolean AND is a garbled gate.  CSP evaluates the fixed
circuit, decodes the output label, and releases only the single final
PRUNE/ACCEPT decision bit; neither
party reconstructs an intermediate comparison or predicate wire.

The F and G transcript stages bind the session ID, operation ID, predicate
type, depth, and node ID.  A transcript is consumed at F before secret work;
malformed, mismatched, interrupted, or replayed transcripts discard pending
state and cannot be resumed under the same operation identity.  The generic
`greaterThan`, `secureMul`, and `EncryptedBit` APIs remain available to
non-predicate callers and retain their existing behavior.

This construction targets semi-honest CP and CSP only.  It is not a
malicious-secure OT or garbled-circuit implementation, does not provide OT
extension, and does not replace authenticated transport, remote attestation,
deployment authorization, anti-rollback, constant-time big-integer work, or a
formal protocol proof.  Those production gaps and the final-only optimizer
leakage boundary remain unchanged.

## Encrypted optimizer leakage boundary

The Phase 5 optimizer does not decrypt costs, linear contributions, scores,
row minima, suffix bounds, or node lower bounds. For every public grid point it
computes `LB[k] > Q * incumbent_cost` as an encrypted bit, folds those bits in
the fixed public grid order, combines the result with `linear_upper < 0`, and
passes exactly one final `PRUNE_NODE` bit through `PredicateEngine`. It does not
materialize or reveal a strongest-bound ciphertext or winning multiplier.
Before an incumbent exists, objective comparisons are skipped and the only
node predicate is encrypted ratio-feasibility pruning.

Availability, row order, method order, grid parameters, depth, node counts,
predicate counts, protocol counts, and timings remain public. Costs and all
relationships derived from them remain encrypted. Branch order is always
method1, method2, method3; there is no secret sorting, dominance elimination,
strong branching, or secret-dependent row/branch selection. Leaves still
reveal only `ACCEPT_CANDIDATE`, using feasibility and the `(total, C12)` strict
incumbent ordering. Exact ties do not update the incumbent, preserving the
fixed-DFS lexicographic-first result.

The numeric-domain check distinguishes homomorphic transient values from
operands entering SCMP/SMUL. Score differences used by SecureMin must remain
below the signed 127-bit SMUL limit. Every node bound and scaled incumbent must
fit `compare_operand_bits`, which itself cannot exceed 127. Public grid
arithmetic is checked before any secure protocol call; unsupported public
threshold-derived anchors are discarded or truncated to the maximum supported
mu rather than exposing or inspecting encrypted data.

HW mode is fail-closed: configuration requires Intel SGX SDK and the hardware
scripts require SGX CPU/device checks. It never falls back to SIM or OFF.
