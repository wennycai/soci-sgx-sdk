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
an unmasked SCMP or SDIV operand. These protocols still lack replay protection
and a formal malicious-security proof, and callers must enforce their declared
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

HW mode is fail-closed: configuration requires Intel SGX SDK and the hardware
scripts require SGX CPU/device checks. It never falls back to SIM or OFF.
