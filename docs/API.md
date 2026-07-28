# C API

`include/soci/soci.h` is the stable version-1 C ABI. Every operation returns a
`soci_status_t`; C++ exceptions are caught internally. Variable-length output
uses the standard two-call pattern: pass a null output to obtain the required
size, allocate, and call again. Plaintexts/scalars are decimal UTF-8 strings.
Ciphertexts and public keys are versioned binary objects carrying their mode.

The C++ RAII wrapper is `include/soci/soci.hpp`. Python and Java call only this
untrusted SDK layer, never ECALLs.
