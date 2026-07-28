# Deployment

Use distinct roots: `runtime/off`, `runtime/sim/cp`, `runtime/sim/csp`,
`runtime/hw/cp`, and `runtime/hw/csp`. Generate HW keys inside the target
hardware enclave; never copy SIM or OFF key material.

Build with a named preset. `scripts/check_sgx_host.sh` is mandatory before HW
configuration. Production signing keys and TLS identities are deployment
secrets and are intentionally absent from source control.

## Portable HW container

Build and export the pinned SGX SDK/PSW 2.26 image:

```bash
./scripts/package_hw_image.sh
```

Copy the archive, checksum and `docker/compose.hw.deploy.yaml` to the SGX host.
Then load and run it:

```bash
sha256sum -c soci-sgx-hw-2.26.tar.gz.sha256
gzip -dc soci-sgx-hw-2.26.tar.gz | docker load
docker-compose -f compose.hw.deploy.yaml run --rm soci-hw check
docker-compose -f compose.hw.deploy.yaml run --rm soci-hw test
docker-compose -f compose.hw.deploy.yaml run --rm soci-hw benchmark
```

If the host exposes the newer nested device names used by eHSM, set:

```bash
export SGX_ENCLAVE_DEVICE=/dev/sgx/enclave
```

The host supplies only the enclave device, persistent data and results.
PCCS, QCNL, AESM, the provisioning device and DCAP quote libraries are not
used because this SDK does not expose remote-attestation APIs.
