# Standalone TEE+CBC image: Gramine + COIN-OR CBC + the benchmark-only
# soci_cbc_plaintext_benchmark.  Fully decoupled from the SIM CI image
# (docker/Dockerfile): it builds the benchmark with SOCI_SGX_MODE=OFF, needs
# no SGX SDK, and never relies on a pre-existing local image.
FROM ubuntu:22.04
ARG DEBIAN_FRONTEND=noninteractive
# China mirror by default for faster apt downloads (plain http: container
# builds here have no proxy/TLS interception setup); override with
# --build-arg APT_MIRROR=http://archive.ubuntu.com/ubuntu outside CN.
ARG APT_MIRROR=http://mirrors.aliyun.com/ubuntu
RUN sed -i "s|http://archive.ubuntu.com/ubuntu|${APT_MIRROR}|g; \
            s|http://security.ubuntu.com/ubuntu|${APT_MIRROR}|g" /etc/apt/sources.list && \
    apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake libgmp-dev libssl-dev coinor-cbc \
    python3 openssl ca-certificates curl gnupg && \
    mkdir -p /etc/apt/keyrings && \
    curl -fsSLo /etc/apt/keyrings/gramine-keyring-jammy.gpg \
      https://packages.gramineproject.io/gramine-keyring-jammy.gpg && \
    echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/gramine-keyring-jammy.gpg] https://packages.gramineproject.io/ jammy main" \
      > /etc/apt/sources.list.d/gramine.list && \
    apt-get update && apt-get install -y --no-install-recommends gramine && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /workspace
COPY . .
# The benchmark target is EXCLUDE_FROM_ALL; configure in OFF mode and build
# only that target.  SGX device/DCAP passthrough is left to the runtime.
RUN cmake -S . -B build/scalable -DSOCI_SGX_MODE=OFF \
      -DSOCI_BUILD_PYTHON=OFF -DSOCI_BUILD_JAVA=OFF && \
    cmake --build build/scalable --target soci_cbc_plaintext_benchmark -j2
CMD ["bash","-lc","scripts/test_tee_cbc_direct.sh"]
