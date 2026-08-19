FROM ubuntu:24.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    build-essential cmake coinor-cbc python3 ca-certificates && rm -rf /var/lib/apt/lists/*
# Install Gramine from the official repository/package for the target image.
# SGX device/DCAP passthrough is intentionally left to the deployment runtime.
WORKDIR /workspace
COPY . /workspace
RUN cmake -S . -B build/scalable -DSOCI_SGX_MODE=OFF -DSOCI_BUILD_PYTHON=OFF -DSOCI_BUILD_JAVA=OFF \
    && cmake --build build/scalable --target soci_cbc_plaintext_benchmark -j2
