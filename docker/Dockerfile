FROM ubuntu:22.04
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential gcc-11 g++-11 cmake ninja-build libgmp-dev libssl-dev coinor-cbc \
    python3 python3-pip openjdk-11-jdk-headless pkg-config ca-certificates wget curl gnupg lsb-release m4 file && \
    rm -rf /var/lib/apt/lists/*
RUN mkdir -p /etc/apt/keyrings && \
    curl -fsSLo /etc/apt/keyrings/gramine-keyring-jammy.gpg \
      https://packages.gramineproject.io/gramine-keyring-jammy.gpg && \
    echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/gramine-keyring-jammy.gpg] https://packages.gramineproject.io/ jammy main" \
      > /etc/apt/sources.list.d/gramine.list && \
    apt-get update && apt-get install -y --no-install-recommends gramine && \
    rm -rf /var/lib/apt/lists/*
ARG SGX_SDK_URL=https://download.01.org/intel-sgx/sgx-linux/2.26/distro/ubuntu22.04-server/sgx_linux_x64_sdk_2.26.100.0.bin
RUN wget -q "$SGX_SDK_URL" -O /tmp/sgx-sdk.bin && \
    chmod +x /tmp/sgx-sdk.bin && echo yes | /tmp/sgx-sdk.bin --prefix /opt/intel && \
    rm /tmp/sgx-sdk.bin
ENV SGX_SDK=/opt/intel/sgxsdk
ENV JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64
COPY scripts/build_gmp_sgx.sh /tmp/build_gmp_sgx.sh
COPY third_party/gmp-6.2.1.tar.xz /tmp/gmp-6.2.1.tar.xz
RUN chmod +x /tmp/build_gmp_sgx.sh && \
    GMP_SOURCE_ARCHIVE=/tmp/gmp-6.2.1.tar.xz /tmp/build_gmp_sgx.sh && \
    rm /tmp/build_gmp_sgx.sh /tmp/gmp-6.2.1.tar.xz
WORKDIR /workspace
COPY . .
CMD ["bash","-lc","scripts/build_off.sh && scripts/test_off.sh"]
