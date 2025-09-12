# Build qemu
# docker build -t qemu_build .
#
# docker run --rm --cap-add=SYS_ADMIN --security-opt apparmor=unconfine -ti qemu_build

FROM ubuntu:24.04

# Install necessary packages
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        wget \
        ca-certificates \
        xz-utils \
        python3 \
        libglib2.0-dev \
        libfdt-dev \
        libpixman-1-dev \
        zlib1g-dev \
        ninja-build \
        build-essential \
        python3-pip \
        git \
        flex \
        bison \
        python3-sphinx \
        rst2pdf

# Download qemu-9.1.1
RUN wget https://download.qemu.org/qemu-9.1.1.tar.xz
RUN tar -xf qemu-9.1.1.tar.xz

# Copy and apply the patch to add HACK-4 AI1337 emulation support
COPY 0001-Add-hack4-ai1337.patch qemu-9.1.1/

RUN cd qemu-9.1.1/ && \
    git apply 0001-Add-hack4-ai1337.patch

# Build QEMU
RUN cd qemu-9.1.1 && ./configure && make -j$(nproc) qemu-system-x86_64

# Package the binaries and specification into /build_package
RUN mkdir -p /build_package && \
    cp /qemu-9.1.1/pc-bios/bios-256k.bin /build_package && \
    cp /qemu-9.1.1/build/qemu-system-x86_64 /build_package/qemu_system_x86_64_ai1337 && \
    cp /qemu-9.1.1/pc-bios/linuxboot_dma.bin /build_package/ && \
    cp /qemu-9.1.1/pc-bios/efi-e1000.rom /build_package/ && \
    cp /qemu-9.1.1/pc-bios/kvmvapic.bin /build_package/ && \
    rst2pdf /qemu-9.1.1/docs/specs/hxp_ai1337.rst -o /build_package/hxp_ai1337.pdf

CMD /bin/bash
