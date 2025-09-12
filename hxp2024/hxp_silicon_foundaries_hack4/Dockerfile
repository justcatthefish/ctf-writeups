# see compose.yml
# or
# 1) echo 'hxp{FLAG}' > flag.txt
# 2) docker build -t hxp_hack4 .
# 3) docker run -p 8100:1024 --rm --cap-add=SYS_ADMIN --security-opt apparmor=unconfined -it hxp_hack4

FROM ubuntu:24.04

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        libpixman-1-0 \
        libepoxy0 \
        libpng16-16 \
        libjpeg9-dev \
        libsasl2-2 \
        libfdt1 \
        libnuma1 \
        libglib2.0-0 \
        libslirp0 \
        libgtk-3-0 \
        libasound2-dev \
        libbrlapi-dev \
        libcurl3-gnutls \
        libpulse0

RUN rm -rf /var/lib/apt/lists
RUN rm -rf /usr/lib/systemd/*
RUN rm -rf /etc/systemd/*

RUN useradd --create-home --shell /bin/bash ctf

COPY ynetd /sbin/
RUN mkdir -p /home/ctf/
COPY \
    qemu_build/build_package/bios-256k.bin \
    qemu_build/build_package/linuxboot_dma.bin \
    qemu_build/build_package/efi-e1000.rom \
    qemu_build/build_package/kvmvapic.bin \
    qemu_build/build_package/qemu_system_x86_64_ai1337 \
    bzImage \
    launch_vm.sh \
    /home/ctf/

COPY flag.txt /home/ctf/

RUN chmod 555 /home/ctf && \
    chown -R root:root /home/ctf && \
    chmod -R 000 /home/ctf/* && \
    chmod 500 /sbin/ynetd && \
    chmod 004 /home/ctf/bzImage && \
    chmod 004 /home/ctf/flag.txt && \
    chmod 005 /home/ctf/launch_vm.sh && \
    chmod 004 /home/ctf/bios-256k.bin && \
    chmod 004 /home/ctf/kvmvapic.bin && \
    chmod 004 /home/ctf/linuxboot_dma.bin && \
    chmod 005 /home/ctf/qemu_system_x86_64_ai1337


RUN ynetd -v

USER ctf
RUN (find --version && id --version && sed --version && grep --version) > /dev/null
RUN ! find / -writable -or -user $(id -un) -or -group $(id -Gn|sed -e 's/ / -or -group /g') 2> /dev/null | grep -Ev -m 1 '^(/dev/|/run/|/proc/|/sys/|/tmp|/var/tmp|/var/lock)'

USER root

WORKDIR /home/ctf
EXPOSE 1024

COPY initramfs.cpio /home/ctf/
RUN  chmod 004 /home/ctf/initramfs.cpio

#CMD ynetd -pow 28 -p 1024 -t 20000 -lt 48000 -lm -1 /home/ctf/launch_vm.sh
CMD ynetd -p 1024 -t 20000 -lt 48000 -lm -1 /home/ctf/launch_vm.sh
