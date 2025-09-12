#!/bin/bash

Args=(
    -cpu "hxp-ai1337"
    -m 128m
    -s
    -kernel bzImage
    -append "console=ttyS0 kaslr oops=panic panic=1"
    -initrd initramfs.cpio

    -snapshot
    -monitor /dev/null
    -no-reboot
    -nographic
    -display none
    -vga none
    -net none
)

./qemu_system_x86_64_ai1337 "${Args[@]}"
