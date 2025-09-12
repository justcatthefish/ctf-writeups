#!/bin/sh

sudo -E gdb --quiet qemu_build/build_package/qemu_system_x86_64_ai1337 --ex 'attachp ai1337'
