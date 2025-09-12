#!/bin/sh

mkdir unpacked
cd unpacked
cpio -idm < ../initramfs.cpio 
