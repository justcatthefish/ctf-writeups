#!/bin/sh

# Note: may need a fix in Pwndbg's vmmap.py file - changing qemu_system to qemu-system 
#diff --git a/pwndbg/aglib/kernel/vmmap.py b/pwndbg/aglib/kernel/vmmap.py
#index db2a2e987..983564783 100644
#--- a/pwndbg/aglib/kernel/vmmap.py
#+++ b/pwndbg/aglib/kernel/vmmap.py
#@@ -123,7 +123,7 @@ class QemuMachine(Machine):
#     @staticmethod
#     def get_qemu_pid():
#         try:
#-            out = subprocess.check_output(["pgrep", "qemu-system"], encoding="utf8")
#+            out = subprocess.check_output(["pgrep", "qemu_system"], encoding="utf8")
#             pids = out.strip().split("\n")
# 
#             if len(pids) == 1:

sudo -E gdb --quiet --ex 'target remote :1234'
