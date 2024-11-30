### BabyQUEMU

in the challenge we got a QEMU build with an added I/O device called “baby”. We could interact with the device via mmio interface on 
linux (by opening and mmaping the resource file from the `/sys/fs/…` path).
The device allowed for setting an internal offset and then reading or writing 4 bytes from memory from that offset.

The device did not check for out of bounds so we could read and write the heap of the qemu process on the host from within the linux VM when being root (we had a root shell).

To exploit this we initially tried overwriting a function pointer we found in the qemu binary vmmaps which we leaked the address for from the heap.

This didn’t work as the function pointer we overwrote was triggered multiple times from multiple threads very often which crashed qemu. 
We later found that qemu also maps a RWX page probably to jit the code. 
We wrote a shellcode to that memory and this gave us a reverse shell which we used to grab the flag.
