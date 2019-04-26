# Bugger re task

* Task description:  An anti-debugger... isn't that really just a bugger?
* Task author: kmh11
* Solved in jCTF by disconnect3d & Altair
* Solved by 32 teams
* rated as 200 points

We started with some static analysis but as the task description suggested it didn't go well, so we went into a more dynamic approach.

The [bugger](bugger) binary has some anti-debugging protection. This can be see e.g. via `strace` (output truncated at `// (...)`):

```
$ strace ./bugger
execve("./bugger", ["./bugger"], 0x7fffffffe3d0 /* 28 vars */) = 0
open("/proc/self/exe", O_RDONLY)        = 3
// (...)
ptrace(PTRACE_TRACEME)                  = -1 EPERM (Operation not permitted)
fstat(1, {st_mode=S_IFCHR|0620, st_rdev=makedev(136, 0), ...}) = 0
brk(NULL)                               = 0x7ffff7fff000
brk(0x7ffff8020000)                     = 0x7ffff8020000
write(1, "No debuggers. Idiot.\n", 21No debuggers. Idiot.
)  = 21
--- SIGSEGV {si_signo=SIGSEGV, si_code=SEGV_MAPERR, si_addr=NULL} ---
+++ killed by SIGSEGV (core dumped) +++
Segmentation fault (core dumped)
```

Later on, it checks for input and when we provide it, it validates the flag:
```
$ ./bugger
Hey, dude! Please enter the flag: asd
Idiot.
```
...and says `Idiot.` when its wrong.

To overcome the `ptrace` we change its result with a simple gdbscript:
```
catch syscall ptrace
run
# continue to the end of ptrace
continue
set $rax = 0
```

And we stopped on read syscall and then dumped the binary via gdb's `dump memory` command.

Then we iterated/improved the gdbscript to get further and further and to understand the binary more and more. Our final [gdbscript can be found in the repo](gdbscript_solvin). Note that we used pwndbg so it uses some of its commands.

It turned out that the logic of [dump2](dump2) was quite simple. There is a function that later checks for flag and we ended up being in it via this gdbscript: 
```
catch syscall ptrace
r
c
set $rax = 0
d 1 2
catch syscall write
d 1 2 3
catch syscall read
# this will stop before the read syscall
c
# this will stop after the read syscall
c
d 1 2 3 4
# here we are in fgets in some IO_getline func from libc
# in the end it is fgets
# we do stepret to come back to the program
stepret
stepret
stepret
stepret
stepret
si
nextcall
```

By debugging further we found out the function start with such operations:
```
fd = fopen("/proc/self/exe", "rb)
fseek(fp, 0, SEEK_END)
size = ftell(fp)
fseek(fp, 0, SEEK_SET)
fclose(fp)
some_weird_call_probably_decrypt()
```

and then has a loop, where it checks the flag. Both the loop counter and a return value (which is a boolean indicating whether the input was the correct flag) are on the stack. We defined a gdb stop hook to see those values on each stop:
```
define hook-stop
printf "i=%d, success=%d\n", *(int*)($rbp-0x6c), *(int*)($rbp-0x70)
end
```

The flag checking loop functionality was quite simple:
- check if strign starts with `actf{not_an_idiot._`
- check if the last byte - 184th byte - is `}`
- grabs a byte from memory, converts it to hexstring via `spritnf(bufx, "%02x", the_byte)`
- checks if flag consists this hexbyte via `memcmp(flag+some_index, bufx, 2)`

And we solved this by going through the loop manually and grabbing flag byte by byte.

The final flag was: `actf{not_an_idiot._b1f5cfe6cd7c7e8d093dd20e0d2e8ad555fd4e4f247529ce93aebcb8e13a8365e9ac0b0805afad333fa959572a24d701d90b615ce6a7989bbb33a1f4daab0962}`


