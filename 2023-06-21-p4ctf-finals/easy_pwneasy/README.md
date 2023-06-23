# Easy pwneasy

## Task description

> This is a challenge for the greatest warriors only. The key is endurence and pwning talent. Prove you have all of them!
> `nc easy_pwneasy.zajebistyc.tf 8010`
> `4aa5d7c4bee8b58703e65cb0276707d429658b1c709a1ecd012a9eea9ee4358a_easy_pwneasy.tar.gz 4.0K`

## Analysis

This challenge was a major time burner for no particular reason.
The `main` function calls some `init()` disabling stdio buffering with [`setvbuf(3)`][setvbuf.3]
and then calls a vulnerable function `program()` (these are [Ghidra][ghidra] disassemblies with minor tweaks):

```c
void program(void)
{
  char valbuf [32];
  char addrbuf [40];
  longlong val;
  longlong addr;
  int i;

  for (i = 0; i < 3; i = i + 1) {
    printf("give me address: ");
    read(0,addrbuf,0x20);
    addr = atoll(addrbuf);
    printf("give me value: ");
    read(0,valbuf,0x20);
    val = atoll(valbuf);
    set(addr,val);
    printf("OK %s = %s\n",addrbuf,valbuf);
  }
  return;
}
```
where `set()` is defined as follows:
```
void set(longlong *addr,longlong val)
{
  if (addr != (longlong *)0x0) {
    *addr = val;
  }
  return;
}
```

## The leak

The first vulnerability is of course a triple write-what-where condition,
but we can sacrifice the first write to gain an ASLR leak by sending short strings
without null termination (say `a`) and abusing short reads.
It leaks two libc pointers on remote.

## Possibilities

The binary has ASLR enabled, but only partial RELRO,
which means we could theoretically write the address of libc's `system` to `atoll@got.plt`
in the main binary if we knew its location, and then just make it `atoll("/bin/sh")`.
But we don't know its location, so we can't.

`libc.so.6` also has partial RELRO only (not sure why though),
but I overlooked it initially and wasted some 5 hours trying the wrong approach.

I really like the technique of abusing [`atexit(3)`][atexit.3] registered handlers,
so I tried it.
Libc registers one exit handler for flushing stdio,
so it only required overwriting that one
as well as the 'pointer cookie' in the thread-local structure (TLS)
— the pointers in the handler table are mangled,
but the TLS (because of being allocated with [`mmap(2)`][mmap.2]) is fortunately
located at a constant offset from libc.

The code goes (or should go) like this:

```py
win = libc.sym.system
cookie_location = libc_base - 0x2890
new_cookie = 0x1337  # or anything else
win = rol(win ^ new_cookie, 0x11, 64)
addr = libc.sym.initial + 0x18   # initial is an artificial symbol
info('want to write %#x @ %#x', win, addr)
rdwri(cookie_location, new_cookie)  # overwrite pointer cookie
rdwri(addr, win)
rdwri(addr + 8, addr_of_bin_sh)
```

(You can read the code for [`run_exit_handlers`][reh] yourself,
with the variable [`initial`][initial.libc] defined here.)

Unfortunately, we have just wasted one write to get the leak,
so we cannot set the argument.

I tried it with every single possible one-gadget address,
of those found by `one_gadget` as well as some other ones I found.
Nearly all of them required even stack (`rsp & 0xf == 0`)
because of AVX instructions (using `xmm*` registers)
and GNU calling convention ABI provides odd stack after calls
(and even stack after returns, but this is not the case),
and others treated a register containing `1` as a pointer.

## Solution

Apparently it is enough to overwrite `.got.plt` entry #16 in libc,
which corresponds to strlen and remember to append `;sh` to the numbers you send.
The other entries called are #21 (strchrnul) and #42 (memcpy).

[atexit.3]: https://man7.org/linux/man-pages/man3/atexit.3.html
[setvbuf.3]: https://man7.org/linux/man-pages/man3/setvbuf.3.html
[mmap.2]: https://man7.org/linux/man-pages/man2/mmap.2.html
[ghidra]: https://ghidra-sre.org/
[reh]: https://elixir.bootlin.com/glibc/glibc-2.37/source/stdlib/exit.c#L38
[initial.libc]: https://elixir.bootlin.com/glibc/glibc-2.37/source/stdlib/cxa_atexit.c#L75
