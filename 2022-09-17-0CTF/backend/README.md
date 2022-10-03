# Backend challenge

The solution was to simply embed a byte array into the .text section. This can be done with the following instruction:
```
@x = dso_local global i8 0, section ".text", align 1
```

Which one can figure out by compiling the following .c file using `clang -S -emit-llvm test.c`:
```
__attribute__ ((section(".text")))
char x = 0;
```
