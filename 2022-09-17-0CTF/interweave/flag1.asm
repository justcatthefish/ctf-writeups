[bits 64]

file_load_va: equ 4096 * 40

db 0x7f, 'E', 'L', 'F'
db 2
db 1
db 1
db 0
dq 0
dw 2
dw 0x3e
dd 1
dq entry_point + file_load_va
dq program_headers_start
dq 0
dd 0
dw 64
dw 0x38
dw 1
dw 0x40
dw 0
dw 0

program_headers_start:
dd 1
dd 5
dq 0
dq file_load_va
dq file_load_va
dq file_end
dq file_end
dq 0x200000

entry_point:
  ; Set eax (and, by extension, rax) to 1. (The write syscall number)
  xor eax, eax
  inc eax
  ; Set edi (and, by extension, rdi) to 1. (The stdout file descriptor)
  mov edi, eax
  ; Set esi (and, by extension, rsi) to the string's virtual address.
  mov esi, file_load_va + message
  ; Set edx (and, by extension, rdx) to the string's length.
  ; xor edx, edx
  mov edx, 0xE00
  ; Issue the write syscall
  syscall
  ; Set syscall number to 60 (exit).
  mov rax, 60
  ; Set the exit status to 0.
  xor edi, edi
  ; Exit the program.
  syscall
code_end:

message: db `replaceme`

file_end: