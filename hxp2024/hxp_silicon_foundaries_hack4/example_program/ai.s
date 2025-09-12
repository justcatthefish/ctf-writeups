global get_scratch_info
global load_scratch
global read_scratch
global clear_scratch
global add_slices
global sub_slices
global mul_slices

%macro mts 0
db 0x0f
db 0x0a
db 0x83
%endmacro

%macro stm 0
db 0x0f
db 0x0a
db 0x84
%endmacro

%macro fscr 0
db 0x0f
db 0x0a
db 0x85
%endmacro

%macro scradd 0
db 0x0f
db 0x0a
db 0x86
%endmacro

%macro scrsub 0
db 0x0f
db 0x0a
db 0x87
%endmacro

%macro scrmul 0
db 0x0f
db 0x0a
db 0x88
%endmacro

%macro scrhlr 0
db 0x0f
db 0x0a
db 0x8a
%endmacro

%macro scrhlw 0
db 0x0f
db 0x0a
db 0x89
%endmacro

section .text

get_scratch_info:
    ; Arguments passed to this function:
    ; ptr to structure containing info -> rdi
    ;    0..7: base
    ;    8..15: default size
    ;    16..19: slice size
    ;    20..21: num slices
    push rbx
    mov rax, 0x80000022
    cpuid
    mov dword [rdi], edx
    mov dword [rdi + 4], ebx
    mov qword [rdi + 8], rax

    push rcx
    shr rcx, 10
    mov dword [rdi + 16], ecx
    pop rcx
    and rcx, 0xFF
    mov byte [rdi + 20], cl
    pop rbx
    ret

load_scratch:
    ; Arguments passed to this function:
    ; slice        -> rdi
    ; slice_offset -> rsi
    ; source       -> rdx
    ; length       -> rcx

    ; Move arguments to desired registers
    push rbx
    mov rbx, rdi      ; Move slice to rbx
    mov rdi, rsi      ; Move slice_offset to rdi
    mov rsi, rdx      ; Move source to rsi
    mov rcx, rcx      ; Length is already in rcx

    mts ; load into scratch memory

    pop rbx

    ret               ; Return to the caller

read_scratch:
    ; Arguments passed to this function:
    ; slice        -> rdi
    ; slice_offset -> rsi
    ; source       -> rdx
    ; length       -> rcx

    ; Move arguments to desired registers
    push rbx
    mov rbx, rdi      ; Move slice to rbx
    mov rdi, rsi      ; Move slice_offset to rdi
    mov rsi, rdx      ; Move destination to rsi
    mov rcx, rcx      ; Length is already in rcx
    stm

    pop rbx

    ret               ; Return to the caller

clear_scratch:
    fscr
    ret

add_slices:
    ; Arguments passed to this function:
    ; slice A      -> rdi
    ; slice B      -> rsi
    ; slice C      -> rdx
    scradd
    ret

sub_slices:
    ; Arguments passed to this function:
    ; slice A      -> rdi
    ; slice B      -> rsi
    ; slice C      -> rdx
    scrsub
    ret

mul_slices:
    ; Arguments passed to this function:
    ; slice A      -> rdi
    ; slice B      -> rsi
    ; slice C      -> rdx
    scrmul
    ret
