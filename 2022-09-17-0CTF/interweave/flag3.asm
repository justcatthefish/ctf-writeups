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
  mov edx, 0xC00
  ; Issue the write syscall
  syscall

  ;call compute_final_hash



compute_final_hash:
	sub	rsp, 96
	mov	r15d, 0x29000
	xorps	xmm0, xmm0
	lea	r14, [rsp + 32]
	movaps	[r14], xmm0
	movaps	[r14 + 48], xmm0
	movaps	[r14 + 32], xmm0
	movaps	[r14 + 16], xmm0
	mov	al, -128
	mov	byte [r14], al
	mov	al, 0x90
	mov	byte [r14 + 62], al
	xor	r12d, r12d
	mov	r13, rsp
.LBB1_1:
	mov	rax, r12
	shl	rax, 5
	movups	xmm0, [r15 + rax]
	movups	xmm1, [r15 + rax + 16]
	movaps	[rsp + 16], xmm1
	movaps	[rsp], xmm0
	mov	rbx, -64
.LBB1_2:
	lea	rsi, [r15 + rbx]
	add	rsi, 64
	mov	rdi, r13
	call	sha256_transform
	add	rbx, 64
	cmp	rbx, 448
	jb	.LBB1_2

	mov	rdi, r13
	mov	rsi, r14
	call	sha256_transform
	xor	eax, eax
.LBB1_4:
	mov	ecx, dword [rsp + 4*rax]
	bswap	ecx
	mov	dword [rsp + 4*rax], ecx
	inc	rax
	cmp	rax, 8
	jne	.LBB1_4

	mov	eax, 1
	mov	edi, 1
	mov	rsi, r13
	mov	edx, 32

	syscall

	inc	r12
	cmp	r12, 16
	jne	.LBB1_1


  ; Set syscall number to 60 (exit).
  mov rax, 60
  ; Set the exit status to 0.
  xor edi, edi
  ; Exit the program.
  syscall



sha256_transform:
	push	rbp
	push	r15
	push	r14
	push	r13
	push	r12
	push	rbx
	sub	rsp, 168
	xor	eax, eax
.LBB0_1:
	mov	ecx, dword [rsi + 4*rax]
	bswap	ecx
	mov	dword [rsp + 4*rax - 96], ecx
	inc	rax
	cmp	rax, 16
	jne	.LBB0_1

	mov	eax, 16
	mov	r8d, dword [rsp - 96]
.LBB0_3:
	mov	edx, dword [rsp + 4*rax - 104]
	mov	esi, edx
	rol	esi, 15
	mov	r9d, dword [rsp + 4*rax - 156]
	mov	ebx, edx
	rol	ebx, 13
	xor	ebx, esi
	shr	edx, 10
	xor	edx, ebx
	add	edx, dword [rsp + 4*rax - 124]
	mov	esi, r9d
	mov	ecx, r9d
	mov	ebp, r9d
	rol	ebp, 25
	rol	esi, 14
	add	edx, r8d
	mov	r8d, r9d
	xor	esi, ebp
	shr	ecx, 3
	xor	ecx, esi
	add	ecx, edx
	mov	dword [rsp + 4*rax - 96], ecx
	inc	rax
	cmp	rax, 64
	jne	.LBB0_3

	mov	esi, dword [rdi]
	mov	edx, dword [rdi + 4]
	mov	r9d, dword [rdi + 8]
	mov	r11d, dword [rdi + 12]
	mov	r10d, dword [rdi + 16]
	mov	eax, dword [rdi + 20]
	mov	ebp, dword [rdi + 24]
	mov	ebx, dword [rdi + 28]
	xor	ecx, ecx
	lea	r8, [rel k]
	mov	dword [rsp - 128], esi
	mov	dword [rsp - 124], edx
	mov	dword [rsp - 100], ebx
	mov	dword [rsp - 104], ebp
	mov	dword [rsp - 108], eax
	mov	dword [rsp - 112], r10d
	mov	dword [rsp - 116], r11d
	mov	dword [rsp - 120], r9d
.LBB0_5:
	mov	r14d, r9d
	mov	r13d, r10d
	mov	r12d, eax
	mov	r15d, ebp
	mov	r9d, edx
	mov	edx, esi
	mov	eax, r10d
	rol	eax, 26
	mov	esi, r10d
	rol	esi, 21
	xor	esi, eax
	mov	eax, r10d
	rol	eax, 7
	xor	eax, esi
	mov	esi, r12d
	and	esi, r10d
	add	esi, eax
	add	esi, ebx
	mov	ebx, r10d
	not	ebx
	and	ebx, ebp
	add	ebx, esi
	add	ebx, dword [rcx + r8]
	add	ebx, dword [rsp + rcx - 96]
	mov	eax, edx
	rol	eax, 30
	mov	esi, edx
	rol	esi, 19
	xor	esi, eax
	mov	eax, edx
	rol	eax, 10
	xor	eax, esi
	mov	ebp, r9d
	xor	ebp, r14d
	and	ebp, edx
	mov	esi, r9d
	and	esi, r14d
	xor	esi, ebp
	add	esi, eax
	mov	r10d, r11d
	add	r10d, ebx
	add	esi, ebx
	add	rcx, 4
	mov	ebx, r15d
	mov	ebp, r12d
	mov	eax, r13d
	mov	r11d, r14d
	cmp	rcx, 256
	jne	.LBB0_5

	add	esi, dword [rsp - 128]
	mov	dword [rdi], esi
	add	edx, dword [rsp - 124]
	mov	dword [rdi + 4], edx
	add	r9d, dword [rsp - 120]
	mov	dword [rdi + 8], r9d
	add	r14d, dword [rsp - 116]
	mov	dword [rdi + 12], r14d
	add	r10d, dword [rsp - 112]
	mov	dword [rdi + 16], r10d
	add	r13d, dword [rsp - 108]
	mov	dword [rdi + 20], r13d
	add	r12d, dword [rsp - 104]
	mov	dword [rdi + 24], r12d
	add	r15d, dword [rsp - 100]
	mov	dword [rdi + 28], r15d
	add	rsp, 168
	pop	rbx
	pop	r12
	pop	r13
	pop	r14
	pop	r15
	pop	rbp
	ret

k dd 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2


code_end:

message: db `replaceme`

file_end: equ 0x1200