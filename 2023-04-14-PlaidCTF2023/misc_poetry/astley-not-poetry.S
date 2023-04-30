2


inc bx /

mov di, 99 /
inc dx /
push dx /

jmp .dec /

.loop: /
	push cx /
# dx == 2
	call .mov /
.dec: /
	call .call /
	mov cx, 0 /
	call .dl /
	mov cx, 9 /
	call .bh /
	mov cx, 818 /
	call .bl /
	mov cx, 0 /
	call .bh /
	mov cx, 9 /
	call .al /
	mov cx, 288 /
	call .cl /
	call .mov /
	inc dx /
	pop cx /
	dec cx /
js .hlt /
jnz .loop /
	call .call /
	mov cx, 13221 /
	call .bh /
	mov cx, 21 /
	call .cl /
	mov cx, 0 /
	call .bh /
	mov cx, 803 /
	call .cl /
	mov cx, 0 /
	call .bh /
	mov cx, 68 /
	call .dl /
	mov cx, 811 /
	call .cl /
	mov cx, 8236 /
	call .push /
	mov cx, 2 /
	call .al /
	mov cx, 298 /
	call .ah /
	mov cx, 990 /
	call .bl /
	mov cx, 15 /
	call .bh /
	mov cx, 24 /
	call .ah /
	mov cx, 806 /
	call .ah /
	mov cx, 3 /
	sal cx, 8 /
	call .al /
	call .mov /
	dec di /
	setne cl /
	sal cl, 1 /
	jmp .loop /

.hlt: /
call .mov /
hlt /

.ah: /
	add cx, 809 /
.dl: /
	add cx, 980 /
.cl: /
	add cx, 1546 /
.bl: /
	add cx, 980 /
.al: /
	add cx, 16649 /
	mov dx, 2 /
.bh: /
	add cx, 8293 /
.push: /
	push cx /
	mov ecx, esp /
	int 4 /
	pop cx /
	ret /


.mov: /
	mov cx, 10 /
.x: /
	dec dx /
	jmp .push /

# pre:
# -- arg in di
# -- ebx == 1
# post:
# -- clobbers ecx
# -- cl == 10
# -- edx == 2
.call: /
	mov ax, di /

	mov cl, 10 /
	div cl /
	add ax, 12336 /
	push ax /
	cmp al, 48 /
	mov dx, 1 /
	je .inc /
# .two_digits: /
	inc dx /
	.inc: /
	lea ecx, [esp+2] /
	sub cx, dx /
	mov ax, 4 /
	int 4 /
	add sp, 2 /
	mov cx, 178 /
	call .al /
	mov cx, 550 /
	call .ah /
	mov cx, 296 /
	call .cl /
	mov cx, 101 /
	call .x /
	mov cx, 115 /
	cmp di, 1 /
	setne dl /
	call .push /
	mov cx, 0 /
	call .dl /
	mov cx, 1 /
	call .bh /
	mov cx, 32 /
	call .bl /
	mov cx, 28 /
	call .ah /
	ret /


EOF
