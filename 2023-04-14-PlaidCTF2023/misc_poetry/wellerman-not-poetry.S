3


# initialization
add sp, 8 /
pop eax /
pop edi /
mov bx, 51 /
jmp .loop /


# pre:
# -- eax == cur_node
# -- bp == cur_min_capacity
# -- edi == target_node
# -- bx == generation
# post:
# -- eax == 0 if path not found
.call: /
	mov cx, bp /
# cmp ax, si
# bh - visited
	cmp ax, di /
	je .ret /
	push esi /
	push edx /
	push cx /
	push ax /
	cmp [eax], bx /
	je .pop /
	mov [eax], bx /
	mov esi, [eax+4] /
	.nop: /
		mov bp, cx /
# mov si, [eax+4]
		test si, si /
# test si, si
		jz .pop /
		call .bx /
		mov bp, [edx+4] /
		cmp bp, 1 /
		jb .nop /
		cmp cx, bp /
		ja .ja /
		mov bp, cx /
		.ja: /
		mov eax, [edx] /
		call .call /
		test ax, ax /
		jz .nop /
		sub [edx+4], bp /
		mov esi, [eax+4] /
		pop ax /
		.push: /
			test si, si /
			jz .ax /
			call .bx /
			cmp ax, [edx] /
			jne .push /
			add [edx+4], bp /
			jmp .ax /
	.pop: /
	pop ax /
	xor ax, ax /
	.ax: /
	pop cx /
	pop edx /
	pop esi /
	.ret: /
	ret /

.bx: /
	mov edx, [esi+4] /
	mov esi, [esi] /
	ret /


.loop: /
mov bp, 45 /
call .call /
add [esp], bp /
inc bx /
test ax, ax /
jnz .loop /

mov eax, [esp] /
sub ax, bp /


EOF
