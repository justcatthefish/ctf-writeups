3


# 1 a
add sp, 8 / pop eax / pop edi / mov
# 2 a
bx, 51 / jmp .esp / .call: / cmp ax, di / mov
# 3 b
cx, bp / je .ret / push esi /
# 4 c
push edx / nop / nop / push cx /
# 5 d
push ax / cmp [eax], bx / je .pop /
# 6 d
mov esi, [eax+4] / nop /
# 7 d
mov [eax], bx / .cx: / nop /
# 8 c
test si, si / mov bp, cx /
# 9 e
jz .pop / call .bx / inc
# 10 e
si / mov bp, [edx+4] / inc
# 11 e
si / sub si, 2 / cmp bp, 1 / .inc : /
# 12 c
jb .cx / cmp cx,
# 13 d
bp / ja .nop / mov bp, cx / .nop: /
# 14 d
mov eax, [edx] / call .call / nop / nop /
# 15 d
test ax, ax / nop / nop / nop /
# 16 c
nop / nop / nop / jz .cx /
# 17 f
mov esi, [eax+4] /
# 18 f
nop / nop / sub [edx+4],
# 19 f
bp / pop ax / .or: / cmp si, [eax+4] /
# 20 c
test si, si / jz .dx /
# 21 d
call .bx / cmp [edx], ax / nop /
# 22 d
jnz .or / add [edx+4], bp / nop /
# 23 d
jmp .dx / .pop: / nop / nop / nop / pop
# 24 c
ax / xor ax, ax / .dx: /
# 25 g
pop cx / pop edx / pop esi /
# 26 g
.ret: / ret / ret / ret / ret / pop esi /
# 27 g
ret / ret / ret / ret / ret / ret / pop esi /
# 28 c
.bx: / push cx / pop cx /
# 29 d
nop / nop / nop / nop / nop / nop / nop /
# 30 d
mov edx, [esi+4] / nop /
# 31 d
mov esi, [esi] / ret / .esp: / nop /
# 32 c
nop / nop / inc cx / dec cx /
# 33 h
mov bp, 45 / call .call / add [esp],
# 34 h
bp / inc bx / test ax, ax / jnz .esp /
# 35 h
nop / nop / nop / nop / mov eax, [esp] /
# 36 c
sub ax, bp / inc cx /
# 37 d
nop / nop / nop / nop / nop / nop / nop /
# 38 d
nop / nop / nop / nop / nop / nop / nop / nop / nop /
# 39 d
nop / nop / nop / nop / nop / nop / nop / nop /
# 40 c
nop / push cx / pop cx /
# 41 i
nop / nop / nop / nop / xor dl, dl /
# 42 i
nop / nop / nop / nop / xor dl, dl /
# 43 j
nop / nop / nop / nop / xor dh, dh /
# 44 j
nop / nop / nop / nop / nop / xor dh, dh /
# 45 d
nop / nop / nop / nop / nop / nop / nop /
# 46 d
nop / nop / nop / nop / nop / nop / nop / nop / nop /
# 47 d
nop / nop / nop / nop / nop / nop / nop / nop /
# 48 c
nop / nop / push cx / pop cx /
# 49 d
nop / nop / nop / nop / nop / nop / nop /
# 50 d
nop / nop / nop / nop / nop / nop / nop / nop / nop /
# 51 d
nop / nop / nop / nop / nop / nop / nop / nop /
# 52 c
nop / nop / push cx / pop cx /


EOF
