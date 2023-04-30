2


# We're no strangers to love
inc bx / mov di, 99 /
# You know the rules and so do I
inc dx / push dx / jmp .dec / .loop: / push cx /
# A full commitment's what I'm thinking of
call .pop / .dec: / call .call /  mov cx, 0 / push 9 /
# You wouldn't get this from any other guy
call .dl / pop ecx / call .nop / mov cx,
#
# I just wanna tell you how I'm feeling
818 / call .bl / mov cx, 0 / nop / nop /
# Gotta make you understand
call .nop / mov cx, 9 / call .dx /
#
# Never gonna give you up
mov cx, 288 / nop /
# Never gonna let you down
call .cl / call .pop / inc dx / nop /
# Never gonna run around and desert you
pop cx / dec cx / js .hlt / jnz .loop / call .call / nop /
# Never gonna make you cry
call .nop / mov cx, 21 / nop /
# Never gonna say goodbye
call .cl / mov cx, 0 / call .nop /
# Never gonna tell a lie and hurt you
push cx / mov cx, 803 / call .cl / nop /
#
# We've known each other for so long
pop cx / call .push / nop / nop / nop /
# Your heart's been aching but you're too shy to say it
mov cx, 68 / call .dl / mov cx, 811 / nop /
# Inside we both know what's been going on
call .cl / mov cx, 8236 / nop /
# We know the game and we're gonna play it
call .push / mov cx, 2 / call .dx / nop /
#
# And if you ask me how I'm feeling
mov cx, 298 / call .ah / nop / nop /
# Don't tell me you're too blind to see
mov cx, 990 / call .bl / mov
#
# Never gonna give you up
cx, 15 / call .nop / nop /
# Never gonna let you down
mov cx, 24 / call .ah / nop /
# Never gonna run around and desert you
mov cx, 806 / call .ah / mov cx, 3 / nop /
# Never gonna make you cry
sal cx, 8 / call .dx / call .pop /
# Never gonna say goodbye
dec di / setne cl / nop /
# Never gonna tell a lie and hurt you
sal cl, 1 / jmp .loop / .hlt: / call .pop / hlt / nop /
# Never gonna give you up
.ah: / add cx, 809 / nop /
# Never gonna let you down
.dl: / add cx, 980 / nop /
# Never gonna run around and desert you
.cl: / add cx, 1546 / .bl: / nop /
# Never gonna make you cry
add cx, 980 / .dx: / nop /
# Never gonna say goodbye
mov dx, 2 / nop / nop / nop /
# Never gonna tell a lie and hurt you
add cx, 16649 / .nop: / nop /
#
#
# We've known each other for so long
add cx, 8293 / .push: / nop /
# Your heart's been aching but you're too shy to say it
push cx / mov ecx, esp / int 4 / pop cx / ret / .pop: /
# Inside we both know what's been going on
mov cx, 10 / .x: / dec dx / jmp .push / nop /
# We know the game and we're gonna play it
.call: / mov ax, di / mov cl, 10 / nop / nop /
#
# I just wanna tell you how I'm feeling
div cl / mov dx, 1 / nop / nop / nop /
# Gotta make you understand
mov cx, 12336 /
#
# Never gonna give you up
add ax, cx / nop / nop /
# Never gonna let you down
cmp al, 48 / je .inc  / nop /
# Never gonna run around and desert you
inc dx / .inc: / push ax / mov ax, 4 / pop cx / nop /
# Never gonna make you cry
nop / lea ecx, [esp] / nop /
# Never gonna say goodbye
sub cx, dx / int 4 / nop /
# Never gonna tell a lie and hurt you
mov cx, 178 / call .dx / nop /
# Never gonna give you up
mov cx, 550 / nop /
# Never gonna let you down
call .ah / push 296 / pop
# Never gonna run around and desert you
ecx / call .cl / mov cx, 101 / nop /
# Never gonna make you cry
call .x / cmp di, 1 / nop /
# Never gonna say goodbye
setne dl / nop / nop / nop /
# Never gonna tell a lie and hurt you
mov cx, 115 / call .push / nop / nop /
# Never gonna give you up
mov cx, 0 / call .dl / nop /
# Never gonna let you down
mov cx, 1 / call .nop / nop /
# Never gonna run around and desert you
mov cx, 32 / call .bl / mov cx, 28 / nop /
# Never gonna make you cry
call .ah / sar cx, 1 / nop /
# Never gonna say goodbye
sub cx, 1421 / nop /
# Never gonna tell a lie and hurt you
ret / nop / nop / nop / nop / nop / nop / nop / nop / nop /


EOF
