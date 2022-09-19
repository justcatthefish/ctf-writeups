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
dw 2
dw 0x40
dw 0
dw 0

program_headers_start:
dd 3
dd 4
dq message
dq file_load_va+message
dq file_load_va+message
dq 18
dq 18
dq 1

dd 1
dd 5
dq 0
dq file_load_va
dq file_load_va
dq file_end
dq file_end
dq 0x200000

entry_point:

code_end:

;message: db `replaceme`
message: db `/proc/$$PID$$/exe`, 0

file_end: