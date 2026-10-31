%include "sys.inc"

extern crc32c_table

section .text
global crc32c, crc32c_update

; rdi = running crc, rsi = buf, rdx = len -> rax
crc32c_update:
    push rbx
    mov rax, rdi
    lea rbx, [rel crc32c_table]
    test rdx, rdx
    jz .d
.l:
    movzx ecx, byte [rsi]
    xor eax, ecx
    movzx ecx, al
    shr rax, 8
    xor eax, [rbx+rcx*4]
    inc rsi
    dec rdx
    jnz .l
.d:
    pop rbx
    ret

; rdi buf, rsi len -> eax
crc32c:
    push rbx
    push r12
    mov rbx, rdi
    mov r12, rsi
    mov rdi, 0xffffffff
    mov rsi, rbx
    mov rdx, r12
    call crc32c_update
    xor eax, 0xffffffff
    pop r12
    pop rbx
    ret
