%include "sys.inc"

extern memset, memcpy, sha256_K

section .bss
sha_H:      resd 8
sha_W:      resd 64
sha_blk:    resb 64
sha_nblk:   resq 1
sha_total:  resq 1

section .text
global sha256_init, sha256_update, sha256_final, sha256_oneshot

sha256_init:
    mov dword [rel sha_H+0], 0x6a09e667
    mov dword [rel sha_H+4], 0xbb67ae85
    mov dword [rel sha_H+8], 0x3c6ef372
    mov dword [rel sha_H+12], 0xa54ff53a
    mov dword [rel sha_H+16], 0x510e527f
    mov dword [rel sha_H+20], 0x9b05688c
    mov dword [rel sha_H+24], 0x1f83d9ab
    mov dword [rel sha_H+28], 0x5be0cd19
    mov qword [rel sha_nblk], 0
    mov qword [rel sha_total], 0
    xor eax, eax
    ret

; rdi = data, rsi = len. Streaming, any length.
sha256_update:
    PROLOGUE 8
    mov rbx, rdi
    mov r12, rsi
    add [rel sha_total], r12
    mov rcx, [rel sha_nblk]
    test rcx, rcx
    jz .full
    mov rax, 64
    sub rax, rcx
    mov rdx, r12
    cmp rdx, rax
    jbe .take
    mov rdx, rax
.take:
    mov r13, rdx
    lea rdi, [rel sha_blk]
    add rdi, rcx
    mov rsi, rbx
    call memcpy
    add rbx, r13
    sub r12, r13
    add [rel sha_nblk], r13
    cmp qword [rel sha_nblk], 64
    jb .done
    lea rsi, [rel sha_blk]
    call sha256_compress
    mov qword [rel sha_nblk], 0
.full:
    cmp r12, 64
    jb .tail
    mov rsi, rbx
    call sha256_compress
    add rbx, 64
    sub r12, 64
    jmp .full
.tail:
    test r12, r12
    jz .done
    lea rdi, [rel sha_blk]
    mov rsi, rbx
    mov rdx, r12
    call memcpy
    mov [rel sha_nblk], r12
.done:
    xor eax, eax
    EPILOGUE 8

; rdi = dst 32 bytes
sha256_final:
    PROLOGUE 8
    mov rbx, rdi
    mov rcx, [rel sha_nblk]
    lea r11, [rel sha_blk]
    mov byte [r11+rcx], 0x80
    inc rcx
    mov [rel sha_nblk], rcx
    cmp rcx, 56
    jbe .padlen
    lea rdi, [rel sha_blk]
    add rdi, rcx
    xor esi, esi
    mov rax, 64
    sub rax, rcx
    mov rdx, rax
    call memset
    lea rsi, [rel sha_blk]
    call sha256_compress
    mov qword [rel sha_nblk], 0
.padlen:
    mov rcx, [rel sha_nblk]
    lea rdi, [rel sha_blk]
    add rdi, rcx
    xor esi, esi
    mov rax, 56
    sub rax, rcx
    mov rdx, rax
    call memset
    mov rax, [rel sha_total]
    shl rax, 3
    mov rcx, 8
    lea r8, [rel sha_blk]
    add r8, 56
.be:
    dec rcx
    mov rdx, rax
    and edx, 0xff
    mov [r8+rcx], dl
    shr rax, 8
    test rcx, rcx
    jnz .be
    lea rsi, [rel sha_blk]
    call sha256_compress
    xor ecx, ecx
    lea rdx, [rel sha_H]
.sw:
    cmp ecx, 8
    je .ok
    mov eax, [rdx+rcx*4]
    bswap eax
    mov [rbx+rcx*4], eax
    inc ecx
    jmp .sw
.ok:
    xor eax, eax
    EPILOGUE 8

; rdi = dst (32 bytes), rsi = src, rdx = len
sha256_oneshot:
    PROLOGUE 8
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    call sha256_init
    mov rdi, r12
    mov rsi, r13
    call sha256_update
    mov rdi, rbx
    call sha256_final
    xor eax, eax
    EPILOGUE 8

; rsi = 64-byte block. Updates sha_H. Leaf except it uses only regs/bss.
sha256_compress:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov rbp, rsi
    lea rsi, [rel sha_W]

    xor ecx, ecx
.w0:
    cmp ecx, 16
    je .wexp
    mov eax, [rbp+rcx*4]
    bswap eax
    mov [rsi+rcx*4], eax
    inc ecx
    jmp .w0
.wexp:
    cmp ecx, 64
    je .init
    mov eax, [rsi+rcx*4-60]   ; W[i-15]
    mov r8d, eax
    ror r8d, 7
    mov r9d, eax
    ror r9d, 18
    xor r8d, r9d
    mov r9d, eax
    shr r9d, 3
    xor r8d, r9d              ; s0
    mov eax, [rsi+rcx*4-8]    ; W[i-2]
    mov r9d, eax
    ror r9d, 17
    mov r10d, eax
    ror r10d, 19
    xor r9d, r10d
    mov r10d, eax
    shr r10d, 10
    xor r9d, r10d             ; s1
    mov eax, [rsi+rcx*4-64]   ; W[i-16]
    add eax, r8d
    add eax, [rsi+rcx*4-28]   ; W[i-7]
    add eax, r9d
    mov [rsi+rcx*4], eax
    inc ecx
    jmp .wexp
.init:
    mov eax, [rel sha_H+0]
    mov ebx, [rel sha_H+4]
    mov r12d, [rel sha_H+8]
    mov r13d, [rel sha_H+12]
    mov r14d, [rel sha_H+16]
    mov r15d, [rel sha_H+20]
    ; g and h on stack
    sub rsp, 16
    mov edx, [rel sha_H+24]
    mov [rsp], edx
    mov edx, [rel sha_H+28]
    mov [rsp+4], edx
    xor ecx, ecx
.round:
    cmp ecx, 64
    je .add
    ; S1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25)
    mov r8d, r14d
    ror r8d, 6
    mov r9d, r14d
    ror r9d, 11
    xor r8d, r9d
    mov r9d, r14d
    ror r9d, 25
    xor r8d, r9d
    ; ch = (e & f) ^ (~e & g)
    mov r9d, r14d
    and r9d, r15d
    mov r10d, r14d
    not r10d
    and r10d, [rsp]           ; g
    xor r9d, r10d
    ; temp1 = h + S1 + ch + K + W
    mov r11d, [rsp+4]         ; h
    add r11d, r8d
    add r11d, r9d
    lea rdx, [rel sha256_K]
    mov edx, [rdx+rcx*4]
    add r11d, edx
    lea rdx, [rel sha_W]
    mov edx, [rdx+rcx*4]
    add r11d, edx
    ; S0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22)
    mov r8d, eax
    ror r8d, 2
    mov r9d, eax
    ror r9d, 13
    xor r8d, r9d
    mov r9d, eax
    ror r9d, 22
    xor r8d, r9d
    ; maj = (a&b) ^ (a&c) ^ (b&c)
    mov r9d, eax
    and r9d, ebx
    mov r10d, eax
    and r10d, r12d
    xor r9d, r10d
    mov r10d, ebx
    and r10d, r12d
    xor r9d, r10d
    add r8d, r9d              ; temp2
    ; h=g, g=f, f=e, e=d+temp1, d=c, c=b, b=a, a=temp1+temp2
    mov edx, [rsp]            ; g
    mov [rsp+4], edx          ; h = g
    mov [rsp], r15d           ; g = f
    mov r15d, r14d            ; f = e
    mov r14d, r13d
    add r14d, r11d            ; e = d + temp1
    mov r13d, r12d            ; d = c
    mov r12d, ebx             ; c = b
    mov ebx, eax              ; b = a
    mov eax, r11d
    add eax, r8d              ; a = temp1+temp2
    inc ecx
    jmp .round
.add:
    add [rel sha_H+0], eax
    add [rel sha_H+4], ebx
    add [rel sha_H+8], r12d
    add [rel sha_H+12], r13d
    add [rel sha_H+16], r14d
    add [rel sha_H+20], r15d
    mov edx, [rsp]
    add [rel sha_H+24], edx
    mov edx, [rsp+4]
    add [rel sha_H+28], edx
    add rsp, 16
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
