%include "sys.inc"

extern memset, memcpy, sha256_K

section .bss
sha_H:      resd 8
sha_W:      resd 64
sha_msg:    resb 320

section .text
global sha256_oneshot

; rdi = dst (32 bytes), rsi = src, rdx = len (0..240)
sha256_oneshot:
    PROLOGUE 8
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    cmp r13, 240
    ja .bad

    mov dword [rel sha_H+0], 0x6a09e667
    mov dword [rel sha_H+4], 0xbb67ae85
    mov dword [rel sha_H+8], 0x3c6ef372
    mov dword [rel sha_H+12], 0xa54ff53a
    mov dword [rel sha_H+16], 0x510e527f
    mov dword [rel sha_H+20], 0x9b05688c
    mov dword [rel sha_H+24], 0x1f83d9ab
    mov dword [rel sha_H+28], 0x5be0cd19

    lea rdi, [rel sha_msg]
    xor esi, esi
    mov edx, 320
    call memset
    lea rdi, [rel sha_msg]
    mov rsi, r12
    mov rdx, r13
    call memcpy
    lea rax, [rel sha_msg]
    mov byte [rax+r13], 0x80

    ; q = len + 1; pad so q % 64 == 56; total = q + 8
    lea r14, [r13+1]
    mov rax, r14
    and eax, 63
    cmp eax, 56
    jb .lt
    ja .gt
    jmp .lenf
.lt:
    mov ecx, 56
    sub ecx, eax
    add r14, rcx
    jmp .lenf
.gt:
    mov ecx, 64
    sub ecx, eax
    add ecx, 56
    add r14, rcx
.lenf:
    ; bit length at total-8, big endian. total = r14+8, field at r14
    mov rax, r13
    shl rax, 3
    ; store 8 bytes BE at sha_msg+r14
    mov rcx, 8
    lea r8, [rel sha_msg]
    add r8, r14
.bestore:
    dec rcx
    mov rdx, rax
    and edx, 0xff
    mov [r8+rcx], dl
    shr rax, 8
    test rcx, rcx
    jnz .bestore

    lea r15, [r14+8]          ; total padded length
    xor r14, r14              ; offset
.blocks:
    cmp r14, r15
    jae .out
    lea rsi, [rel sha_msg]
    add rsi, r14
    call sha256_compress
    add r14, 64
    jmp .blocks
.out:
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
.bad:
    mov rax, -EINVAL
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
