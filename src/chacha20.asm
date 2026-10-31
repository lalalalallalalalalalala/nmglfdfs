%include "sys.inc"

; Quarter round on the 16-dword state at RBX.
%macro QR 4
    mov eax, [rbx+%1*4]
    add eax, [rbx+%2*4]
    mov [rbx+%1*4], eax
    mov r8d, [rbx+%4*4]
    xor r8d, eax
    rol r8d, 16
    mov [rbx+%4*4], r8d

    mov eax, [rbx+%3*4]
    add eax, r8d
    mov [rbx+%3*4], eax
    mov r9d, [rbx+%2*4]
    xor r9d, eax
    rol r9d, 12
    mov [rbx+%2*4], r9d

    mov eax, [rbx+%1*4]
    add eax, r9d
    mov [rbx+%1*4], eax
    xor r8d, eax
    rol r8d, 8
    mov [rbx+%4*4], r8d

    mov eax, [rbx+%3*4]
    add eax, r8d
    mov [rbx+%3*4], eax
    xor r9d, eax
    rol r9d, 7
    mov [rbx+%2*4], r9d
%endmacro

section .text
global chacha20_xor

; ChaCha20 XOR (RFC 8439). dst and src may alias.
; rdi dst, rsi src, rdx len, rcx key(32), r8 nonce(12), r9 counter (u32)
chacha20_xor:
    PROLOGUE 136
    mov rbx, rdi              ; dst
    mov r12, rsi              ; src
    mov r13, rdx              ; len
    mov r14, rcx              ; key
    mov r15, r8               ; nonce
    mov [rsp+128], r9d        ; counter
.block:
    test r13, r13
    jz .done
    lea rdi, [rsp]
    mov rsi, r14
    mov rdx, r15
    mov ecx, [rsp+128]
    call chacha20_block
    mov ecx, 64
    cmp r13, 64
    jae .full
    mov ecx, r13d
.full:
    xor eax, eax
.x:
    cmp eax, ecx
    je .adv
    mov dl, [r12+rax]
    xor dl, [rsp+rax]
    mov [rbx+rax], dl
    inc eax
    jmp .x
.adv:
    add rbx, rcx
    add r12, rcx
    sub r13, rcx
    inc dword [rsp+128]
    jmp .block
.done:
    xor eax, eax
    EPILOGUE 136

; rdi = out64, rsi = key, rdx = nonce, ecx = counter
; writes 64 keystream bytes. Clobbers caller-saved; preserves rbx/r12-r15 via its own saves? 
; Called from chacha20_xor which needs rbx etc preserved. This function must preserve them.
chacha20_block:
    push rbx
    push r12
    push rbp
    sub rsp, 128
    mov rbx, rsp              ; working state
    mov rbp, rdi              ; out
    mov r12, rsi              ; key

    mov dword [rbx+0], 0x61707865
    mov dword [rbx+4], 0x3320646e
    mov dword [rbx+8], 0x79622d32
    mov dword [rbx+12], 0x6b206574
    mov eax, [r12+0]
    mov [rbx+16], eax
    mov eax, [r12+4]
    mov [rbx+20], eax
    mov eax, [r12+8]
    mov [rbx+24], eax
    mov eax, [r12+12]
    mov [rbx+28], eax
    mov eax, [r12+16]
    mov [rbx+32], eax
    mov eax, [r12+20]
    mov [rbx+36], eax
    mov eax, [r12+24]
    mov [rbx+40], eax
    mov eax, [r12+28]
    mov [rbx+44], eax
    mov [rbx+48], ecx
    mov eax, [rdx+0]
    mov [rbx+52], eax
    mov eax, [rdx+4]
    mov [rbx+56], eax
    mov eax, [rdx+8]
    mov [rbx+60], eax

    ; copy original
    mov ecx, 16
.cp:
    mov eax, [rbx+rcx*4-4]
    mov [rbx+64+rcx*4-4], eax
    dec ecx
    jnz .cp

    mov ecx, 10
.rounds:
    ; columns
    QR 0, 4, 8, 12
    QR 1, 5, 9, 13
    QR 2, 6, 10, 14
    QR 3, 7, 11, 15
    ; diagonals
    QR 0, 5, 10, 15
    QR 1, 6, 11, 12
    QR 2, 7, 8, 13
    QR 3, 4, 9, 14
    dec ecx
    jnz .rounds

    xor ecx, ecx
.add:
    cmp ecx, 16
    je .store
    mov eax, [rbx+rcx*4]
    add eax, [rbx+64+rcx*4]
    mov [rbp+rcx*4], eax
    inc ecx
    jmp .add
.store:
    add rsp, 128
    pop rbp
    pop r12
    pop rbx
    ret
