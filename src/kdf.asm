%include "sys.inc"

extern memcpy, memset, sha256_oneshot

section .bss
hmac_cat:   resb 256
hmac_tmp:   resb 32
kdf_msg:    resb 160
kdf_u:      resb 32
kdf_t:      resb 32

section .rodata
lbl_verifier: db "NMGLFDFS-VERIFIER"
lbl_verifier_len equ $ - lbl_verifier
lbl_wrap:     db "WRAP-NMGLFDFS"
lbl_wrap_len equ $ - lbl_wrap
lbl_data:     db "DATA-KEY"
lbl_data_len equ $ - lbl_data
lbl_meta:     db "META-KEY"
lbl_meta_len equ $ - lbl_meta
lbl_sleep:    db "SLEEP-SEAL-NMGL"
lbl_sleep_len equ $ - lbl_sleep

section .text
global hmac_sha256, pbkdf2_sha256
global derive_verifier, derive_wrap_key, derive_data_key, derive_meta_key, derive_sleep_key

; rdi dst32, rsi key, rdx keylen, rcx msg, r8 msglen
hmac_sha256:
    PROLOGUE 216
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    mov r14, rcx
    mov r15, r8
    cmp r15, 160
    ja .bad
    cmp r13, 128
    ja .bad

    lea rdi, [rsp]
    xor esi, esi
    mov edx, 192
    call memset

    cmp r13, 64
    jbe .shortk
    lea rdi, [rel hmac_tmp]
    mov rsi, r12
    mov rdx, r13
    call sha256_oneshot
    test eax, eax
    jnz .bad
    lea rdi, [rsp]
    lea rsi, [rel hmac_tmp]
    mov edx, 32
    call memcpy
    jmp .pads
.shortk:
    lea rdi, [rsp]
    mov rsi, r12
    mov rdx, r13
    call memcpy
.pads:
    xor ecx, ecx
.pad:
    cmp ecx, 64
    je .inner
    mov al, [rsp+rcx]
    mov dl, al
    xor al, 0x36
    mov [rsp+64+rcx], al
    xor dl, 0x5c
    mov [rsp+128+rcx], dl
    inc ecx
    jmp .pad
.inner:
    lea rdi, [rel hmac_cat]
    lea rsi, [rsp+64]
    mov edx, 64
    call memcpy
    lea rdi, [rel hmac_cat]
    add rdi, 64
    mov rsi, r14
    mov rdx, r15
    call memcpy
    lea rdi, [rel hmac_tmp]
    lea rsi, [rel hmac_cat]
    lea rdx, [r15+64]
    call sha256_oneshot
    test eax, eax
    jnz .bad

    lea rdi, [rel hmac_cat]
    lea rsi, [rsp+128]
    mov edx, 64
    call memcpy
    lea rdi, [rel hmac_cat]
    add rdi, 64
    lea rsi, [rel hmac_tmp]
    mov edx, 32
    call memcpy
    mov rdi, rbx
    lea rsi, [rel hmac_cat]
    mov edx, 96
    call sha256_oneshot
    EPILOGUE 216
.bad:
    mov rax, -EINVAL
    EPILOGUE 216

; PBKDF2-HMAC-SHA256, dkLen = 32 (one block, block index 1).
; rdi dst, rsi pass, rdx passlen, rcx salt, r8 saltlen, r9 iters
pbkdf2_sha256:
    PROLOGUE 40
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    mov r14, rcx
    mov r15, r8
    cmp r15, 64
    ja .bad
    cmp r9, 0
    je .bad
    mov [rsp], r9             ; iters

    lea rdi, [rel kdf_msg]
    mov rsi, r14
    mov rdx, r15
    call memcpy
    lea rax, [rel kdf_msg]
    add rax, r15
    mov byte [rax], 0
    mov byte [rax+1], 0
    mov byte [rax+2], 0
    mov byte [rax+3], 1

    lea rdi, [rel kdf_u]
    mov rsi, r12
    mov rdx, r13
    lea rcx, [rel kdf_msg]
    lea r8, [r15+4]
    call hmac_sha256
    test eax, eax
    jnz .bad

    lea rdi, [rel kdf_t]
    lea rsi, [rel kdf_u]
    mov edx, 32
    call memcpy

    mov r14, 1
.loop:
    mov rax, [rsp]
    cmp r14, rax
    jae .copy
    lea rdi, [rel kdf_u]
    mov rsi, r12
    mov rdx, r13
    lea rcx, [rel kdf_u]
    mov r8, 32
    call hmac_sha256
    test eax, eax
    jnz .bad
    xor ecx, ecx
    lea r8, [rel kdf_u]
    lea r9, [rel kdf_t]
.xor:
    cmp ecx, 32
    je .next
    mov al, [r8+rcx]
    xor [r9+rcx], al
    inc ecx
    jmp .xor
.next:
    inc r14
    jmp .loop
.copy:
    mov rdi, rbx
    lea rsi, [rel kdf_t]
    mov edx, 32
    call memcpy
    xor eax, eax
    EPILOGUE 40
.bad:
    mov rax, -EINVAL
    EPILOGUE 40

; rdi dst, rsi kek(32), rdx salt(16)
derive_verifier:
    PROLOGUE 8
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    lea rdi, [rel kdf_msg]
    mov rsi, r12
    mov edx, 32
    call memcpy
    lea rdi, [rel kdf_msg+32]
    mov rsi, r13
    mov edx, 16
    call memcpy
    lea rdi, [rel kdf_msg+48]
    lea rsi, [rel lbl_verifier]
    mov edx, lbl_verifier_len
    call memcpy
    mov rdi, rbx
    lea rsi, [rel kdf_msg]
    mov edx, 48 + lbl_verifier_len
    call sha256_oneshot
    EPILOGUE 8

derive_data_key:
    ; rdi dst, rsi fs_key
    PROLOGUE 8
    mov rbx, rdi
    mov r12, rsi
    lea rdi, [rel kdf_msg]
    mov rsi, r12
    mov edx, 32
    call memcpy
    lea rdi, [rel kdf_msg+32]
    lea rsi, [rel lbl_data]
    mov edx, lbl_data_len
    call memcpy
    mov rdi, rbx
    lea rsi, [rel kdf_msg]
    mov edx, 32+lbl_data_len
    call sha256_oneshot
    EPILOGUE 8

derive_meta_key:
    PROLOGUE 8
    mov rbx, rdi
    mov r12, rsi
    lea rdi, [rel kdf_msg]
    mov rsi, r12
    mov edx, 32
    call memcpy
    lea rdi, [rel kdf_msg+32]
    lea rsi, [rel lbl_meta]
    mov edx, lbl_meta_len
    call memcpy
    mov rdi, rbx
    lea rsi, [rel kdf_msg]
    mov edx, 32+lbl_meta_len
    call sha256_oneshot
    EPILOGUE 8

derive_wrap_key:
    PROLOGUE 8
    mov rbx, rdi
    mov r12, rsi
    lea rdi, [rel kdf_msg]
    mov rsi, r12
    mov edx, 32
    call memcpy
    lea rdi, [rel kdf_msg+32]
    lea rsi, [rel lbl_wrap]
    mov edx, lbl_wrap_len
    call memcpy
    mov rdi, rbx
    lea rsi, [rel kdf_msg]
    mov edx, 32+lbl_wrap_len
    call sha256_oneshot
    EPILOGUE 8

derive_sleep_key:
    PROLOGUE 8
    mov rbx, rdi
    mov r12, rsi
    lea rdi, [rel kdf_msg]
    mov rsi, r12
    mov edx, 32
    call memcpy
    lea rdi, [rel kdf_msg+32]
    lea rsi, [rel lbl_sleep]
    mov edx, lbl_sleep_len
    call memcpy
    mov rdi, rbx
    lea rsi, [rel kdf_msg]
    mov edx, 32+lbl_sleep_len
    call sha256_oneshot
    EPILOGUE 8
