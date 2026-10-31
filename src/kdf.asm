%include "sys.inc"

extern memcpy, memset, sha256_oneshot, sha256_init, sha256_update, sha256_final

section .bss
hmac_ipad:  resb 64
hmac_opad:  resb 64
hmac_inner: resb 32
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
global hmac_sha256, hmac_init, hmac_update, hmac_final, pbkdf2_sha256
global derive_verifier, derive_wrap_key, derive_data_key, derive_meta_key, derive_sleep_key

; rdi dst32, rsi key, rdx keylen, rcx msg, r8 msglen
hmac_sha256:
    PROLOGUE 8
    mov rbx, rdi
    mov r12, rcx
    mov r13, r8
    mov rdi, rsi
    mov rsi, rdx
    call hmac_init
    test eax, eax
    jnz .ret
    mov rdi, r12
    mov rsi, r13
    call hmac_update
    mov rdi, rbx
    call hmac_final
    xor eax, eax
.ret:
    EPILOGUE 8

; rdi key, rsi keylen. Starts the inner hash (ipad already absorbed).
hmac_init:
    PROLOGUE 8
    mov rbx, rdi
    mov r12, rsi
    cmp r12, 128
    ja .bad
    cmp r12, 64
    jbe .shortk
    lea rdi, [rel hmac_tmp]
    mov rsi, rbx
    mov rdx, r12
    call sha256_oneshot
    test eax, eax
    jnz .ret
    lea rbx, [rel hmac_tmp]
    mov r12d, 32
.shortk:
    lea rdi, [rel hmac_ipad]
    xor esi, esi
    mov edx, 128
    call memset
    lea rdi, [rel hmac_ipad]
    mov rsi, rbx
    mov rdx, r12
    call memcpy
    lea rdi, [rel hmac_opad]
    mov rsi, rbx
    mov rdx, r12
    call memcpy
    xor ecx, ecx
    lea r8, [rel hmac_ipad]
    lea r9, [rel hmac_opad]
.pad:
    cmp ecx, 64
    je .go
    mov al, [r8+rcx]
    mov dl, al
    xor al, 0x36
    mov [r8+rcx], al
    xor dl, 0x5c
    mov [r9+rcx], dl
    inc ecx
    jmp .pad
.go:
    call sha256_init
    lea rdi, [rel hmac_ipad]
    mov esi, 64
    call sha256_update
    xor eax, eax
    jmp .ret
.bad:
    mov rax, -EINVAL
.ret:
    EPILOGUE 8

; rdi data, rsi len
hmac_update:
    jmp sha256_update

; rdi dst32
hmac_final:
    PROLOGUE 8
    mov rbx, rdi
    lea rdi, [rel hmac_inner]
    call sha256_final
    call sha256_init
    lea rdi, [rel hmac_opad]
    mov esi, 64
    call sha256_update
    lea rdi, [rel hmac_inner]
    mov esi, 32
    call sha256_update
    mov rdi, rbx
    call sha256_final
    xor eax, eax
    EPILOGUE 8

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
