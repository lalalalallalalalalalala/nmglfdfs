%include "sys.inc"

extern memcpy, sha256_oneshot, chacha20_xor, aes_sbox, aes_inv_sbox

; Per-block pipeline:
;   encrypt: bitflip -> math[method] -> ChaCha20
;   decrypt: ChaCha20 -> inv math[method] -> bitflip
; method = timestamp_ms % 10
; Caller passes a parameter block:
;   +0  dst ptr, +8 src ptr, +16 len, +24 key ptr,
;   +32 timestamp, +40 generation, +48 file offset, +56 inode,
;   +64 decrypt flag (0 encrypt, 1 decrypt)

section .bss
g_buf:      resq 1
g_len:      resq 1
g_key:      resq 1
g_ts:       resq 1
g_gen:      resq 1
g_off:      resq 1
g_ino:      resq 1
g_method:   resq 1
g_dec:      resb 1
pp_bkey:    resb 32
pp_sub:     resb 32
pp_nonce:   resb 16
pp_mat:     resb 128

section .rodata
lbl_bf:     db "NMGL-BITFLIP"
lbl_m:      db "NMGL-METHOD"
math_tab:
    dq m_modmul, m_feistel32, m_bitperm, m_gfmul, m_sbox
    dq m_arx, m_nibble, m_affine, m_feistel64, m_mixcol

section .text
global pipeline_apply, bitflip_run

; rdi = parameter block
pipeline_apply:
    PROLOGUE 8
    call load_params
    test eax, eax
    jnz .ret
    mov rax, [rel g_ts]
    xor edx, edx
    mov ecx, 10
    div rcx
    mov [rel g_method], rdx
    mov al, [rel g_dec]
    test al, al
    jnz .dec
    call apply_bitflip
    call derive_method_key
    call math_apply
    call apply_method_chacha
    xor eax, eax
    jmp .ret
.dec:
    call derive_method_key
    call apply_method_chacha
    call math_apply
    call apply_bitflip
    xor eax, eax
.ret:
    EPILOGUE 8

; Same parameter block. Applies only the bit-flip stage (involution).
bitflip_run:
    PROLOGUE 8
    call load_params
    test eax, eax
    jnz .ret
    call apply_bitflip
    xor eax, eax
.ret:
    EPILOGUE 8

; rdi = params. Sets globals, copies src->dst when they differ.
; rax 0, or -EINVAL if length is not a multiple of 16.
load_params:
    PROLOGUE 8
    mov rax, [rdi+PP_LEN]
    test rax, 15
    jnz .bad
    test rax, rax
    jz .bad
    mov [rel g_len], rax
    mov rax, [rdi+PP_DST]
    mov [rel g_buf], rax
    mov rax, [rdi+PP_KEY]
    mov [rel g_key], rax
    mov rax, [rdi+PP_TS]
    mov [rel g_ts], rax
    mov rax, [rdi+PP_GEN]
    mov [rel g_gen], rax
    mov rax, [rdi+PP_OFF]
    mov [rel g_off], rax
    mov rax, [rdi+PP_INO]
    mov [rel g_ino], rax
    mov rax, [rdi+PP_DEC]
    mov [rel g_dec], al
    mov rsi, [rdi+PP_SRC]
    mov rax, [rel g_buf]
    cmp rsi, rax
    je .same
    mov rdi, rax
    mov rdx, [rel g_len]
    call memcpy
.same:
    xor eax, eax
    EPILOGUE 8
.bad:
    mov rax, -EINVAL
    EPILOGUE 8

derive_bitflip_key:
    PROLOGUE 8
    lea rdi, [rel pp_mat]
    mov rsi, [rel g_key]
    mov edx, 32
    call memcpy
    lea rbx, [rel pp_mat]
    mov rax, [rel g_ts]
    mov [rbx+32], rax
    mov rax, [rel g_gen]
    mov [rbx+40], rax
    mov rax, [rel g_off]
    mov [rbx+48], rax
    mov rax, [rel g_ino]
    mov [rbx+56], rax
    lea rdi, [rbx+64]
    lea rsi, [rel lbl_bf]
    mov edx, 11
    call memcpy
    lea rdi, [rel pp_bkey]
    lea rsi, [rel pp_mat]
    mov edx, 75
    call sha256_oneshot
    EPILOGUE 8

derive_method_key:
    PROLOGUE 8
    lea rdi, [rel pp_mat]
    mov rsi, [rel g_key]
    mov edx, 32
    call memcpy
    lea rbx, [rel pp_mat]
    mov rax, [rel g_method]
    mov [rbx+32], al
    mov rax, [rel g_ts]
    mov [rbx+33], rax
    mov rax, [rel g_gen]
    mov [rbx+41], rax
    mov rax, [rel g_off]
    mov [rbx+49], rax
    mov rax, [rel g_ino]
    mov [rbx+57], rax
    lea rdi, [rbx+65]
    lea rsi, [rel lbl_m]
    mov edx, 11
    call memcpy
    lea rdi, [rel pp_sub]
    lea rsi, [rel pp_mat]
    mov edx, 76
    call sha256_oneshot
    EPILOGUE 8

apply_bitflip:
    PROLOGUE 8
    call derive_bitflip_key
    lea rbx, [rel pp_nonce]
    mov rax, [rel g_ts]
    mov [rbx], rax
    mov rax, [rel g_off]
    xor rax, [rel g_ino]
    xor rax, [rel g_gen]
    mov [rbx+8], eax
    mov rdi, [rel g_buf]
    mov rsi, rdi
    mov rdx, [rel g_len]
    lea rcx, [rel pp_bkey]
    lea r8, [rel pp_nonce]
    xor r9d, r9d
    call chacha20_xor
    mov rax, [rel g_ts]
    popcnt rcx, rax
    and ecx, 1
    mov r12d, ecx
    mov rbx, [rel g_buf]
    mov r13, [rel g_len]
    xor r14, r14
.l:
    cmp r14, r13
    jae .d
    mov rax, [rel g_ts]
    mov rcx, r14
    and cl, 63
    shr rax, cl
    and eax, 1
    xor eax, r12d
    jz .n
    not byte [rbx+r14]
.n:
    inc r14
    jmp .l
.d:
    EPILOGUE 8

apply_method_chacha:
    PROLOGUE 8
    lea rbx, [rel pp_nonce]
    mov rax, [rel g_ts]
    xor rax, [rel g_gen]
    mov [rbx], rax
    mov eax, dword [rel g_off]
    xor eax, dword [rel g_ino]
    mov ecx, dword [rel g_method]
    imul ecx, 0x10001
    xor eax, ecx
    mov [rbx+8], eax
    mov rdi, [rel g_buf]
    mov rsi, rdi
    mov rdx, [rel g_len]
    lea rcx, [rel pp_sub]
    lea r8, [rel pp_nonce]
    mov r9d, 1
    call chacha20_xor
    EPILOGUE 8

math_apply:
    mov rax, [rel g_method]
    cmp rax, 9
    ja .bad
    lea rcx, [rel math_tab]
    jmp [rcx+rax*8]
.bad:
    ret

; ---------- math layers (in place on g_buf / g_len) ----------

m_modmul:
    mov rbx, [rel g_buf]
    mov r12, [rel g_len]
    xor r13, r13
.l:
    cmp r13, r12
    jae .d
    mov rax, [rbx+r13]
    mov rdx, MUL64_CONST
    cmp byte [rel g_dec], 0
    je .m
    mov rdx, MUL64_INV
.m:
    mul rdx
    mov [rbx+r13], rax
    add r13, 8
    jmp .l
.d:
    ret

m_arx:
    mov rbx, [rel g_buf]
    mov r12, [rel g_len]
    xor r13, r13
    cmp byte [rel g_dec], 0
    jne .dec
.l:
    cmp r13, r12
    jae .d
    mov rax, [rbx+r13]
    mov r10, ARX_C1
    add rax, r10
    rol rax, 17
    mov r10, ARX_C2
    xor rax, r10
    mov r10, ARX_C3
    add rax, r10
    rol rax, 9
    mov r10, ARX_C4
    xor rax, r10
    mov [rbx+r13], rax
    add r13, 8
    jmp .l
.dec:
    cmp r13, r12
    jae .d
    mov rax, [rbx+r13]
    mov r10, ARX_C4
    xor rax, r10
    ror rax, 9
    mov r10, ARX_C3
    sub rax, r10
    mov r10, ARX_C2
    xor rax, r10
    ror rax, 17
    mov r10, ARX_C1
    sub rax, r10
    mov [rbx+r13], rax
    add r13, 8
    jmp .dec
.d:
    ret

; F(x,k) = rotl(x+k, 7) xor const. 4-round Feistel on u32 halves.
m_feistel32:
    PROLOGUE 8
    mov rbx, [rel g_buf]
    mov r15, [rel g_len]
    xor r14, r14
.word:
    cmp r14, r15
    jae .d
    mov r12d, [rbx+r14]
    mov r13d, [rbx+r14+4]
    cmp byte [rel g_dec], 0
    jne .dec
    xor ecx, ecx
.er:
    cmp ecx, 4
    je .st
    lea r8, [rel pp_sub]
    mov r9d, [r8+rcx*4]
    mov eax, r13d
    add eax, r9d
    rol eax, 7
    xor eax, FEISTEL_XOR32
    xor eax, r12d
    mov r12d, r13d
    mov r13d, eax
    inc ecx
    jmp .er
.dec:
    mov ecx, 3
.dr:
    lea r8, [rel pp_sub]
    mov r9d, [r8+rcx*4]
    mov eax, r12d
    add eax, r9d
    rol eax, 7
    xor eax, FEISTEL_XOR32
    xor eax, r13d
    mov r13d, r12d
    mov r12d, eax
    dec ecx
    jns .dr
.st:
    mov [rbx+r14], r12d
    mov [rbx+r14+4], r13d
    add r14, 8
    jmp .word
.d:
    EPILOGUE 8

m_feistel64:
    PROLOGUE 8
    mov rbx, [rel g_buf]
    mov r15, [rel g_len]
    xor r14, r14
.word:
    cmp r14, r15
    jae .d
    mov r12, [rbx+r14]
    mov r13, [rbx+r14+8]
    cmp byte [rel g_dec], 0
    jne .dec
    xor ecx, ecx
.er:
    cmp ecx, 4
    je .st
    lea r8, [rel pp_sub]
    mov r9, [r8+rcx*8]
    mov rax, r13
    add rax, r9
    rol rax, 13
    mov r10, ARX_C4
    xor rax, r10
    xor rax, r12
    mov r12, r13
    mov r13, rax
    inc ecx
    jmp .er
.dec:
    mov ecx, 3
.dr:
    lea r8, [rel pp_sub]
    mov r9, [r8+rcx*8]
    mov rax, r12
    add rax, r9
    rol rax, 13
    mov r10, ARX_C4
    xor rax, r10
    xor rax, r13
    mov r13, r12
    mov r12, rax
    dec ecx
    jns .dr
.st:
    mov [rbx+r14], r12
    mov [rbx+r14+8], r13
    add r14, 16
    jmp .word
.d:
    EPILOGUE 8

m_bitperm:
    mov rbx, [rel g_buf]
    mov r12, [rel g_len]
    xor r13, r13
.word:
    cmp r13, r12
    jae .d
    mov r14, [rbx+r13]
    xor r15, r15
    xor ecx, ecx
    cmp byte [rel g_dec], 0
    jne .inv
.fb:
    cmp ecx, 64
    je .st
    bt r14, rcx
    jnc .fn
    mov eax, ecx
    imul eax, 17
    add eax, 5
    and eax, 63
    bts r15, rax
.fn:
    inc ecx
    jmp .fb
.inv:
    cmp ecx, 64
    je .st
    mov eax, ecx
    sub eax, 5
    and eax, 63
    imul eax, 49
    and eax, 63
    bt r14, rcx
    jnc .in
    bts r15, rax
.in:
    inc ecx
    jmp .inv
.st:
    mov [rbx+r13], r15
    add r13, 8
    jmp .word
.d:
    ret

m_gfmul:
    PROLOGUE 8
    mov rbx, [rel g_buf]
    mov r12, [rel g_len]
    xor r13, r13
.l:
    cmp r13, r12
    jae .d
    movzx edi, byte [rbx+r13]
    cmp byte [rel g_dec], 0
    jne .dec
    mov esi, GF_CONST
    call gf_mul
    xor al, 0xA7
    jmp .s
.dec:
    xor edi, 0xA7
    mov esi, GF_INV
    call gf_mul
.s:
    mov [rbx+r13], al
    inc r13
    jmp .l
.d:
    EPILOGUE 8

; dil = a, sil = b -> al. AES polynomial 0x11b.
; High-byte registers are avoided: SIL needs a REX prefix.
gf_mul:
    push rbx
    mov bl, dil
    mov r8b, sil
    xor al, al
    mov ecx, 8
.l:
    test r8b, 1
    jz .no
    xor al, bl
.no:
    mov dl, bl
    shl bl, 1
    test dl, 0x80
    jz .nx
    xor bl, 0x1b
.nx:
    shr r8b, 1
    dec ecx
    jnz .l
    pop rbx
    ret

m_sbox:
    mov rbx, [rel g_buf]
    mov r12, [rel g_len]
    lea r13, [rel aes_sbox]
    cmp byte [rel g_dec], 0
    je .go
    lea r13, [rel aes_inv_sbox]
.go:
    xor r14, r14
.l:
    cmp r14, r12
    jae .d
    movzx eax, byte [rbx+r14]
    mov al, [r13+rax]
    mov [rbx+r14], al
    inc r14
    jmp .l
.d:
    ret

m_nibble:
    mov rbx, [rel g_buf]
    mov r12, [rel g_len]
    xor r13, r13
    cmp byte [rel g_dec], 0
    jne .dec
.l:
    cmp r13, r12
    jae .d
    mov al, [rbx+r13]
    mov cl, al
    shr al, 4
    shl cl, 4
    or al, cl
    add al, 0x6D
    mov eax, r13d
    ; reload byte after add into dl
    mov dl, [rbx+r13]
    mov cl, dl
    shr dl, 4
    shl cl, 4
    or dl, cl
    add dl, 0x6D
    mov eax, r13d
    imul eax, 31
    xor dl, al
    mov [rbx+r13], dl
    inc r13
    jmp .l
.dec:
    cmp r13, r12
    jae .d
    mov eax, r13d
    imul eax, 31
    mov dl, [rbx+r13]
    xor dl, al
    sub dl, 0x6D
    mov al, dl
    mov cl, al
    shr al, 4
    shl cl, 4
    or al, cl
    mov [rbx+r13], al
    inc r13
    jmp .dec
.d:
    ret

m_affine:
    PROLOGUE 8
    mov rbx, [rel g_buf]
    mov r12, [rel g_len]
    xor r13, r13
.l:
    cmp r13, r12
    jae .d
    mov dil, [rbx+r13]
    cmp byte [rel g_dec], 0
    jne .dec
    call affine_fwd
    jmp .s
.dec:
    call affine_inv
.s:
    mov [rbx+r13], al
    inc r13
    jmp .l
.d:
    EPILOGUE 8

; dil -> al. Does not touch RBX (callers keep a pointer there).
affine_fwd:
    mov dl, dil
    mov al, dl
    mov cl, dl
    rol cl, 1
    xor al, cl
    mov cl, dl
    rol cl, 2
    xor al, cl
    mov cl, dl
    rol cl, 3
    xor al, cl
    mov cl, dl
    rol cl, 4
    xor al, cl
    xor al, 0x63
    ret

affine_inv:
    mov dl, dil
    mov al, dl
    ror al, 2
    mov cl, dl
    ror cl, 5
    xor al, cl
    mov cl, dl
    ror cl, 7
    xor al, cl
    xor al, 0x05
    ret

m_mixcol:
    PROLOGUE 8
    mov rbx, [rel g_buf]
    mov r12, [rel g_len]
    xor r13, r13
.l:
    cmp r13, r12
    jae .d
    lea rdi, [rbx+r13]
    cmp byte [rel g_dec], 0
    jne .dec
    call mix4_fwd
    jmp .n
.dec:
    call mix4_inv
.n:
    add r13, 4
    jmp .l
.d:
    EPILOGUE 8

; rdi = 4 bytes
mix4_fwd:
    PROLOGUE 24
    mov rbx, rdi
    movzx r12d, byte [rbx]
    movzx r13d, byte [rbx+1]
    movzx r14d, byte [rbx+2]
    movzx r15d, byte [rbx+3]
    ; o0 = 2a ^ 3b ^ c ^ d
    mov edi, r12d
    mov esi, 2
    call gf_mul
    mov [rsp], al
    mov edi, r13d
    mov esi, 3
    call gf_mul
    xor [rsp], al
    mov al, r14b
    xor [rsp], al
    mov al, r15b
    xor [rsp], al
    ; o1 = a ^ 2b ^ 3c ^ d
    mov edi, r13d
    mov esi, 2
    call gf_mul
    mov [rsp+1], al
    mov edi, r14d
    mov esi, 3
    call gf_mul
    xor [rsp+1], al
    mov al, r12b
    xor [rsp+1], al
    mov al, r15b
    xor [rsp+1], al
    ; o2 = a ^ b ^ 2c ^ 3d
    mov edi, r14d
    mov esi, 2
    call gf_mul
    mov [rsp+2], al
    mov edi, r15d
    mov esi, 3
    call gf_mul
    xor [rsp+2], al
    mov al, r12b
    xor [rsp+2], al
    mov al, r13b
    xor [rsp+2], al
    ; o3 = 3a ^ b ^ c ^ 2d
    mov edi, r12d
    mov esi, 3
    call gf_mul
    mov [rsp+3], al
    mov edi, r15d
    mov esi, 2
    call gf_mul
    xor [rsp+3], al
    mov al, r13b
    xor [rsp+3], al
    mov al, r14b
    xor [rsp+3], al
    mov al, [rsp]
    mov [rbx], al
    mov al, [rsp+1]
    mov [rbx+1], al
    mov al, [rsp+2]
    mov [rbx+2], al
    mov al, [rsp+3]
    mov [rbx+3], al
    EPILOGUE 24

mix4_inv:
    PROLOGUE 24
    mov rbx, rdi
    movzx r12d, byte [rbx]
    movzx r13d, byte [rbx+1]
    movzx r14d, byte [rbx+2]
    movzx r15d, byte [rbx+3]
    ; o0 = 14a ^ 11b ^ 13c ^ 9d
    mov edi, r12d
    mov esi, 14
    call gf_mul
    mov [rsp], al
    mov edi, r13d
    mov esi, 11
    call gf_mul
    xor [rsp], al
    mov edi, r14d
    mov esi, 13
    call gf_mul
    xor [rsp], al
    mov edi, r15d
    mov esi, 9
    call gf_mul
    xor [rsp], al
    ; o1 = 9a ^ 14b ^ 11c ^ 13d
    mov edi, r12d
    mov esi, 9
    call gf_mul
    mov [rsp+1], al
    mov edi, r13d
    mov esi, 14
    call gf_mul
    xor [rsp+1], al
    mov edi, r14d
    mov esi, 11
    call gf_mul
    xor [rsp+1], al
    mov edi, r15d
    mov esi, 13
    call gf_mul
    xor [rsp+1], al
    ; o2 = 13a ^ 9b ^ 14c ^ 11d
    mov edi, r12d
    mov esi, 13
    call gf_mul
    mov [rsp+2], al
    mov edi, r13d
    mov esi, 9
    call gf_mul
    xor [rsp+2], al
    mov edi, r14d
    mov esi, 14
    call gf_mul
    xor [rsp+2], al
    mov edi, r15d
    mov esi, 11
    call gf_mul
    xor [rsp+2], al
    ; o3 = 11a ^ 13b ^ 9c ^ 14d
    mov edi, r12d
    mov esi, 11
    call gf_mul
    mov [rsp+3], al
    mov edi, r13d
    mov esi, 13
    call gf_mul
    xor [rsp+3], al
    mov edi, r14d
    mov esi, 9
    call gf_mul
    xor [rsp+3], al
    mov edi, r15d
    mov esi, 14
    call gf_mul
    xor [rsp+3], al
    mov al, [rsp]
    mov [rbx], al
    mov al, [rsp+1]
    mov [rbx+1], al
    mov al, [rsp+2]
    mov [rbx+2], al
    mov al, [rsp+3]
    mov [rbx+3], al
    EPILOGUE 24
