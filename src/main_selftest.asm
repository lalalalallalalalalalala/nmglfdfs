%include "sys.inc"

extern sha256_oneshot, crc32c, chacha20_xor, pbkdf2_sha256
extern pipeline_apply, bitflip_run
extern memset, memcpy, memcmp, print_out, print_err, print_u64, print_fd
extern argc, argv, envp
extern fs_selftest

section .bss
buf_a:      resb 4096
buf_b:      resb 4096
buf_c:      resb 4096
keyb:       resb 32
hashb:      resb 32
param:      resb 80
fails:      resq 1

section .data
name_sha0:  db "sha256 empty", 10, 0
name_sha1:  db "sha256 abc", 10, 0
name_sha2:  db "sha256 56", 10, 0
name_sha3:  db "sha256 100", 10, 0
name_crc:   db "crc32c", 10, 0
name_chacha: db "chacha20 rfc", 10, 0
name_pbk1:  db "pbkdf2 c=1", 10, 0
name_pbk2:  db "pbkdf2 c=2", 10, 0
name_round: db "roundtrip method ", 0
name_det:   db "determinism", 10, 0
name_bf:    db "bitflip involution", 10, 0
name_bfd:   db "bitflip depends on timestamp", 10, 0
name_diff:  db "methods differ", 10, 0
okmsg:      db "selftest: all passed", 10, 0
crypto_done: db "start", 10, 0
step_after: db "crypto done", 10, 0
badmsg:     db "selftest: failures=", 0
failpref:   db "FAIL ", 0

sha0_exp:
    db 0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14
    db 0x9a,0xfb,0xf4,0xc8,0x99,0x6f,0xb9,0x24
    db 0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c
    db 0xa4,0x95,0x99,0x1b,0x78,0x52,0xb8,0x55
sha1_exp:
    db 0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea
    db 0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23
    db 0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c
    db 0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad
pbk1_exp:
    db 0x12,0x0f,0xb6,0xcf,0xfc,0xf8,0xb3,0x2c
    db 0x43,0xe7,0x22,0x52,0x56,0xc4,0xf8,0x37
    db 0xa8,0x65,0x48,0xc9,0x2c,0xcc,0x35,0x48
    db 0x08,0x05,0x98,0x7c,0xb7,0x0b,0xe1,0x7b
pbk2_exp:
    db 0xae,0x4d,0x0c,0x95,0xaf,0x6b,0x46,0xd3
    db 0x2d,0x0a,0xdf,0xf9,0x28,0xf0,0x6d,0xd0
    db 0x2a,0x30,0x3f,0x8e,0xf3,0xc2,0x51,0xdf
    db 0xd6,0xe2,0xd8,0x5a,0x95,0x47,0x4c,0x43
chacha_exp:
    db 0x10,0xf1,0xe7,0xe4,0xd1,0x3b,0x59,0x15
    db 0x50,0x0f,0xdd,0x1f,0xa3,0x20,0x71,0xc4
    db 0xc7,0xd1,0xf4,0xc7,0x33,0xc0,0x68,0x03
    db 0x04,0x22,0xaa,0x9a,0xc3,0xd4,0x6c,0x4e
    db 0xd2,0x82,0x64,0x46,0x07,0x9f,0xaa,0x09
    db 0x14,0xc2,0xd7,0x05,0xd9,0x8b,0x02,0xa2
    db 0xb5,0x12,0x9c,0xd1,0xde,0x16,0x4e,0xb9
    db 0xcb,0xd0,0x83,0xe8,0xa2,0x50,0x3c,0x4e
chacha_nonce:
    db 0x00,0x00,0x00,0x09,0x00,0x00,0x00,0x4a,0x00,0x00,0x00,0x00
abc_msg:    db "abc"
sha2_msg:   db "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
sha2_exp:
    db 0x24,0x8d,0x6a,0x61,0xd2,0x06,0x38,0xb8
    db 0xe5,0xc0,0x26,0x93,0x0c,0x3e,0x60,0x39
    db 0xa3,0x3c,0xe4,0x59,0x64,0xff,0x21,0x67
    db 0xf6,0xec,0xed,0xd4,0x19,0xdb,0x06,0xc1
sha3_msg:   times 100 db "a"
sha3_exp:
    db 0x28,0x16,0x59,0x78,0x88,0xe4,0xa0,0xd3
    db 0xa3,0x6b,0x82,0xb8,0x33,0x16,0xab,0x32
    db 0x68,0x0e,0xb8,0xf0,0x0f,0x8c,0xd3,0xb9
    db 0x04,0xd6,0x81,0x24,0x6d,0x28,0x5a,0x0e
crc_msg:    db "123456789"
pass_msg:   db "password"
salt_msg:   db "salt"

section .text
global _start

_start:
    pop rdi
    mov rsi, rsp
    lea rdx, [rsp+rdi*8+8]
    mov [rel argc], rdi
    mov [rel argv], rsi
    mov [rel envp], rdx
    call app_main
    mov rdi, rax
    mov rax, SYS_exit
    syscall

app_main:
    PROLOGUE 8
    mov qword [rel fails], 0

    lea rdi, [rel hashb]
    lea rsi, [rel abc_msg]
    xor edx, edx
    call sha256_oneshot
    lea rdi, [rel hashb]
    lea rsi, [rel sha0_exp]
    mov edx, 32
    lea rcx, [rel name_sha0]
    call expect_mem

    lea rdi, [rel hashb]
    lea rsi, [rel abc_msg]
    mov edx, 3
    call sha256_oneshot
    lea rdi, [rel hashb]
    lea rsi, [rel sha1_exp]
    mov edx, 32
    lea rcx, [rel name_sha1]
    call expect_mem

    lea rdi, [rel hashb]
    lea rsi, [rel sha2_msg]
    mov edx, 56
    call sha256_oneshot
    lea rdi, [rel hashb]
    lea rsi, [rel sha2_exp]
    mov edx, 32
    lea rcx, [rel name_sha2]
    call expect_mem

    lea rdi, [rel hashb]
    lea rsi, [rel sha3_msg]
    mov edx, 100
    call sha256_oneshot
    lea rdi, [rel hashb]
    lea rsi, [rel sha3_exp]
    mov edx, 32
    lea rcx, [rel name_sha3]
    call expect_mem

    lea rdi, [rel crc_msg]
    mov esi, 9
    call crc32c
    cmp eax, 0xe3069283
    je .crcok
    lea rcx, [rel name_crc]
    call fail
.crcok:
    xor ecx, ecx
.fillk:
    cmp ecx, 32
    je .ch
    lea rdx, [rel keyb]
    mov [rdx+rcx], cl
    inc ecx
    jmp .fillk
.ch:
    lea rdi, [rel buf_a]
    xor esi, esi
    mov edx, 64
    call memset
    lea rdi, [rel buf_b]
    lea rsi, [rel buf_a]
    mov edx, 64
    lea rcx, [rel keyb]
    lea r8, [rel chacha_nonce]
    mov r9d, 1
    call chacha20_xor
    lea rdi, [rel buf_b]
    lea rsi, [rel chacha_exp]
    mov edx, 64
    lea rcx, [rel name_chacha]
    call expect_mem

    lea rdi, [rel hashb]
    lea rsi, [rel pass_msg]
    mov edx, 8
    lea rcx, [rel salt_msg]
    mov r8d, 4
    mov r9d, 1
    call pbkdf2_sha256
    lea rdi, [rel hashb]
    lea rsi, [rel pbk1_exp]
    mov edx, 32
    lea rcx, [rel name_pbk1]
    call expect_mem

    lea rdi, [rel hashb]
    lea rsi, [rel pass_msg]
    mov edx, 8
    lea rcx, [rel salt_msg]
    mov r8d, 4
    mov r9d, 2
    call pbkdf2_sha256
    lea rdi, [rel hashb]
    lea rsi, [rel pbk2_exp]
    mov edx, 32
    lea rcx, [rel name_pbk2]
    call expect_mem

    call test_rounds
    call test_bitflip
    call fs_selftest
    add [rel fails], rax

    cmp qword [rel fails], 0
    jne .bad
    lea rdi, [rel okmsg]
    call print_out
    xor eax, eax
    EPILOGUE 8
.bad:
    lea rdi, [rel badmsg]
    call print_err
    mov rax, [rel fails]
    call print_u64
    lea rsi, [rel nlbyte]
    mov rdx, 1
    mov rdi, 2
    call print_fd
    mov rax, [rel fails]
    EPILOGUE 8

; rdi got, rsi exp, edx len, rcx name
expect_mem:
    PROLOGUE 24
    mov [rsp], rcx
    call memcmp
    test eax, eax
    jz .ok
    mov rcx, [rsp]
    call fail
.ok:
    EPILOGUE 24

; rcx = name cstr
fail:
    PROLOGUE 8
    mov rbx, rcx
    inc qword [rel fails]
    lea rdi, [rel failpref]
    call print_err
    mov rdi, rbx
    call print_err
    EPILOGUE 8

test_rounds:
    PROLOGUE 8
    xor r15, r15
.m:
    cmp r15, 10
    je .diff
    call fill_pattern
    mov rax, 1000
    add rax, r15
    mov r8, rax              ; ts
    xor r9d, r9d             ; encrypt
    lea rdi, [rel buf_b]
    lea rsi, [rel buf_a]
    call do_pipe
    lea rdi, [rel buf_b]
    lea rsi, [rel buf_a]
    mov edx, 4096
    call memcmp
    test eax, eax
    jnz .cipher_ok
    mov rax, r15
    call print_u64
    lea rcx, [rel name_round]
    call fail
    jmp .next
.cipher_ok:
    ; second encrypt must match
    mov rax, 1000
    add rax, r15
    mov r8, rax
    xor r9d, r9d
    lea rdi, [rel buf_c]
    lea rsi, [rel buf_a]
    call do_pipe
    lea rdi, [rel buf_c]
    lea rsi, [rel buf_b]
    mov edx, 4096
    lea rcx, [rel name_det]
    call expect_mem
    ; decrypt
    mov rax, 1000
    add rax, r15
    mov r8, rax
    mov r9d, 1
    lea rdi, [rel buf_c]
    lea rsi, [rel buf_b]
    call do_pipe
    lea rdi, [rel buf_c]
    lea rsi, [rel buf_a]
    mov edx, 4096
    call memcmp
    test eax, eax
    jz .next
    mov rax, r15
    call print_u64
    lea rcx, [rel name_round]
    call fail
.next:
    inc r15
    jmp .m
.diff:
    ; ciphertext of method 0 and method 1 must differ
    call fill_pattern
    mov r8, 1000
    xor r9d, r9d
    lea rdi, [rel buf_b]
    lea rsi, [rel buf_a]
    call do_pipe
    mov r8, 1001
    xor r9d, r9d
    lea rdi, [rel buf_c]
    lea rsi, [rel buf_a]
    call do_pipe
    lea rdi, [rel buf_b]
    lea rsi, [rel buf_c]
    mov edx, 4096
    call memcmp
    test eax, eax
    jnz .dd
    lea rcx, [rel name_diff]
    call fail
.dd:
    EPILOGUE 8

test_bitflip:
    PROLOGUE 8
    call fill_pattern
    ; copy original
    lea rdi, [rel buf_c]
    lea rsi, [rel buf_a]
    mov edx, 4096
    call memcpy
    mov r8, 123456789
    xor r9d, r9d
    lea rdi, [rel buf_a]
    lea rsi, [rel buf_a]
    call do_bit
    mov r8, 123456789
    lea rdi, [rel buf_a]
    lea rsi, [rel buf_a]
    call do_bit
    lea rdi, [rel buf_a]
    lea rsi, [rel buf_c]
    mov edx, 4096
    lea rcx, [rel name_bf]
    call expect_mem
    ; one flip vs different timestamp
    call fill_pattern
    mov r8, 50
    lea rdi, [rel buf_b]
    lea rsi, [rel buf_a]
    call do_bit
    mov r8, 51
    lea rdi, [rel buf_c]
    lea rsi, [rel buf_a]
    call do_bit
    lea rdi, [rel buf_b]
    lea rsi, [rel buf_c]
    mov edx, 4096
    call memcmp
    test eax, eax
    jnz .ok
    lea rcx, [rel name_bfd]
    call fail
.ok:
    EPILOGUE 8

; fill buf_a with a non-trivial pattern, keyb with 0..31
fill_pattern:
    PROLOGUE 8
    xor ecx, ecx
.l:
    cmp ecx, 4096
    je .k
    mov eax, ecx
    imul eax, 17
    add eax, 3
    lea rdx, [rel buf_a]
    mov [rdx+rcx], al
    inc ecx
    jmp .l
.k:
    xor ecx, ecx
.lk:
    cmp ecx, 32
    je .d
    mov eax, ecx
    xor eax, 0x5a
    lea rdx, [rel keyb]
    mov [rdx+rcx], al
    inc ecx
    jmp .lk
.d:
    EPILOGUE 8

; r8 = ts, r9 = decrypt flag, rdi dst, rsi src. 4096 bytes, gen=7, off=4096, ino=257
do_pipe:
    PROLOGUE 8
    mov rbx, rdi
    mov r12, rsi
    mov r13, r8
    mov r14, r9
    lea rdi, [rel param]
    mov rax, rbx
    mov [rdi+PP_DST], rax
    mov rax, r12
    mov [rdi+PP_SRC], rax
    mov qword [rdi+PP_LEN], 4096
    lea rax, [rel keyb]
    mov [rdi+PP_KEY], rax
    mov rax, r13
    mov [rdi+PP_TS], rax
    mov qword [rdi+PP_GEN], 7
    mov qword [rdi+PP_OFF], 4096
    mov qword [rdi+PP_INO], 257
    mov rax, r14
    mov [rdi+PP_DEC], rax
    lea rdi, [rel param]
    call pipeline_apply
    EPILOGUE 8

do_bit:
    PROLOGUE 8
    mov rbx, rdi
    mov r12, rsi
    mov r13, r8
    lea rdi, [rel param]
    mov rax, rbx
    mov [rdi+PP_DST], rax
    mov rax, r12
    mov [rdi+PP_SRC], rax
    mov qword [rdi+PP_LEN], 4096
    lea rax, [rel keyb]
    mov [rdi+PP_KEY], rax
    mov rax, r13
    mov [rdi+PP_TS], rax
    mov qword [rdi+PP_GEN], 7
    mov qword [rdi+PP_OFF], 4096
    mov qword [rdi+PP_INO], 257
    mov qword [rdi+PP_DEC], 0
    lea rdi, [rel param]
    call bitflip_run
    EPILOGUE 8

section .data
nlbyte: db 10
