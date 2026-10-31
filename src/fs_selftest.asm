%include "sys.inc"

extern fs_format, fs_open, fs_close, fs_sleep, fs_wake, fs_wipe
extern fs_create, fs_mkdir, fs_lookup, fs_unlink, fs_rmdir
extern fs_read, fs_write, fs_read_inode
extern pass_buf, pass_len, fs_stage, dbg_q, dbg_b, fs_root
extern print_err, print_u64, memcmp, memset, memcpy

section .bss
tbuf:       resb 8192
rbuf:       resb 8192
nameb:      resb 16

section .data
img:        db "/tmp/nmgl-selftest.img", 0
pw:         db "test-passphrase", 0
pw_len      equ 15
fn_hello:   db "hello", 0
fn_sub:     db "sub", 0
fn_big:     db "big", 0
secret:     db "HELLO-NMGLFDFS-SECRET"
secret_len  equ 21
step_fmt:   db "fs format", 10, 0
step_open:  db "fs open", 10, 0
step_cr:    db "fs create", 10, 0
step_wr:    db "fs write", 10, 0
step_rd:    db "fs read", 10, 0
step_re:    db "fs remount", 10, 0
step_many:  db "fs many", 10, 0
step_sl:    db "fs sleep", 10, 0
step_wk:    db "fs wake", 10, 0
step_wp:    db "fs wipe", 10, 0
step_mkdir: db "fs mkdir", 10, 0
step_plain: db "plaintext leaked", 10, 0
fsok:       db "selftest: filesystem passed", 10, 0

section .text
global fs_selftest

fs_selftest:
    PROLOGUE 8
    xor r15, r15
    lea rsi, [rel pw]
    lea rdi, [rel pass_buf]
    mov ecx, pw_len
    rep movsb
    mov byte [rel pass_buf+pw_len], 0
    mov qword [rel pass_len], pw_len

    mov rax, SYS_unlink
    lea rdi, [rel img]
    syscall

    lea rdi, [rel img]
    mov esi, 16
    call fs_format
    test rax, rax
    jz .open1
    lea rcx, [rel step_fmt]
    call .fail
    jmp .done
.open1:
    lea rdi, [rel img]
    call fs_open
    test eax, eax
    jz .cr
    lea rcx, [rel step_open]
    call .fail
    jmp .done
.cr:
    mov edi, ROOT_INO
    lea rsi, [rel fn_hello]
    mov edx, 5
    mov ecx, 420
    call fs_create
    cmp rax, 0
    jg .wr
    lea rcx, [rel step_cr]
    call .fail
    jmp .shut
.wr:
    mov rbx, rax
    mov rdi, rbx
    xor esi, esi
    lea rdx, [rel secret]
    mov ecx, secret_len
    call fs_write
    cmp rax, secret_len
    je .rd
    lea rcx, [rel step_wr]
    call .fail
    lea rdi, [rel tag_root]
    call print_err
    mov rax, [rel fs_root]
    call print_u64
    lea rdi, [rel tag_q]
    call print_err
    mov rax, [rel dbg_q]
    call print_u64
    lea rdi, [rel tag_b]
    call print_err
    mov rax, [rel dbg_b]
    call print_u64
    lea rdi, [rel nl]
    call print_err
    mov edi, 2
    lea rsi, [rel nl]
    mov edx, 1
    mov rax, SYS_write
    syscall
    jmp .shut
.rd:
    mov rdi, rbx
    xor esi, esi
    lea rdx, [rel rbuf]
    mov ecx, secret_len
    call fs_read
    cmp rax, secret_len
    jne .rdbad
    lea rdi, [rel rbuf]
    lea rsi, [rel secret]
    mov edx, secret_len
    call memcmp
    test eax, eax
    jz .big
.rdbad:
    lea rcx, [rel step_rd]
    call .fail
.big:
    mov edi, ROOT_INO
    lea rsi, [rel fn_big]
    mov edx, 3
    mov ecx, 420
    call fs_create
    cmp rax, 0
    jle .manyb
    mov rbx, rax
    lea rdi, [rel tbuf]
    mov esi, 'A'
    mov edx, 5000
    call memset
    mov rdi, rbx
    xor esi, esi
    lea rdx, [rel tbuf]
    mov ecx, 5000
    call fs_write
    cmp rax, 5000
    jne .manyb
    mov rdi, rbx
    xor esi, esi
    lea rdx, [rel rbuf]
    mov ecx, 5000
    call fs_read
    cmp rax, 5000
    jne .manyb
    lea rdi, [rel rbuf]
    lea rsi, [rel tbuf]
    mov edx, 5000
    call memcmp
    test eax, eax
    jz .many
.manyb:
    lea rcx, [rel step_many]
    call .fail
.many:
    xor r12, r12
.ml:
    cmp r12, 30
    jae .md
    lea rdi, [rel nameb]
    mov byte [rdi], 'f'
    mov eax, r12d
    mov ecx, 10
    xor edx, edx
    div ecx
    add al, '0'
    mov [rel nameb+1], al
    add dl, '0'
    mov [rel nameb+2], dl
    mov byte [rel nameb+3], 0
    mov edi, ROOT_INO
    lea rsi, [rel nameb]
    mov edx, 3
    mov ecx, 420
    call fs_create
    cmp rax, 0
    jle .mfail
    mov rbx, rax
    mov rdi, rbx
    xor esi, esi
    lea rdx, [rel nameb]
    mov ecx, 3
    call fs_write
    cmp rax, 3
    jl .mfail
    inc r12
    jmp .ml
.mfail:
    lea rcx, [rel step_many]
    call .fail
.md:
    mov edi, ROOT_INO
    lea rsi, [rel fn_sub]
    mov edx, 3
    mov ecx, 493
    call fs_mkdir
    cmp rax, 0
    jg .subok
    lea rcx, [rel step_mkdir]
    call .fail
.subok:
    call fs_close
    lea rdi, [rel img]
    call fs_open
    test eax, eax
    jz .reread
    lea rcx, [rel step_re]
    call .fail
    jmp .done
.reread:
    mov edi, ROOT_INO
    lea rsi, [rel fn_hello]
    mov edx, 5
    call fs_lookup
    cmp rax, 0
    jle .rbad
    mov rbx, rax
    mov rdi, rbx
    xor esi, esi
    lea rdx, [rel rbuf]
    mov ecx, secret_len
    call fs_read
    cmp rax, secret_len
    jne .rbad
    lea rdi, [rel rbuf]
    lea rsi, [rel secret]
    mov edx, secret_len
    call memcmp
    test eax, eax
    jz .plain
.rbad:
    lea rcx, [rel step_re]
    call .fail
.plain:
    call fs_close
    call .scan_plain
    test eax, eax
    jz .sl
    lea rcx, [rel step_plain]
    call .fail
.sl:
    lea rdi, [rel img]
    call fs_sleep
    test eax, eax
    jz .slopen
    lea rcx, [rel step_sl]
    call .fail
    jmp .wk
.slopen:
    lea rdi, [rel img]
    call fs_open
    cmp eax, -ERR_SLEEP
    je .slc
    lea rcx, [rel step_sl]
    call .fail
.slc:
    call fs_close
.wk:
    lea rdi, [rel img]
    call fs_wake
    test eax, eax
    jz .wkopen
    lea rcx, [rel step_wk]
    call .fail
    jmp .wp
.wkopen:
    lea rdi, [rel img]
    call fs_open
    test eax, eax
    jnz .wkbad
    mov edi, ROOT_INO
    lea rsi, [rel fn_hello]
    mov edx, 5
    call fs_lookup
    cmp rax, 0
    jle .wkbad
    mov rdi, rax
    xor esi, esi
    lea rdx, [rel rbuf]
    mov ecx, secret_len
    call fs_read
    cmp rax, secret_len
    jne .wkbad
    lea rdi, [rel rbuf]
    lea rsi, [rel secret]
    mov edx, secret_len
    call memcmp
    test eax, eax
    jz .wkc
.wkbad:
    lea rcx, [rel step_wk]
    call .fail
.wkc:
    call fs_close
.wp:
    lea rdi, [rel img]
    call fs_wipe
    test eax, eax
    jz .wpopen
    lea rcx, [rel step_wp]
    call .fail
    jmp .done
.wpopen:
    lea rdi, [rel img]
    call fs_open
    cmp eax, -ERR_WIPED
    je .wpc
    lea rcx, [rel step_wp]
    call .fail
.wpc:
    call fs_close
.done:
    mov rax, r15
    EPILOGUE 8
.shut:
    call fs_close
    jmp .done

; rcx = message. Increments r15 (not saved) and prints rax.
.fail:
    push rbx
    push r12
    sub rsp, 8
    mov rbx, rcx
    mov r12, rax
    inc r15
    mov rdi, rbx
    call print_err
    mov rax, r12
    neg rax
    call print_u64
    mov edi, 2
    lea rsi, [rel nl]
    mov edx, 1
    mov rax, SYS_write
    syscall
    add rsp, 8
    pop r12
    pop rbx
    ret

; rax 0 if secret is absent from the image, 1 if found.
.scan_plain:
    PROLOGUE 24
    mov rax, SYS_open
    lea rdi, [rel img]
    xor esi, esi
    xor edx, edx
    syscall
    cmp rax, 0
    jl .bad
    mov [rsp], rax
    mov qword [rsp+8], 0
.srd:
    mov rax, SYS_read
    mov rdi, [rsp]
    lea rsi, [rel tbuf]
    mov edx, 4096
    syscall
    cmp rax, 0
    jle .eof
    mov r12, rax
    cmp r12, secret_len
    jb .srd
    xor r13, r13
.sc:
    mov rax, r12
    sub rax, secret_len
    cmp r13, rax
    jg .srd
    lea rdi, [rel tbuf]
    add rdi, r13
    lea rsi, [rel secret]
    mov edx, secret_len
    call memcmp
    test eax, eax
    jz .found
    inc r13
    jmp .sc
.found:
    mov qword [rsp+8], 1
.eof:
    mov rax, SYS_close
    mov rdi, [rsp]
    syscall
    mov rax, [rsp+8]
    EPILOGUE 24
.bad:
    mov eax, 1
    EPILOGUE 24

section .data
nl: db 10, 0
tag_root: db " root=", 0
tag_q: db " q=", 0
tag_b: db " b=", 0
