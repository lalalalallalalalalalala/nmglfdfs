%include "sys.inc"

extern fs_format, fs_open, fs_close, fs_sleep, fs_wake, fs_wipe
extern fs_create, fs_mkdir, fs_lookup, fs_unlink, fs_rmdir
extern fs_read, fs_write, fs_read_inode
extern btree_get, btree_root_level, btree_root_nitems, crc32c
extern pass_buf, pass_len, fs_stage, dbg_q, dbg_b, fs_root
extern print_err, print_out, print_u64, memcmp, memset, memcpy

section .bss
tbuf:       resb 8192
rbuf:       resb 8192
nameb:      resb 16
ino_tab:    resq 4096
n_bulk:     resq 1
dir_ino:    resq 4
dirf_ino:   resq 4
exttmp:     resb 64
tamper_bn:  resq 1
root_bn:    resq 1
which_fail: resb 1

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
step_split: db "fs internal split", 10, 0
step_mac:   db "fs auth", 10, 0
msg_nfiles: db "internal-split files ", 0
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
    mov esi, 64
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
    call .grow_tree
    test eax, eax
    jz .plain2
    lea rcx, [rel step_split]
    cmp byte [rel which_fail], 2
    jne .pfail
    lea rcx, [rel step_mac]
.pfail:
    call .fail
.plain2:
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

; Grow the tree until the root is at least level 2, remount, read every
; new object back, then reject a flipped ciphertext byte and a CRC-adjusted
; metadata block. Returns 0, or -errno with which_fail set (1 split, 2 auth).
.grow_tree:
    PROLOGUE 24
    mov byte [rel which_fail], 1
    xor r13, r13
.gtd:
    cmp r13, 4
    jae .gtfiles
    lea rdi, [rel nameb]
    mov byte [rdi], 'd'
    mov eax, r13d
    add al, '0'
    mov [rel nameb+1], al
    mov byte [rel nameb+2], 0
    mov edi, ROOT_INO
    lea rsi, [rel nameb]
    mov edx, 2
    mov ecx, 493
    call fs_mkdir
    cmp rax, 0
    jle .gterr
    lea r11, [rel dir_ino]
    mov [r11+r13*8], rax
    mov rdi, rax
    lea rsi, [rel zname]
    mov edx, 1
    mov ecx, 420
    call fs_create
    cmp rax, 0
    jle .gterr
    lea r11, [rel dirf_ino]
    mov [r11+r13*8], rax
    mov rbx, rax
    mov byte [rel nameb], 'Z'
    mov eax, r13d
    add al, '0'
    mov [rel nameb+1], al
    mov rdi, rbx
    xor esi, esi
    lea rdx, [rel nameb]
    mov ecx, 2
    call fs_write
    cmp rax, 2
    jne .gterr
    inc r13
    jmp .gtd
.gtfiles:
    xor r12, r12
.gtloop:
    cmp r12, 4096
    jae .gtfull
    mov eax, r12d
    mov ecx, 1000
    xor edx, edx
    div ecx
    add al, '0'
    mov [rel nameb+1], al
    mov eax, edx
    mov ecx, 100
    xor edx, edx
    div ecx
    add al, '0'
    mov [rel nameb+2], al
    mov eax, edx
    mov ecx, 10
    xor edx, edx
    div ecx
    add al, '0'
    mov [rel nameb+3], al
    add dl, '0'
    mov [rel nameb+4], dl
    mov byte [rel nameb], 'f'
    mov byte [rel nameb+5], 0
    mov edi, ROOT_INO
    lea rsi, [rel nameb]
    mov edx, 5
    mov ecx, 420
    call fs_create
    cmp rax, 0
    jle .gterr
    lea r11, [rel ino_tab]
    mov [r11+r12*8], rax
    mov rbx, rax
    mov rdi, rbx
    xor esi, esi
    lea rdx, [rel nameb+1]
    mov ecx, 4
    call fs_write
    cmp rax, 4
    jne .gterr
    inc r12
    call btree_root_level
    cmp rax, 0
    jl .gterr
    cmp rax, 2
    jl .gtloop
    call btree_root_nitems
    cmp rax, 0
    jl .gterr
    cmp rax, 3
    jl .gtloop
    mov [rel n_bulk], r12
    mov [rsp], rax
    lea rdi, [rel msg_nfiles]
    call print_out
    mov rax, [rel n_bulk]
    call print_u64
    mov edi, 1
    lea rsi, [rel nl]
    mov edx, 1
    mov rax, SYS_write
    syscall
    jmp .gtreopen
.gtfull:
    mov rax, -ENOSPC
    jmp .gterr
.gtreopen:
    call fs_close
    lea rdi, [rel img]
    call fs_open
    test eax, eax
    jnz .gterr
    xor r12, r12
.gtrd:
    cmp r12, [rel n_bulk]
    jae .gtdirs
    mov eax, r12d
    mov ecx, 1000
    xor edx, edx
    div ecx
    add al, '0'
    mov [rel nameb+1], al
    mov eax, edx
    mov ecx, 100
    xor edx, edx
    div ecx
    add al, '0'
    mov [rel nameb+2], al
    mov eax, edx
    mov ecx, 10
    xor edx, edx
    div ecx
    add al, '0'
    mov [rel nameb+3], al
    add dl, '0'
    mov [rel nameb+4], dl
    lea r11, [rel ino_tab]
    mov rdi, [r11+r12*8]
    xor esi, esi
    lea rdx, [rel rbuf]
    mov ecx, 4
    call fs_read
    cmp rax, 4
    jne .gterr
    lea rdi, [rel rbuf]
    lea rsi, [rel nameb+1]
    mov edx, 4
    call memcmp
    test eax, eax
    jnz .gterr
    inc r12
    jmp .gtrd
.gtdirs:
    xor r13, r13
.gtdl:
    cmp r13, 4
    jae .gtname
    mov byte [rel nameb], 'd'
    mov eax, r13d
    add al, '0'
    mov [rel nameb+1], al
    mov byte [rel nameb+2], 0
    mov edi, ROOT_INO
    lea rsi, [rel nameb]
    mov edx, 2
    call fs_lookup
    lea r11, [rel dir_ino]
    cmp rax, [r11+r13*8]
    jne .gterr
    lea r11, [rel dirf_ino]
    mov rdi, [r11+r13*8]
    xor esi, esi
    lea rdx, [rel rbuf]
    mov ecx, 2
    call fs_read
    cmp rax, 2
    jne .gterr
    mov byte [rel nameb], 'Z'
    mov eax, r13d
    add al, '0'
    mov [rel nameb+1], al
    lea rdi, [rel rbuf]
    lea rsi, [rel nameb]
    mov edx, 2
    call memcmp
    test eax, eax
    jnz .gterr
    inc r13
    jmp .gtdl
.gtname:
    mov edi, ROOT_INO
    lea rsi, [rel nameb]
    mov byte [rel nameb], 'f'
    mov eax, [rel n_bulk]
    dec eax
    mov ecx, 1000
    xor edx, edx
    div ecx
    add al, '0'
    mov [rel nameb+1], al
    mov eax, edx
    mov ecx, 100
    xor edx, edx
    div ecx
    add al, '0'
    mov [rel nameb+2], al
    mov eax, edx
    mov ecx, 10
    xor edx, edx
    div ecx
    add al, '0'
    mov [rel nameb+3], al
    add dl, '0'
    mov [rel nameb+4], dl
    mov byte [rel nameb+5], 0
    mov edi, ROOT_INO
    lea rsi, [rel nameb]
    mov edx, 5
    call fs_lookup
    cmp rax, 0
    jle .gterr
    lea r11, [rel ino_tab]
    mov rcx, [rel n_bulk]
    dec rcx
    cmp rax, [r11+rcx*8]
    jne .gterr
    mov byte [rel which_fail], 2
    lea r11, [rel ino_tab]
    mov rdi, [r11]
    mov rsi, TYPE_EXTENT
    xor edx, edx
    lea rcx, [rel exttmp]
    mov r8, EXT_BYTES
    call btree_get
    cmp rax, EXT_BYTES
    jne .gterr
    lea r11, [rel exttmp]
    mov rax, [r11+EXT_DISK]
    mov [rel tamper_bn], rax
    mov rax, [rel fs_root]
    mov [rel root_bn], rax
    call fs_close
    mov rax, [rel tamper_bn]
    shl rax, 12
    add rax, 128
    mov [rsp+8], rax
    call .flip_at
    test eax, eax
    jnz .gterr
    lea rdi, [rel img]
    call fs_open
    test eax, eax
    jnz .gterr
    lea r11, [rel ino_tab]
    mov rdi, [r11]
    xor esi, esi
    lea rdx, [rel rbuf]
    mov ecx, 4
    call fs_read
    mov [rsp], rax
    call fs_close
    mov rax, [rsp+8]
    call .flip_at
    test eax, eax
    jnz .gterr
    mov rax, [rsp]
    cmp rax, -EIO
    jne .gterr
    lea rdi, [rel img]
    call fs_open
    test eax, eax
    jnz .gterr
    lea r11, [rel ino_tab]
    mov rdi, [r11]
    xor esi, esi
    lea rdx, [rel rbuf]
    mov ecx, 4
    call fs_read
    cmp rax, 4
    jne .gterr
    call fs_close
    mov rax, [rel root_bn]
    shl rax, 12
    mov [rsp+8], rax
    mov rax, SYS_open
    lea rdi, [rel img]
    mov rsi, O_RDWR
    xor edx, edx
    syscall
    cmp rax, 0
    jl .gterr
    mov [rsp], rax
    mov rax, SYS_pread
    mov rdi, [rsp]
    lea rsi, [rel tbuf]
    mov edx, BLOCK_SIZE
    mov r10, [rsp+8]
    syscall
    cmp rax, BLOCK_SIZE
    jne .gtc
    lea rdi, [rel rbuf]
    lea rsi, [rel tbuf]
    mov edx, BLOCK_SIZE
    call memcpy
    inc byte [rel tbuf+100]
    mov dword [rel tbuf+NH_CRC], 0
    lea rdi, [rel tbuf+8]
    mov esi, BLOCK_SIZE-8
    call crc32c
    mov [rel tbuf+NH_CRC], eax
    mov rax, SYS_pwrite
    mov rdi, [rsp]
    lea rsi, [rel tbuf]
    mov edx, BLOCK_SIZE
    mov r10, [rsp+8]
    syscall
    cmp rax, BLOCK_SIZE
    jne .gtc
    mov rax, SYS_close
    mov rdi, [rsp]
    syscall
    lea rdi, [rel img]
    call fs_open
    cmp eax, -EIO
    jne .gtmeta
    mov rax, SYS_open
    lea rdi, [rel img]
    mov rsi, O_RDWR
    xor edx, edx
    syscall
    cmp rax, 0
    jl .gterr
    mov [rsp], rax
    mov rax, SYS_pwrite
    mov rdi, [rsp]
    lea rsi, [rel rbuf]
    mov edx, BLOCK_SIZE
    mov r10, [rsp+8]
    syscall
    cmp rax, BLOCK_SIZE
    jne .gtc
    mov rax, SYS_close
    mov rdi, [rsp]
    syscall
    lea rdi, [rel img]
    call fs_open
    test eax, eax
    jnz .gterr
    xor eax, eax
    jmp .gtdone
.gtmeta:
    mov [rsp+16], rax
    mov rax, SYS_open
    lea rdi, [rel img]
    mov rsi, O_RDWR
    xor edx, edx
    syscall
    cmp rax, 0
    jl .gterr
    mov rbx, rax
    mov rax, SYS_pwrite
    mov rdi, rbx
    lea rsi, [rel rbuf]
    mov edx, BLOCK_SIZE
    mov r10, [rsp+8]
    syscall
    mov rax, SYS_close
    mov rdi, rbx
    syscall
    mov rax, [rsp+16]
    jmp .gterr
.gtc:
    mov rbx, rax
    mov rax, SYS_close
    mov rdi, [rsp]
    syscall
    mov rax, rbx
    cmp rax, 0
    jge .gtcio
    jmp .gterr
.gtcio:
    mov rax, -EIO
    jmp .gterr
.gterr:
    mov byte [rsp+16], 0
    test rax, rax
    js .gtdone
    mov rax, -EIO
.gtdone:
    EPILOGUE 24

; rax = file offset. XOR byte 1. Returns 0 or -errno.
.flip_at:
    PROLOGUE 8
    mov [rsp], rax
    mov rax, SYS_open
    lea rdi, [rel img]
    mov rsi, O_RDWR
    xor edx, edx
    syscall
    cmp rax, 0
    jl .flbad
    mov rbx, rax
    mov rax, SYS_pread
    mov rdi, rbx
    lea rsi, [rel nameb+8]
    mov edx, 1
    mov r10, [rsp]
    syscall
    cmp rax, 1
    jne .flc
    xor byte [rel nameb+8], 1
    mov rax, SYS_pwrite
    mov rdi, rbx
    lea rsi, [rel nameb+8]
    mov edx, 1
    mov r10, [rsp]
    syscall
    cmp rax, 1
    jne .flc
    mov rax, SYS_close
    mov rdi, rbx
    syscall
    xor eax, eax
    EPILOGUE 8
.flc:
    mov r12, rax
    mov rax, SYS_close
    mov rdi, rbx
    syscall
    mov rax, r12
    cmp rax, 0
    jl .flbad
    mov rax, -EIO
.flbad:
    EPILOGUE 8

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
zname: db "z", 0
tag_root: db " root=", 0
tag_q: db " q=", 0
tag_b: db " b=", 0
