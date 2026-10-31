%include "sys.inc"

section .bss
global argc, argv, envp, debug_on
global pass_buf, pass_len, pos_argc
global pos0, pos1, pos2, pos3

argc:       resq 1
argv:       resq 1
envp:       resq 1
debug_on:   resb 1
pass_buf:   resb MAX_PASS
pass_len:   resq 1
pos_argc:   resq 1
pos0:       resq 1
pos1:       resq 1
pos2:       resq 1
pos3:       resq 1

section .data
env_debug:  db "NMGLFDFS_DEBUG", 0
env_pass:   db "NMGLFDFS_PASSPHRASE", 0
nl:         db 10

section .text
global memcpy, memset, memmove, memcmp, strlen, strcmp
global print_fd, print_err, print_out, print_hex8, print_hexbuf, print_u64
global die, getenv, now_ms, fill_random, parse_u64, ct_memeq
global cli_init, app_startup, explain_err

; rdi dst, rsi src, rdx n
memcpy:
    push rdi
    mov rcx, rdx
    test rcx, rcx
    jz .d
    rep movsb
.d:
    pop rax
    ret

; rdi dst, rsi val, rdx n
memset:
    push rdi
    mov rax, rsi
    mov rcx, rdx
    test rcx, rcx
    jz .d
    rep stosb
.d:
    pop rax
    ret

; rdi dst, rsi src, rdx n  (overlap safe)
memmove:
    push rbx
    mov rax, rdi
    mov rcx, rdx
    test rcx, rcx
    jz .d
    cmp rdi, rsi
    je .d
    jb .fwd
    lea rbx, [rsi+rcx]
    cmp rdi, rbx
    jae .fwd
    ; backward
    lea rsi, [rsi+rcx-1]
    lea rdi, [rdi+rcx-1]
    std
    rep movsb
    cld
    jmp .d
.fwd:
    rep movsb
.d:
    pop rbx
    ret

; rdi a, rsi b, rdx n -> rax 0 if equal, else nonzero
memcmp:
    xor eax, eax
    test rdx, rdx
    jz .d
.l:
    mov cl, [rdi]
    mov ch, [rsi]
    cmp cl, ch
    jne .ne
    inc rdi
    inc rsi
    dec rdx
    jnz .l
    xor eax, eax
    ret
.ne:
    movzx eax, cl
    movzx ecx, ch
    sub eax, ecx
.d:
    ret

; constant-time compare of exactly rcx bytes? 
; rdi a, rsi b, rdx n -> rax 0 if equal
ct_memeq:
    xor eax, eax
    test rdx, rdx
    jz .d
.l:
    mov cl, [rdi]
    xor cl, [rsi]
    movzx ecx, cl
    or eax, ecx
    inc rdi
    inc rsi
    dec rdx
    jnz .l
.d:
    ret

strlen:
    xor rax, rax
.l:
    cmp byte [rdi+rax], 0
    je .d
    inc rax
    jmp .l
.d:
    ret

; rax 0 if equal
strcmp:
    xor eax, eax
.l:
    mov cl, [rdi]
    mov ch, [rsi]
    cmp cl, ch
    jne .ne
    test cl, cl
    jz .eq
    inc rdi
    inc rsi
    jmp .l
.eq:
    xor eax, eax
    ret
.ne:
    mov eax, 1
    ret

; print rdx bytes from rsi to fd rdi
print_fd:
    push rbx
    push r12
    push r13
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
.l:
    test r13, r13
    jz .d
    mov rax, SYS_write
    mov rdi, rbx
    mov rsi, r12
    mov rdx, r13
    syscall
    cmp rax, 0
    jle .d
    add r12, rax
    sub r13, rax
    jmp .l
.d:
    pop r13
    pop r12
    pop rbx
    ret

print_out:
    push rdi
    call strlen
    mov rdx, rax
    pop rsi
    mov rdi, 1
    jmp print_fd

print_err:
    push rdi
    call strlen
    mov rdx, rax
    pop rsi
    mov rdi, 2
    call print_fd
    ret

print_nl:
    lea rsi, [rel nl]
    mov rdx, 1
    mov rdi, 1
    jmp print_fd

; print rax as 16 hex chars to stdout
print_hex8:
    PROLOGUE 8
    mov rbx, rax
    mov r12, 16
.h:
    mov rax, rbx
    shr rax, 60
    and eax, 0fh
    cmp eax, 10
    jb .dgt
    add eax, 'a'-10
    jmp .c
.dgt:
    add eax, '0'
.c:
    mov [rsp], al
    lea rsi, [rsp]
    mov rdx, 1
    mov rdi, 1
    call print_fd
    shl rbx, 4
    dec r12
    jnz .h
    EPILOGUE 8

; rdi buf, rsi len
print_hexbuf:
    PROLOGUE 8
    mov rbx, rdi
    mov r12, rsi
.l:
    test r12, r12
    jz .d
    movzx eax, byte [rbx]
    mov r13d, eax
    shr eax, 4
    call hex_nibble
    mov eax, r13d
    and eax, 0fh
    call hex_nibble
    inc rbx
    dec r12
    jmp .l
.d:
    EPILOGUE 8

; eax = nibble 0..15. Standalone so the call is aligned by its own prologue.
hex_nibble:
    PROLOGUE 8
    cmp eax, 10
    jb .dg
    add eax, 'a'-10
    jmp .p
.dg:
    add eax, '0'
.p:
    mov [rsp], al
    mov rdi, 1
    lea rsi, [rsp]
    mov rdx, 1
    call print_fd
    EPILOGUE 8

; print unsigned rax in decimal
print_u64:
    PROLOGUE 40
    lea rbx, [rsp+32]
    mov byte [rbx], 0
    mov r12, rax
    test r12, r12
    jnz .l
    dec rbx
    mov byte [rbx], '0'
    jmp .p
.l:
    test r12, r12
    jz .p
    xor rdx, rdx
    mov rax, r12
    mov rcx, 10
    div rcx
    mov r12, rax
    add dl, '0'
    dec rbx
    mov [rbx], dl
    jmp .l
.p:
    mov rdi, rbx
    call print_out
    EPILOGUE 40

; rdi cstr, noreturn
die:
    call print_err
    mov rdi, 1
    mov rax, SYS_exit
    syscall

; rdi name -> rax value ptr or 0
getenv:
    PROLOGUE 8
    mov rbx, rdi
    call strlen
    mov r12, rax          ; namelen
    mov r13, [rel envp]
.l:
    mov rdi, [r13]
    test rdi, rdi
    jz .no
    mov rsi, rbx
    mov rcx, r12
.cmp:
    mov al, [rsi]
    cmp al, [rdi]
    jne .next
    inc rsi
    inc rdi
    dec rcx
    jnz .cmp
    cmp byte [rdi], '='
    jne .next
    lea rax, [rdi+1]
    jmp .d
.next:
    add r13, 8
    jmp .l
.no:
    xor eax, eax
.d:
    EPILOGUE 8

now_ms:
    PROLOGUE 24
    mov rax, SYS_clock_gettime
    xor edi, edi
    lea rsi, [rsp]
    syscall
    mov rax, [rsp]        ; sec
    mov rcx, 1000
    mul rcx
    mov rbx, rax
    mov rax, [rsp+8]      ; nsec
    xor rdx, rdx
    mov rcx, 1000000
    div rcx
    add rax, rbx
    EPILOGUE 24

; rdi buf, rsi len
fill_random:
    push rbx
    push r12
    push r13
    mov rbx, rdi
    mov r12, rsi
.l:
    test r12, r12
    jz .d
    mov rax, SYS_getrandom
    mov rdi, rbx
    mov rsi, r12
    xor edx, edx
    syscall
    cmp rax, 0
    jle .fail
    add rbx, rax
    sub r12, rax
    jmp .l
.fail:
    mov rax, -EIO
    pop r13
    pop r12
    pop rbx
    ret
.d:
    xor eax, eax
    pop r13
    pop r12
    pop rbx
    ret

; rdi str -> rax value, CF=1 on error
parse_u64:
    xor rax, rax
    xor ecx, ecx
.l:
    mov cl, [rdi]
    test cl, cl
    jz .end
    cmp cl, '0'
    jb .bad
    cmp cl, '9'
    ja .bad
    sub cl, '0'
    mov rdx, 10
    mul rdx
    jc .bad
    add rax, rcx
    jc .bad
    inc rdi
    jmp .l
.end:
    clc
    ret
.bad:
    stc
    ret

; Parse argv. Fills positional pointers and passphrase.
; Returns rax 0 if passphrase present.
cli_init:
    PROLOGUE 8
    mov qword [rel pos_argc], 0
    mov qword [rel pass_len], 0
    mov byte [rel pass_buf], 0
    lea rdi, [rel env_debug]
    call getenv
    test rax, rax
    jz .nd
    mov byte [rel debug_on], 1
.nd:
    ; env passphrase as default
    lea rdi, [rel env_pass]
    call getenv
    test rax, rax
    jz .noenv
    mov rdi, rax
    call .copy_pass
.noenv:
    mov rbx, 1
.loop:
    cmp rbx, [rel argc]
    jae .done
    mov r12, [rel argv]
    mov rdi, [r12+rbx*8]
    lea rsi, [rel opt_p]
    call strcmp
    test eax, eax
    jnz .notp
    inc rbx
    cmp rbx, [rel argc]
    jae .bad
    mov rdi, [r12+rbx*8]
    call .copy_pass
    inc rbx
    jmp .loop
.notp:
    lea rsi, [rel opt_plong]
    mov rdx, 13
    push rdi
    call memcmp
    pop rdi
    test eax, eax
    jnz .pos
    lea rdi, [rdi+13]
    call .copy_pass
    inc rbx
    jmp .loop
.pos:
    mov rax, [rel pos_argc]
    cmp rax, 4
    jae .skippos
    lea r13, [rel pos0]
    mov rcx, [r12+rbx*8]
    mov [r13+rax*8], rcx
    inc qword [rel pos_argc]
.skippos:
    inc rbx
    jmp .loop
.done:
    cmp qword [rel pass_len], 0
    je .bad
    xor eax, eax
    EPILOGUE 8
.bad:
    mov rax, -EINVAL
    EPILOGUE 8

; rdi = cstr passphrase
.copy_pass:
    push rbx
    mov rbx, rdi
    call strlen
    cmp rax, MAX_PASS-1
    jb .oklen
    mov rax, MAX_PASS-1
.oklen:
    mov [rel pass_len], rax
    lea rdi, [rel pass_buf]
    mov rsi, rbx
    mov rdx, rax
    call memcpy
    mov rcx, [rel pass_len]
    lea rdi, [rel pass_buf]
    mov byte [rdi+rcx], 0
    pop rbx
    ret

app_startup:
    ret

; rax = signed errno (0 = success, negative = error). Prints one Russian line.
explain_err:
    PROLOGUE 8
    mov rbx, rax
    cmp rbx, 0
    jge .done
    cmp rbx, -ERR_SLEEP
    je .sleep
    cmp rbx, -ERR_WIPED
    je .wipe
    cmp rbx, -EPERM
    je .perm
    cmp rbx, -EINVAL
    je .inval
    cmp rbx, -EIO
    je .io
    cmp rbx, -ENOTDIR
    je .notdir
    lea rdi, [rel err_generic]
    call print_err
    mov rax, rbx
    neg rax
    call print_u64
    lea rdi, [rel err_nl]
    call print_err
    jmp .done
.sleep:
    lea rdi, [rel err_sleep]
    call print_err
    jmp .done
.wipe:
    lea rdi, [rel err_wipe]
    call print_err
    jmp .done
.perm:
    lea rdi, [rel err_perm]
    call print_err
    jmp .done
.inval:
    lea rdi, [rel err_inval]
    call print_err
    jmp .done
.io:
    lea rdi, [rel err_io]
    call print_err
    jmp .done
.notdir:
    lea rdi, [rel err_notdir]
    call print_err
.done:
    EPILOGUE 8

section .rodata
opt_p:      db "-p", 0
opt_plong:  db "--passphrase=", 0
err_nl:     db 10, 0
err_generic: db "Ошибка ", 0
err_sleep:  db "Файловая система спит. Сначала: nmglfdfs-ctl wake <образ>", 10, 0
err_wipe:   db "Метаданные уничтожены (wipe), данные расшифровать нельзя.", 10, 0
err_perm:   db "Неверный пароль.", 10, 0
err_inval:  db "Неверные аргументы.", 10, 0
err_io:     db "Ошибка ввода-вывода или повреждённый образ.", 10, 0
err_notdir: db "Точка монтирования должна быть каталогом.", 10, 0
