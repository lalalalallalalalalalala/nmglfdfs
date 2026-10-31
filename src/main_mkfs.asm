%include "sys.inc"

extern argc, argv, envp, cli_init, explain_err, print_out, print_err
extern fs_format, parse_u64
extern pos_argc, pos0, pos1

section .rodata
usage: db "Использование: mkfs.nmglfdfs [-p ПАРОЛЬ] ОБРАЗ РАЗМЕР_МБ", 10
       db "Пароль можно также передать в переменной NMGLFDFS_PASSPHRASE.", 10, 0
okmsg: db "Образ NMGLFDFS создан.", 10, 0

section .text
global _start

_start:
    pop rdi
    mov rsi, rsp
    lea rdx, [rsp+rdi*8+8]
    mov [rel argc], rdi
    mov [rel argv], rsi
    mov [rel envp], rdx
    call tool_main
    mov rdi, rax
    mov rax, SYS_exit
    syscall

tool_main:
    PROLOGUE 8
    call cli_init
    test eax, eax
    jnz .usage
    cmp qword [rel pos_argc], 2
    jb .usage
    mov rdi, [rel pos1]
    call parse_u64
    jc .usage
    mov rsi, rax
    mov rdi, [rel pos0]
    call fs_format
    test rax, rax
    jnz .err
    lea rdi, [rel okmsg]
    call print_out
    xor eax, eax
    EPILOGUE 8
.usage:
    lea rdi, [rel usage]
    call print_err
    mov eax, 1
    EPILOGUE 8
.err:
    call explain_err
    mov eax, 1
    EPILOGUE 8
