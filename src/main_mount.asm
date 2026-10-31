%include "sys.inc"

extern argc, argv, envp, cli_init, explain_err, print_err
extern fs_open, fs_close, fuse_main
extern pos_argc, pos0, pos1

section .rodata
usage: db "Использование: nmglfdfs [-p ПАРОЛЬ] ОБРАЗ ТОЧКА_МОНТИРОВАНИЯ", 10
       db "Процесс остаётся в фоне протокола FUSE, пока каталог не размонтируют:", 10
       db "  fusermount3 -u ТОЧКА_МОНТИРОВАНИЯ", 10
       db "Пароль: -p или переменная NMGLFDFS_PASSPHRASE.", 10, 0

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
    mov rdi, [rel pos0]
    call fs_open
    test rax, rax
    jnz .err
    mov rdi, [rel pos1]
    call fuse_main
    mov rbx, rax
    call fs_close
    mov rax, rbx
    test rax, rax
    jnz .err
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
