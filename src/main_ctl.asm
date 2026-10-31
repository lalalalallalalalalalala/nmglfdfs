%include "sys.inc"

extern argc, argv, envp, cli_init, explain_err, print_out, print_err, strcmp
extern fs_sleep, fs_wake, fs_wipe
extern pos_argc, pos0, pos1

section .rodata
usage: db "Использование: nmglfdfs-ctl [-p ПАРОЛЬ] sleep|wake|wipe ОБРАЗ", 10
       db "  sleep  скрыть метаданные, пока образ не разбудят", 10
       db "  wake   вернуть метаданные тем же паролем", 10
       db "  wipe   необратимо уничтожить ключ (crypto-shred)", 10
       db "Пароль: -p или переменная NMGLFDFS_PASSPHRASE.", 10, 0
cmd_sleep: db "sleep", 0
cmd_wake:  db "wake", 0
cmd_wipe:  db "wipe", 0
ok_sleep:  db "Файловая система усыплена. Чтение закрыто до wake.", 10, 0
ok_wake:   db "Файловая система разбужена.", 10, 0
ok_wipe:   db "Ключ метаданных уничтожен. Данные больше нельзя прочитать.", 10, 0

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
    lea rsi, [rel cmd_sleep]
    call strcmp
    test eax, eax
    jnz .trywake
    mov rdi, [rel pos1]
    call fs_sleep
    lea rbx, [rel ok_sleep]
    jmp .done
.trywake:
    mov rdi, [rel pos0]
    lea rsi, [rel cmd_wake]
    call strcmp
    test eax, eax
    jnz .trywipe
    mov rdi, [rel pos1]
    call fs_wake
    lea rbx, [rel ok_wake]
    jmp .done
.trywipe:
    mov rdi, [rel pos0]
    lea rsi, [rel cmd_wipe]
    call strcmp
    test eax, eax
    jnz .usage
    mov rdi, [rel pos1]
    call fs_wipe
    lea rbx, [rel ok_wipe]
.done:
    test rax, rax
    jnz .err
    mov rdi, rbx
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
