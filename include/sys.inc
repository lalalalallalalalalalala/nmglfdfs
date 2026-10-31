bits 64
default rel

%include "const.inc"

%define SYS_read        0
%define SYS_write       1
%define SYS_open        2
%define SYS_close       3
%define SYS_stat        4
%define SYS_fstat       5
%define SYS_pread       17
%define SYS_pwrite      18
%define SYS_exit        60
%define SYS_fork        57
%define SYS_execve      59
%define SYS_wait4       61
%define SYS_ftruncate   77
%define SYS_getuid      102
%define SYS_getgid      104
%define SYS_geteuid     107
%define SYS_mount       165
%define SYS_umount2     166
%define SYS_clock_gettime 228
%define SYS_exit_group  231
%define SYS_getrandom   318
%define SYS_socketpair  53
%define SYS_recvmsg     47
%define SYS_fcntl       72
%define SYS_mkdir       83
%define SYS_unlink      87
%define SYS_getcwd      79

%define O_RDONLY        0
%define O_WRONLY        1
%define O_RDWR          2
%define O_CREAT         64
%define O_TRUNC         512
%define O_CLOEXEC       0x80000

; After six callee-saved pushes, RSP ≡ 8 (mod 16). Sub amount must be ≡ 8 (mod 16).
%macro PROLOGUE 1
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, %1
%endmacro

%macro EPILOGUE 1
    add rsp, %1
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
%endmacro
