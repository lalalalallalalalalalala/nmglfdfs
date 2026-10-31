%include "sys.inc"

; Userspace FUSE daemon. The kernel protocol on /dev/fuse is spoken directly.
; Unprivileged mount is performed by the system helper fusermount3 (it is not
; linked in; we only exec it and receive the device fd over a socket).

extern memcpy, memset, strlen, print_err, explain_err, now_ms
extern fs_readdir_step
extern fs_lookup, fs_create, fs_mkdir, fs_unlink, fs_rmdir
extern fs_read, fs_write, fs_truncate, fs_rename, fs_read_inode, save_ino
extern ino_buf, fs_op_uid, fs_op_gid, fs_total, fs_free
extern envp

FUSE_BUFSZ equ 262144

section .bss
fuse_fd:        resd 1
sv:             resd 2
req_uid:        resd 1
req_gid:        resd 1
stop_loop:      resb 1
fuse_in:        resb FUSE_BUFSZ
fuse_out:       resb FUSE_BUFSZ
name_tmp:       resb 256
env_arr:        resq 256
comm_env:       resb 32
argv_mnt:       resq 1
re_ino:         resq 1
re_type:        resd 1

section .rodata
fusermount_bin: db "/usr/bin/fusermount3", 0
opt_o:          db "-o", 0
opt_dd:         db "--", 0
fuse_opts:      db "rw,nosuid,nodev,default_permissions,fsname=nmglfdfs", 0
msg_fuse_fail:  db "Не удалось смонтировать образ через fusermount3.", 10, 0
comm_prefix:    db "_FUSE_COMMFD="
comm_prefix_len equ 13

section .data
fuse_argv:
    dq fusermount_bin
    dq opt_o
    dq fuse_opts
    dq opt_dd
    dq 0
    dq 0

section .text
global fuse_main

; rdi = mountpoint. Returns 0 or negative errno. Does not return until unmount.
fuse_main:
    PROLOGUE 8
    mov rbx, rdi
    call fuse_mount
    test rax, rax
    js .ret
    call fuse_loop
    mov edi, [rel fuse_fd]
    mov rax, SYS_close
    syscall
    xor eax, eax
.ret:
    EPILOGUE 8

; rdi mountpoint -> rax 0 and fuse_fd set, or negative errno.
fuse_mount:
    PROLOGUE 264
    mov rbx, rdi
    mov rax, SYS_stat
    mov rdi, rbx
    lea rsi, [rsp]
    syscall
    cmp rax, 0
    jl .statbad
    mov eax, [rsp+24]
    and eax, 0xf000
    cmp eax, 0x4000
    jne .notdir

    mov rax, SYS_socketpair
    mov edi, 1
    mov esi, 1
    xor edx, edx
    lea r10, [rel sv]
    syscall
    cmp rax, 0
    jl .statbad

    mov rax, SYS_fork
    syscall
    cmp rax, 0
    je .child
    jl .statbad
    mov r12, rax
    mov edi, [rel sv]
    mov rax, SYS_close
    syscall

    call recv_fuse_fd
    mov r13, rax
    mov edi, [rel sv+4]
    mov rax, SYS_close
    syscall
    mov rax, SYS_wait4
    mov rdi, r12
    lea rsi, [rsp]
    xor edx, edx
    xor r10, r10
    syscall
    mov rax, r13
    test rax, rax
    js .ret
    mov [rel fuse_fd], eax
    xor eax, eax
    jmp .ret
.notdir:
    mov rax, -ENOTDIR
    jmp .ret
.statbad:
    cmp rax, -4096
    ja .ret
    mov rax, -EIO
.ret:
    EPILOGUE 264

.child:
    mov edi, [rel sv+4]
    mov rax, SYS_close
    syscall
    mov eax, [rel sv]
    call build_comm_env
    mov [rel fuse_argv+32], rbx
    call build_env
    mov rax, SYS_execve
    lea rdi, [rel fusermount_bin]
    lea rsi, [rel fuse_argv]
    lea rdx, [rel env_arr]
    syscall
    mov edi, 127
    mov rax, SYS_exit
    syscall

; eax = comm fd. Writes comm_env.
build_comm_env:
    PROLOGUE 24
    mov r12d, eax
    lea rdi, [rel comm_env]
    lea rsi, [rel comm_prefix]
    mov edx, comm_prefix_len
    call memcpy
    lea rbx, [rsp+16]
    mov byte [rbx], 0
    mov eax, r12d
    test eax, eax
    jnz .digits
    dec rbx
    mov byte [rbx], '0'
    jmp .copy
.digits:
    dec rbx
    xor edx, edx
    mov ecx, 10
    div ecx
    add dl, '0'
    mov [rbx], dl
    test eax, eax
    jnz .digits
.copy:
    lea rdi, [rel comm_env]
    add rdi, comm_prefix_len
.cl:
    mov al, [rbx]
    mov [rdi], al
    inc rbx
    inc rdi
    test al, al
    jnz .cl
    EPILOGUE 24

build_env:
    mov rsi, [rel envp]
    xor rcx, rcx
.l:
    cmp rcx, 250
    jae .add
    lea rdx, [rel env_arr]
    mov rax, [rsi+rcx*8]
    mov [rdx+rcx*8], rax
    test rax, rax
    jz .add
    inc rcx
    jmp .l
.add:
    lea rax, [rel comm_env]
    lea rdx, [rel env_arr]
    mov [rdx+rcx*8], rax
    mov qword [rdx+rcx*8+8], 0
    ret

recv_fuse_fd:
    PROLOGUE 168
    lea rax, [rsp+160]
    mov byte [rax], 0
    mov qword [rsp], rax
    mov qword [rsp+8], 1
    mov qword [rsp+16], 0
    mov dword [rsp+24], 0
    lea rax, [rsp]
    mov [rsp+32], rax
    mov qword [rsp+40], 1
    lea rax, [rsp+80]
    mov [rsp+48], rax
    mov qword [rsp+56], 64
    mov dword [rsp+64], 0
    mov rax, SYS_recvmsg
    mov edi, [rel sv+4]
    lea rsi, [rsp+16]
    xor edx, edx
    syscall
    cmp rax, 0
    jle .bad
    mov eax, [rsp+80+12]
    cmp eax, 1
    jne .bad
    mov eax, [rsp+80+16]
    cmp eax, 0
    jl .bad
    movsxd rax, eax
    jmp .ret
.bad:
    lea rdi, [rel msg_fuse_fail]
    call print_err
    mov rax, -EIO
.ret:
    EPILOGUE 168

fuse_loop:
    PROLOGUE 8
    mov byte [rel stop_loop], 0
.l:
    cmp byte [rel stop_loop], 0
    jne .done
    mov rax, SYS_read
    mov edi, [rel fuse_fd]
    lea rsi, [rel fuse_in]
    mov rdx, FUSE_BUFSZ
    syscall
    cmp rax, 0
    jle .done
    cmp rax, FUSE_IN_HEADER
    jb .done
    mov ecx, [rel fuse_in]
    cmp rax, rcx
    jb .done
    mov eax, [rel fuse_in+24]
    mov [rel req_uid], eax
    mov [rel fs_op_uid], eax
    mov eax, [rel fuse_in+28]
    mov [rel req_gid], eax
    mov [rel fs_op_gid], eax
    mov eax, [rel fuse_in+4]
    cmp eax, FUSE_FORGET
    je .l
    cmp eax, FUSE_BATCH_FORGET
    je .l
    cmp eax, FUSE_INTERRUPT
    je .l
    cmp eax, FUSE_INIT
    je .init
    cmp eax, FUSE_DESTROY
    je .destroy
    cmp eax, FUSE_LOOKUP
    je .lookup
    cmp eax, FUSE_GETATTR
    je .getattr
    cmp eax, FUSE_SETATTR
    je .setattr
    cmp eax, FUSE_MKDIR
    je .mkdir
    cmp eax, FUSE_CREATE
    je .create
    cmp eax, FUSE_MKNOD
    je .mknod
    cmp eax, FUSE_UNLINK
    je .unlink
    cmp eax, FUSE_RMDIR
    je .rmdir
    cmp eax, FUSE_OPEN
    je .open
    cmp eax, FUSE_OPENDIR
    je .open
    cmp eax, FUSE_READ
    je .read
    cmp eax, FUSE_WRITE
    je .write
    cmp eax, FUSE_RELEASE
    je .ok0
    cmp eax, FUSE_RELEASEDIR
    je .ok0
    cmp eax, FUSE_FLUSH
    je .ok0
    cmp eax, FUSE_FSYNC
    je .ok0
    cmp eax, FUSE_FSYNCDIR
    je .ok0
    cmp eax, FUSE_ACCESS
    je .ok0
    cmp eax, FUSE_STATFS
    je .statfs
    cmp eax, FUSE_READDIR
    je .readdir
    cmp eax, FUSE_RENAME
    je .rename
    cmp eax, FUSE_RENAME2
    je .rename2
    mov eax, -ENOSYS
    call reply_errno
    jmp .l
.ok0:
    xor edi, edi
    call reply_payload
    jmp .l
.init:
    call do_init
    jmp .l
.destroy:
    xor edi, edi
    call reply_payload
    mov byte [rel stop_loop], 1
    jmp .l
.lookup:
    call do_lookup
    jmp .l
.getattr:
    call do_getattr
    jmp .l
.setattr:
    call do_setattr
    jmp .l
.mkdir:
    call do_mkdir
    jmp .l
.create:
    call do_create
    jmp .l
.mknod:
    call do_mknod
    jmp .l
.unlink:
    call do_unlink
    jmp .l
.rmdir:
    call do_rmdir
    jmp .l
.open:
    call do_open
    jmp .l
.read:
    call do_read
    jmp .l
.write:
    call do_write
    jmp .l
.statfs:
    call do_statfs
    jmp .l
.readdir:
    call do_readdir
    jmp .l
.rename:
    mov esi, 8
    call do_rename
    jmp .l
.rename2:
    mov esi, FUSE_RENAME2_IN
    call do_rename
    jmp .l
.done:
    EPILOGUE 8

; Header nodeid -> rax internal inode. nodeid 1 is the root.
node_ino:
    mov rax, [rel fuse_in+16]
    cmp rax, FUSE_ROOT_ID
    jne .d
    mov rax, ROOT_INO
.d:
    ret

; rdi internal inode -> rax fuse nodeid
ino_fuse:
    mov rax, rdi
    cmp rax, ROOT_INO
    jne .d
    mov rax, FUSE_ROOT_ID
.d:
    ret

; Fill fuse_attr at rdi from ino_buf. rsi = fuse ino.
fill_attr:
    push rbx
    mov rbx, rdi
    mov [rbx], rsi
    mov rax, [rel ino_buf+INO_SIZE]
    mov [rbx+8], rax
    mov rax, [rel ino_buf+INO_BLOCKS]
    shl rax, 3
    mov [rbx+16], rax
    mov rax, [rel ino_buf+INO_ATIME]
    mov [rbx+24], rax
    mov rax, [rel ino_buf+INO_MTIME]
    mov [rbx+32], rax
    mov rax, [rel ino_buf+INO_CTIME]
    mov [rbx+40], rax
    mov dword [rbx+48], 0
    mov dword [rbx+52], 0
    mov dword [rbx+56], 0
    mov eax, [rel ino_buf+INO_MODE]
    mov [rbx+60], eax
    mov eax, [rel ino_buf+INO_NLINK]
    mov [rbx+64], eax
    mov eax, [rel ino_buf+INO_UID]
    mov [rbx+68], eax
    mov eax, [rel ino_buf+INO_GID]
    mov [rbx+72], eax
    mov dword [rbx+76], 0
    mov dword [rbx+80], BLOCK_SIZE
    mov dword [rbx+84], 0
    pop rbx
    ret

; rdi = payload length. unique taken from the current request. error = 0.
reply_payload:
    mov eax, edi
    add eax, FUSE_OUT_HEADER
    mov [rel fuse_out], eax
    mov dword [rel fuse_out+4], 0
    mov rax, [rel fuse_in+8]
    mov [rel fuse_out+8], rax
    mov edx, [rel fuse_out]
    mov edi, [rel fuse_fd]
    lea rsi, [rel fuse_out]
    call write_full
    ret

; eax = negative errno
reply_errno:
    mov dword [rel fuse_out], FUSE_OUT_HEADER
    mov [rel fuse_out+4], eax
    mov rax, [rel fuse_in+8]
    mov [rel fuse_out+8], rax
    mov edi, [rel fuse_fd]
    lea rsi, [rel fuse_out]
    mov edx, FUSE_OUT_HEADER
    call write_full
    ret

write_full:
    push rbx
    push r12
    push r13
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
.l:
    test r13, r13
    jz .ok
    mov rax, SYS_write
    mov rdi, rbx
    mov rsi, r12
    mov rdx, r13
    syscall
    cmp rax, 0
    jle .bad
    add r12, rax
    sub r13, rax
    jmp .l
.ok:
    xor eax, eax
    pop r13
    pop r12
    pop rbx
    ret
.bad:
    mov rax, -EIO
    pop r13
    pop r12
    pop rbx
    ret

; rdi = start, rsi = end (exclusive) -> rax length, or -1 if no NUL in range.
cstr_n:
    xor rax, rax
.l:
    lea rcx, [rdi+rax]
    cmp rcx, rsi
    jae .bad
    cmp byte [rdi+rax], 0
    je .d
    inc rax
    cmp rax, MAX_NAME
    ja .bad
    jmp .l
.bad:
    mov rax, -1
.d:
    ret

; Load inode rdi into ino_buf. rax 0 or negative.
load_fuse_ino:
    lea rsi, [rel ino_buf]
    call fs_read_inode
    ret

; Write entry_out at fuse_out+16 for internal inode rdi. rax 0 or error.
; Also leaves fuse nodeid in r12.
emit_entry:
    PROLOGUE 8
    mov rbx, rdi
    call load_fuse_ino
    test eax, eax
    jnz .ret
    mov rdi, rbx
    call ino_fuse
    mov r12, rax
    lea rdi, [rel fuse_out+FUSE_OUT_HEADER]
    xor esi, esi
    mov edx, FUSE_ENTRY_OUT
    call memset
    mov [rel fuse_out+FUSE_OUT_HEADER], r12
    lea rdi, [rel fuse_out+FUSE_OUT_HEADER+40]
    mov rsi, r12
    call fill_attr
    xor eax, eax
.ret:
    EPILOGUE 8

do_init:
    PROLOGUE 8
    mov eax, [rel fuse_in+FUSE_IN_HEADER]
    cmp eax, 7
    jne .bad
    mov eax, [rel fuse_in+FUSE_IN_HEADER+4]
    cmp eax, FUSE_KERNEL_MINOR
    jbe .minor
    mov eax, FUSE_KERNEL_MINOR
.minor:
    mov r12d, eax
    mov eax, [rel fuse_in+FUSE_IN_HEADER+8]
    cmp eax, 65536
    jbe .ra
    mov eax, 65536
.ra:
    mov r13d, eax
    lea rdi, [rel fuse_out+FUSE_OUT_HEADER]
    xor esi, esi
    mov edx, FUSE_INIT_OUT
    call memset
    mov dword [rel fuse_out+FUSE_OUT_HEADER], 7
    mov [rel fuse_out+FUSE_OUT_HEADER+4], r12d
    mov [rel fuse_out+FUSE_OUT_HEADER+8], r13d
    mov dword [rel fuse_out+FUSE_OUT_HEADER+12], FUSE_BIG_WRITES
    mov word [rel fuse_out+FUSE_OUT_HEADER+16], 16
    mov word [rel fuse_out+FUSE_OUT_HEADER+18], 12
    mov dword [rel fuse_out+FUSE_OUT_HEADER+20], 65536
    mov dword [rel fuse_out+FUSE_OUT_HEADER+24], 1
    mov word [rel fuse_out+FUSE_OUT_HEADER+28], 16
    mov edi, FUSE_INIT_OUT
    call reply_payload
    jmp .ret
.bad:
    mov eax, -EINVAL
    call reply_errno
.ret:
    EPILOGUE 8

do_getattr:
    PROLOGUE 8
    call node_ino
    mov rbx, rax
    mov rdi, rbx
    call load_fuse_ino
    test eax, eax
    jnz .err
    mov rdi, rbx
    call ino_fuse
    mov r12, rax
    lea rdi, [rel fuse_out+FUSE_OUT_HEADER]
    xor esi, esi
    mov edx, FUSE_ATTR_OUT
    call memset
    lea rdi, [rel fuse_out+FUSE_OUT_HEADER+16]
    mov rsi, r12
    call fill_attr
    mov edi, FUSE_ATTR_OUT
    call reply_payload
    jmp .ret
.err:
    call reply_errno
.ret:
    EPILOGUE 8

do_lookup:
    PROLOGUE 8
    call node_ino
    mov rbx, rax
    mov eax, [rel fuse_in]
    lea rsi, [rel fuse_in]
    add rsi, rax
    lea rdi, [rel fuse_in+FUSE_IN_HEADER]
    call cstr_n
    cmp rax, 0
    jl .inval
    mov r12, rax
    mov rdi, rbx
    lea rsi, [rel fuse_in+FUSE_IN_HEADER]
    mov rdx, r12
    call fs_lookup
    test rax, rax
    js .err
    mov rdi, rax
    call emit_entry
    test eax, eax
    jnz .err
    mov edi, FUSE_ENTRY_OUT
    call reply_payload
    jmp .ret
.inval:
    mov eax, -EINVAL
.err:
    call reply_errno
.ret:
    EPILOGUE 8

do_mkdir:
    PROLOGUE 8
    call node_ino
    mov rbx, rax
    mov r13d, [rel fuse_in+FUSE_IN_HEADER]
    mov eax, [rel fuse_in]
    lea rsi, [rel fuse_in]
    add rsi, rax
    lea rdi, [rel fuse_in+FUSE_IN_HEADER+FUSE_MKDIR_IN]
    call cstr_n
    cmp rax, 0
    jl .inval
    mov r12, rax
    mov rdi, rbx
    lea rsi, [rel fuse_in+FUSE_IN_HEADER+FUSE_MKDIR_IN]
    mov rdx, r12
    mov ecx, r13d
    call fs_mkdir
    test rax, rax
    js .err
    mov rdi, rax
    call emit_entry
    test eax, eax
    jnz .err
    mov edi, FUSE_ENTRY_OUT
    call reply_payload
    jmp .ret
.inval:
    mov eax, -EINVAL
.err:
    call reply_errno
.ret:
    EPILOGUE 8

do_create:
    PROLOGUE 8
    call node_ino
    mov rbx, rax
    mov r13d, [rel fuse_in+FUSE_IN_HEADER+4]
    mov eax, [rel fuse_in]
    lea rsi, [rel fuse_in]
    add rsi, rax
    lea rdi, [rel fuse_in+FUSE_IN_HEADER+FUSE_CREATE_IN]
    call cstr_n
    cmp rax, 0
    jl .inval
    mov r12, rax
    mov rdi, rbx
    lea rsi, [rel fuse_in+FUSE_IN_HEADER+FUSE_CREATE_IN]
    mov rdx, r12
    mov ecx, r13d
    call fs_create
    test rax, rax
    js .err
    mov r14, rax
    mov rdi, r14
    call emit_entry
    test eax, eax
    jnz .err
    mov [rel fuse_out+FUSE_OUT_HEADER+FUSE_ENTRY_OUT], r14
    mov dword [rel fuse_out+FUSE_OUT_HEADER+FUSE_ENTRY_OUT+8], 0
    mov dword [rel fuse_out+FUSE_OUT_HEADER+FUSE_ENTRY_OUT+12], 0
    mov edi, FUSE_ENTRY_OUT+16
    call reply_payload
    jmp .ret
.inval:
    mov eax, -EINVAL
.err:
    call reply_errno
.ret:
    EPILOGUE 8

do_mknod:
    jmp do_create

do_unlink:
    PROLOGUE 8
    call node_ino
    mov rbx, rax
    mov eax, [rel fuse_in]
    lea rsi, [rel fuse_in]
    add rsi, rax
    lea rdi, [rel fuse_in+FUSE_IN_HEADER]
    call cstr_n
    cmp rax, 0
    jl .inval
    mov rdi, rbx
    lea rsi, [rel fuse_in+FUSE_IN_HEADER]
    mov rdx, rax
    call fs_unlink
    test eax, eax
    jnz .err
    xor edi, edi
    call reply_payload
    jmp .ret
.inval:
    mov eax, -EINVAL
.err:
    call reply_errno
.ret:
    EPILOGUE 8

do_rmdir:
    PROLOGUE 8
    call node_ino
    mov rbx, rax
    mov eax, [rel fuse_in]
    lea rsi, [rel fuse_in]
    add rsi, rax
    lea rdi, [rel fuse_in+FUSE_IN_HEADER]
    call cstr_n
    cmp rax, 0
    jl .inval
    mov rdi, rbx
    lea rsi, [rel fuse_in+FUSE_IN_HEADER]
    mov rdx, rax
    call fs_rmdir
    test eax, eax
    jnz .err
    xor edi, edi
    call reply_payload
    jmp .ret
.inval:
    mov eax, -EINVAL
.err:
    call reply_errno
.ret:
    EPILOGUE 8

do_open:
    PROLOGUE 8
    call node_ino
    mov rbx, rax
    mov rdi, rbx
    call load_fuse_ino
    test eax, eax
    jnz .err
    mov qword [rel fuse_out+FUSE_OUT_HEADER], rbx
    mov dword [rel fuse_out+FUSE_OUT_HEADER+8], 0
    mov dword [rel fuse_out+FUSE_OUT_HEADER+12], 0
    mov edi, 16
    call reply_payload
    jmp .ret
.err:
    call reply_errno
.ret:
    EPILOGUE 8

do_read:
    PROLOGUE 8
    call node_ino
    mov rbx, rax
    mov r12, [rel fuse_in+FUSE_IN_HEADER+8]
    mov eax, [rel fuse_in+FUSE_IN_HEADER+16]
    cmp eax, 131072
    jbe .sz
    mov eax, 131072
.sz:
    mov r13d, eax
    mov rdi, rbx
    mov rsi, r12
    lea rdx, [rel fuse_out+FUSE_OUT_HEADER]
    mov ecx, r13d
    call fs_read
    test rax, rax
    js .err
    mov edi, eax
    call reply_payload
    jmp .ret
.err:
    call reply_errno
.ret:
    EPILOGUE 8

do_write:
    PROLOGUE 8
    call node_ino
    mov rbx, rax
    mov r12, [rel fuse_in+FUSE_IN_HEADER+8]
    mov r13d, [rel fuse_in+FUSE_IN_HEADER+16]
    mov eax, [rel fuse_in]
    sub eax, FUSE_IN_HEADER+FUSE_WRITE_IN
    cmp r13d, eax
    ja .inval
    mov rdi, rbx
    mov rsi, r12
    lea rdx, [rel fuse_in+FUSE_IN_HEADER+FUSE_WRITE_IN]
    mov ecx, r13d
    call fs_write
    test rax, rax
    js .err
    mov [rel fuse_out+FUSE_OUT_HEADER], eax
    mov dword [rel fuse_out+FUSE_OUT_HEADER+4], 0
    mov edi, 8
    call reply_payload
    jmp .ret
.inval:
    mov eax, -EINVAL
.err:
    call reply_errno
.ret:
    EPILOGUE 8

do_setattr:
    PROLOGUE 8
    call node_ino
    mov rbx, rax
    mov r12d, [rel fuse_in+FUSE_IN_HEADER]
    test r12d, FATTR_SIZE
    jz .nosz
    mov rdi, rbx
    mov rsi, [rel fuse_in+FUSE_IN_HEADER+16]
    call fs_truncate
    test eax, eax
    jnz .err
.nosz:
    mov rdi, rbx
    call load_fuse_ino
    test eax, eax
    jnz .err
    test r12d, FATTR_MODE
    jz .nouid
    mov eax, [rel fuse_in+FUSE_IN_HEADER+68]
    mov ecx, eax
    and ecx, 0xf000
    jnz .mode
    mov ecx, [rel ino_buf+INO_MODE]
    and ecx, 0xf000
    and eax, 0xfff
    or eax, ecx
.mode:
    mov [rel ino_buf+INO_MODE], eax
.nouid:
    test r12d, FATTR_UID
    jz .nogid
    mov eax, [rel fuse_in+FUSE_IN_HEADER+76]
    mov [rel ino_buf+INO_UID], eax
.nogid:
    test r12d, FATTR_GID
    jz .noat
    mov eax, [rel fuse_in+FUSE_IN_HEADER+80]
    mov [rel ino_buf+INO_GID], eax
.noat:
    test r12d, FATTR_ATIME_NOW
    jz .atset
    call now_ms
    xor edx, edx
    mov rcx, 1000
    div rcx
    mov [rel ino_buf+INO_ATIME], rax
    jmp .nomt
.atset:
    test r12d, FATTR_ATIME
    jz .nomt
    mov rax, [rel fuse_in+FUSE_IN_HEADER+32]
    mov [rel ino_buf+INO_ATIME], rax
.nomt:
    test r12d, FATTR_MTIME_NOW
    jz .mtset
    call now_ms
    xor edx, edx
    mov rcx, 1000
    div rcx
    mov [rel ino_buf+INO_MTIME], rax
    jmp .save
.mtset:
    test r12d, FATTR_MTIME
    jz .save
    mov rax, [rel fuse_in+FUSE_IN_HEADER+40]
    mov [rel ino_buf+INO_MTIME], rax
.save:
    mov rdi, rbx
    call save_ino
    test eax, eax
    jnz .err
    mov rdi, rbx
    call ino_fuse
    mov r12, rax
    lea rdi, [rel fuse_out+FUSE_OUT_HEADER]
    xor esi, esi
    mov edx, FUSE_ATTR_OUT
    call memset
    lea rdi, [rel fuse_out+FUSE_OUT_HEADER+16]
    mov rsi, r12
    call fill_attr
    mov edi, FUSE_ATTR_OUT
    call reply_payload
    jmp .ret
.err:
    call reply_errno
.ret:
    EPILOGUE 8

do_statfs:
    PROLOGUE 8
    lea rdi, [rel fuse_out+FUSE_OUT_HEADER]
    xor esi, esi
    mov edx, 80
    call memset
    mov rax, [rel fs_total]
    mov [rel fuse_out+FUSE_OUT_HEADER], rax
    mov rax, [rel fs_free]
    mov [rel fuse_out+FUSE_OUT_HEADER+8], rax
    mov [rel fuse_out+FUSE_OUT_HEADER+16], rax
    mov dword [rel fuse_out+FUSE_OUT_HEADER+40], BLOCK_SIZE
    mov dword [rel fuse_out+FUSE_OUT_HEADER+44], MAX_NAME
    mov dword [rel fuse_out+FUSE_OUT_HEADER+48], BLOCK_SIZE
    mov edi, 80
    call reply_payload
    EPILOGUE 8

do_readdir:
    PROLOGUE 24
    call node_ino
    mov [rsp], rax
    mov rax, [rel fuse_in+FUSE_IN_HEADER+8]
    mov [rsp+8], rax
    mov eax, [rel fuse_in+FUSE_IN_HEADER+16]
    cmp eax, 131072
    jbe .cap
    mov eax, 131072
.cap:
    mov [rsp+16], eax
    lea rbx, [rel fuse_out+FUSE_OUT_HEADER]
    mov r15, rbx
.ent:
    mov rax, r15
    sub rax, rbx
    mov ecx, [rsp+16]
    sub ecx, eax
    cmp ecx, 280
    jl .send
    mov rdi, [rsp]
    mov rsi, [rsp+8]
    lea rdx, [rel name_tmp]
    lea rcx, [rel re_ino]
    lea r8, [rel re_type]
    call fs_readdir_step
    test rax, rax
    jz .send
    js .err
    mov [rsp+8], rax
    mov r13, rax
    lea rdi, [rel name_tmp]
    call strlen
    mov r14, rax
    mov rdi, [rel re_ino]
    call ino_fuse
    mov r12, rax
    mov [r15], r12
    mov [r15+8], r13
    mov [r15+16], r14d
    mov eax, [rel re_type]
    mov [r15+20], eax
    lea rdi, [r15+24]
    lea rsi, [rel name_tmp]
    mov rdx, r14
    call memcpy
    mov eax, r14d
    add eax, 24
    add eax, 7
    and eax, ~7
    add r15, rax
    jmp .ent
.send:
    mov rax, r15
    sub rax, rbx
    mov edi, eax
    call reply_payload
    jmp .ret
.err:
    mov rcx, r15
    sub rcx, rbx
    test rcx, rcx
    jnz .send
    call reply_errno
.ret:
    EPILOGUE 24

; esi = byte offset of the first name inside the payload (8 or 16).
do_rename:
    PROLOGUE 8
    mov r13d, esi
    call node_ino
    mov rbx, rax
    mov r14, [rel fuse_in+FUSE_IN_HEADER]
    cmp r14, FUSE_ROOT_ID
    jne .nd
    mov r14, ROOT_INO
.nd:
    mov eax, [rel fuse_in]
    lea r15, [rel fuse_in]
    add r15, rax
    lea rdi, [rel fuse_in+FUSE_IN_HEADER]
    add rdi, r13
    mov r12, rdi
    mov rsi, r15
    call cstr_n
    cmp rax, 0
    jl .inval
    mov rdx, rax
    lea r8, [r12+rax+1]
    mov rdi, r8
    mov rsi, r15
    mov [rel re_ino], rdx
    call cstr_n
    cmp rax, 0
    jl .inval
    mov r9, rax
    mov rdx, [rel re_ino]
    mov rsi, r12
    mov rdi, rbx
    mov rcx, r14
    call fs_rename
    test eax, eax
    jnz .err
    xor edi, edi
    call reply_payload
    jmp .ret
.inval:
    mov eax, -EINVAL
.err:
    call reply_errno
.ret:
    EPILOGUE 8
