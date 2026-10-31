%include "sys.inc"

extern memcpy, memset, memcmp, ct_memeq
extern crc32c, chacha20_xor, pbkdf2_sha256
extern derive_verifier, derive_wrap_key, derive_data_key, derive_meta_key, derive_sleep_key
extern fill_random, now_ms
extern pass_buf, pass_len

section .bss
global fs_fd, fs_flags, fs_total, fs_bitmap_start, fs_bitmap_blocks
global fs_root, fs_generation, fs_next_inode, fs_free, fs_kdf_iters
global fs_uid, fs_gid, fs_write_seq
global fs_salt, fs_uuid, fs_wrapped, fs_verifier, fs_sleep_blob
global fs_key, fs_data_key, fs_meta_key, fs_kek
global fs_op_uid, fs_op_gid
global super_buf, bitmap_mem, node_io

fs_fd:              resq 1
fs_flags:           resd 1
fs_bitmap_blocks:   resd 1
fs_total:           resq 1
fs_bitmap_start:    resq 1
fs_root:            resq 1
fs_generation:      resq 1
fs_next_inode:      resq 1
fs_free:            resq 1
fs_write_seq:       resq 1
fs_kdf_iters:       resd 1
fs_uid:             resd 1
fs_gid:             resd 1
fs_op_uid:          resd 1
fs_op_gid:          resd 1
fs_salt:            resb 16
fs_uuid:            resb 16
fs_wrapped:         resb 32
fs_verifier:        resb 32
fs_key:             resb 32
fs_data_key:        resb 32
fs_meta_key:        resb 32
fs_kek:             resb 32
fs_sleep_blob:      resb 64
alloc_hint:         resq 1
super_buf:          resb BLOCK_SIZE
node_io:            resb BLOCK_SIZE
bitmap_mem:         resb MAX_BITMAP_BLOCKS * BLOCK_SIZE
wrap_key_buf:       resb 32
nonce_tmp:          resb 16
global dbg_b
dbg_b:              resq 1

section .rodata
sleep_magic:        db "SLEEPv1!"

section .text
global block_read, block_write, node_read, node_write
global alloc_block, free_block, super_store, bitmap_write
global fs_format, fs_open, fs_close, fs_sleep, fs_wake
global bit_test, bit_set, bit_clear

; rdi = block, rsi = buf. 0 or -errno
block_read:
    PROLOGUE 8
    mov rbx, rdi
    mov r12, rsi
    mov rax, SYS_pread
    mov rdi, [rel fs_fd]
    mov rsi, r12
    mov rdx, BLOCK_SIZE
    mov r10, rbx
    shl r10, 12
    syscall
    cmp rax, BLOCK_SIZE
    je .ok
    mov rax, -EIO
    EPILOGUE 8
.ok:
    xor eax, eax
    EPILOGUE 8

block_write:
    PROLOGUE 8
    mov rbx, rdi
    mov r12, rsi
    mov rax, SYS_pwrite
    mov rdi, [rel fs_fd]
    mov rsi, r12
    mov rdx, BLOCK_SIZE
    mov r10, rbx
    shl r10, 12
    syscall
    cmp rax, BLOCK_SIZE
    je .ok
    mov rax, -EIO
    EPILOGUE 8
.ok:
    xor eax, eax
    EPILOGUE 8

; rdi = bn -> eax 1 if used. Clobbers rax, rcx, rdx.
bit_test:
    mov rax, rdi
    shr rax, 3
    mov cl, dil
    and cl, 7
    lea rdx, [rel bitmap_mem]
    mov dl, [rdx+rax]
    mov al, 1
    shl al, cl
    and al, dl
    movzx eax, al
    ret

bit_set:
    mov rax, rdi
    shr rax, 3
    mov cl, dil
    and cl, 7
    lea rdx, [rel bitmap_mem]
    add rdx, rax
    mov al, 1
    shl al, cl
    or [rdx], al
    ret

bit_clear:
    mov rax, rdi
    shr rax, 3
    mov cl, dil
    and cl, 7
    lea rdx, [rel bitmap_mem]
    add rdx, rax
    mov al, 1
    shl al, cl
    not al
    and [rdx], al
    ret

; rax = block or 0 if full
alloc_block:
    PROLOGUE 8
    mov rbx, [rel alloc_hint]
    mov r12, [rel fs_total]
    xor r13, r13
.scan:
    cmp rbx, r12
    jae .wrap
    mov rdi, rbx
    call bit_test
    test eax, eax
    jz .take
    inc rbx
    jmp .scan
.wrap:
    test r13, r13
    jnz .none
    mov r13, 1
    xor rbx, rbx
    jmp .scan
.take:
    test rbx, rbx
    jz .skip0
    mov rdi, rbx
    call bit_set
    dec qword [rel fs_free]
    lea rax, [rbx+1]
    mov [rel alloc_hint], rax
    mov rax, rbx
    EPILOGUE 8
.skip0:
    inc rbx
    jmp .scan
.none:
    xor eax, eax
    EPILOGUE 8

; rdi = bn
free_block:
    PROLOGUE 8
    mov rbx, rdi
    test rbx, rbx
    jz .d
    call bit_test
    test eax, eax
    jz .d
    mov rdi, rbx
    call bit_clear
    inc qword [rel fs_free]
    cmp rbx, [rel alloc_hint]
    jae .d
    mov [rel alloc_hint], rbx
.d:
    EPILOGUE 8

; Encrypt payload with the metadata key and write the node.
; rdi = plaintext node buffer (header bytenr already set). Buffer is not modified.
node_write:
    PROLOGUE 8
    mov rbx, rdi
    lea rdi, [rel node_io]
    mov rsi, rbx
    mov edx, BLOCK_SIZE
    call memcpy
    lea r12, [rel nonce_tmp]
    mov rax, [rel node_io+NH_BYTENR]
    mov [r12], rax
    mov eax, [rel node_io+NH_GEN]
    mov [r12+8], eax
    lea rdi, [rel node_io+PAYLOAD_OFF]
    mov rsi, rdi
    mov edx, PAYLOAD_SIZE
    lea rcx, [rel fs_meta_key]
    mov r8, r12
    xor r9d, r9d
    call chacha20_xor
    lea rdi, [rel node_io+8]
    mov esi, BLOCK_SIZE-8
    call crc32c
    mov [rel node_io+NH_CRC], eax
    mov rdi, [rel node_io+NH_BYTENR]
    lea rsi, [rel node_io]
    call block_write
    EPILOGUE 8

; rdi = bn, rsi = dst plaintext. 0 or -errno
node_read:
    PROLOGUE 8
    mov rbx, rdi
    mov r12, rsi
    mov rsi, r12
    call block_read
    test eax, eax
    jnz .ret
    mov eax, [r12+NH_MAGIC]
    cmp eax, MAGIC_NODE
    jne .badmagic
    mov rax, [r12+NH_BYTENR]
    cmp rax, rbx
    jne .badbn
    mov r13d, [r12+NH_CRC]
    mov dword [r12+NH_CRC], 0
    lea rdi, [r12+8]
    mov esi, BLOCK_SIZE-8
    call crc32c
    mov [r12+NH_CRC], r13d
    cmp eax, r13d
    jne .badcrc
    movzx eax, word [r12+NH_NITEMS]
    cmp ax, MAX_LEAF_ITEMS
    ja .badn
    lea r14, [rel nonce_tmp]
    mov rax, [r12+NH_BYTENR]
    mov [r14], rax
    mov eax, [r12+NH_GEN]
    mov [r14+8], eax
    lea rdi, [r12+PAYLOAD_OFF]
    mov rsi, rdi
    mov edx, PAYLOAD_SIZE
    lea rcx, [rel fs_meta_key]
    mov r8, r14
    xor r9d, r9d
    call chacha20_xor
    xor eax, eax
    jmp .ret
.badmagic:
    mov qword [rel dbg_b], 1
    jmp .io
.badbn:
    mov qword [rel dbg_b], 2
    jmp .io
.badcrc:
    mov qword [rel dbg_b], 3
    jmp .io
.badn:
    mov qword [rel dbg_b], 4
.io:
    mov rax, -EIO
.ret:
    EPILOGUE 8

super_crc_calc:
    mov dword [rel super_buf+SB_CRC], 0
    lea rdi, [rel super_buf]
    mov esi, SB_CRC
    call crc32c
    mov [rel super_buf+SB_CRC], eax
    ret

super_pack:
    PROLOGUE 8
    lea rdi, [rel super_buf]
    xor esi, esi
    mov edx, BLOCK_SIZE
    call memset
    mov rax, MAGIC_SUPER
    mov [rel super_buf+SB_MAGIC], rax
    mov dword [rel super_buf+SB_VERSION], VERSION
    mov eax, [rel fs_flags]
    mov [rel super_buf+SB_FLAGS], eax
    mov dword [rel super_buf+SB_BLOCK_SIZE], BLOCK_SIZE
    mov eax, [rel fs_bitmap_blocks]
    mov [rel super_buf+SB_BITMAP_BLOCKS], eax
    mov rax, [rel fs_total]
    mov [rel super_buf+SB_TOTAL_BLOCKS], rax
    mov rax, [rel fs_bitmap_start]
    mov [rel super_buf+SB_BITMAP_START], rax
    mov rax, [rel fs_root]
    mov [rel super_buf+SB_ROOT], rax
    mov rax, [rel fs_generation]
    mov [rel super_buf+SB_GENERATION], rax
    mov rax, [rel fs_next_inode]
    mov [rel super_buf+SB_NEXT_INODE], rax
    mov rax, [rel fs_free]
    mov [rel super_buf+SB_FREE_BLOCKS], rax
    mov eax, [rel fs_kdf_iters]
    mov [rel super_buf+SB_KDF_ITERS], eax
    lea rdi, [rel super_buf+SB_SALT]
    lea rsi, [rel fs_salt]
    mov edx, 16
    call memcpy
    lea rdi, [rel super_buf+SB_UUID]
    lea rsi, [rel fs_uuid]
    mov edx, 16
    call memcpy
    lea rdi, [rel super_buf+SB_WRAPPED]
    lea rsi, [rel fs_wrapped]
    mov edx, 32
    call memcpy
    lea rdi, [rel super_buf+SB_SLEEP]
    lea rsi, [rel fs_sleep_blob]
    mov edx, 64
    call memcpy
    lea rdi, [rel super_buf+SB_VERIFIER]
    lea rsi, [rel fs_verifier]
    mov edx, 32
    call memcpy
    mov rax, [rel fs_write_seq]
    mov [rel super_buf+SB_WRITE_SEQ], rax
    call super_crc_calc
    xor eax, eax
    EPILOGUE 8

; 0 if super_buf is a valid superblock
super_check:
    PROLOGUE 8
    mov rax, [rel super_buf+SB_MAGIC]
    mov rcx, MAGIC_SUPER
    cmp rax, rcx
    jne .bad
    mov eax, [rel super_buf+SB_VERSION]
    cmp eax, VERSION
    jne .bad
    mov r12d, [rel super_buf+SB_CRC]
    mov dword [rel super_buf+SB_CRC], 0
    lea rdi, [rel super_buf]
    mov esi, SB_CRC
    call crc32c
    mov [rel super_buf+SB_CRC], r12d
    cmp eax, r12d
    jne .bad
    xor eax, eax
    EPILOGUE 8
.bad:
    mov rax, -EIO
    EPILOGUE 8

super_unpack:
    mov eax, [rel super_buf+SB_FLAGS]
    mov [rel fs_flags], eax
    mov eax, [rel super_buf+SB_BITMAP_BLOCKS]
    mov [rel fs_bitmap_blocks], eax
    mov rax, [rel super_buf+SB_TOTAL_BLOCKS]
    mov [rel fs_total], rax
    mov rax, [rel super_buf+SB_BITMAP_START]
    mov [rel fs_bitmap_start], rax
    mov rax, [rel super_buf+SB_ROOT]
    mov [rel fs_root], rax
    mov rax, [rel super_buf+SB_GENERATION]
    mov [rel fs_generation], rax
    mov rax, [rel super_buf+SB_NEXT_INODE]
    mov [rel fs_next_inode], rax
    mov rax, [rel super_buf+SB_FREE_BLOCKS]
    mov [rel fs_free], rax
    mov eax, [rel super_buf+SB_KDF_ITERS]
    mov [rel fs_kdf_iters], eax
    mov rax, [rel super_buf+SB_WRITE_SEQ]
    mov [rel fs_write_seq], rax
    lea rdi, [rel fs_salt]
    lea rsi, [rel super_buf+SB_SALT]
    mov edx, 16
    call memcpy
    lea rdi, [rel fs_uuid]
    lea rsi, [rel super_buf+SB_UUID]
    mov edx, 16
    call memcpy
    lea rdi, [rel fs_wrapped]
    lea rsi, [rel super_buf+SB_WRAPPED]
    mov edx, 32
    call memcpy
    lea rdi, [rel fs_sleep_blob]
    lea rsi, [rel super_buf+SB_SLEEP]
    mov edx, 64
    call memcpy
    lea rdi, [rel fs_verifier]
    lea rsi, [rel super_buf+SB_VERIFIER]
    mov edx, 32
    call memcpy
    xor eax, eax
    ret

super_store:
    PROLOGUE 8
    call super_pack
    xor edi, edi
    lea rsi, [rel super_buf]
    call block_write
    test eax, eax
    jnz .ret
    mov edi, 1
    lea rsi, [rel super_buf]
    call block_write
.ret:
    EPILOGUE 8

bitmap_write:
    PROLOGUE 8
    mov ebx, [rel fs_bitmap_blocks]
    xor r12, r12
.l:
    cmp r12d, ebx
    jae .ok
    mov rax, [rel fs_bitmap_start]
    add rax, r12
    mov rdi, rax
    mov rax, r12
    shl rax, 12
    lea rsi, [rel bitmap_mem]
    add rsi, rax
    call block_write
    test eax, eax
    jnz .ret
    inc r12
    jmp .l
.ok:
    xor eax, eax
.ret:
    EPILOGUE 8

bitmap_read:
    PROLOGUE 8
    mov ebx, [rel fs_bitmap_blocks]
    cmp ebx, MAX_BITMAP_BLOCKS
    ja .bad
    test ebx, ebx
    jz .bad
    xor r12, r12
.l:
    cmp r12d, ebx
    jae .ok
    mov rax, [rel fs_bitmap_start]
    add rax, r12
    mov rdi, rax
    mov rax, r12
    shl rax, 12
    lea rsi, [rel bitmap_mem]
    add rsi, rax
    call block_read
    test eax, eax
    jnz .ret
    inc r12
    jmp .l
.ok:
    xor eax, eax
    jmp .ret
.bad:
    mov rax, -EIO
.ret:
    EPILOGUE 8

; Derive kek into fs_kek from pass_buf / salt / iters.
kdf_kek:
    PROLOGUE 8
    lea rdi, [rel fs_kek]
    lea rsi, [rel pass_buf]
    mov rdx, [rel pass_len]
    lea rcx, [rel fs_salt]
    mov r8d, 16
    mov r9d, [rel fs_kdf_iters]
    call pbkdf2_sha256
    EPILOGUE 8

; 0 if verifier matches kek.
check_verifier:
    PROLOGUE 40
    lea rdi, [rsp]
    lea rsi, [rel fs_kek]
    lea rdx, [rel fs_salt]
    call derive_verifier
    lea rdi, [rsp]
    lea rsi, [rel fs_verifier]
    mov edx, 32
    call ct_memeq
    test eax, eax
    jz .ok
    mov rax, -EPERM
    EPILOGUE 40
.ok:
    xor eax, eax
    EPILOGUE 40

; fs_wrapped = chacha(fs_key) under wrap key. Or the inverse, same operation.
apply_wrap:
    PROLOGUE 8
    lea rdi, [rel wrap_key_buf]
    lea rsi, [rel fs_kek]
    call derive_wrap_key
    lea rbx, [rel nonce_tmp]
    lea rsi, [rel fs_salt]
    mov rdi, rbx
    mov edx, 12
    call memcpy
    mov rdi, [rel wrap_dst]
    mov rsi, [rel wrap_src]
    mov edx, 32
    lea rcx, [rel wrap_key_buf]
    mov r8, rbx
    xor r9d, r9d
    call chacha20_xor
    xor eax, eax
    EPILOGUE 8

section .bss
wrap_dst:   resq 1
wrap_src:   resq 1

section .text

unwrap_key:
    PROLOGUE 8
    lea rax, [rel fs_key]
    mov [rel wrap_dst], rax
    lea rax, [rel fs_wrapped]
    mov [rel wrap_src], rax
    call apply_wrap
    lea rdi, [rel fs_data_key]
    lea rsi, [rel fs_key]
    call derive_data_key
    lea rdi, [rel fs_meta_key]
    lea rsi, [rel fs_key]
    call derive_meta_key
    xor eax, eax
    EPILOGUE 8

wrap_key:
    PROLOGUE 8
    lea rax, [rel fs_wrapped]
    mov [rel wrap_dst], rax
    lea rax, [rel fs_key]
    mov [rel wrap_src], rax
    call apply_wrap
    EPILOGUE 8

; rdi = path, rsi = size_mb
fs_format:
    PROLOGUE 8
    mov rbx, rdi
    mov r12, rsi
    cmp r12, 4
    jb .inval
    cmp r12, 2048
    ja .inval
    cmp qword [rel pass_len], 0
    je .inval
    mov rax, SYS_open
    mov rdi, rbx
    mov rsi, O_RDWR | O_CREAT | O_TRUNC
    mov rdx, 0x1a4
    syscall
    cmp rax, 0
    jl .retax
    mov [rel fs_fd], rax
    mov rax, r12
    shl rax, 20
    mov r13, rax
    mov rax, SYS_ftruncate
    mov rdi, [rel fs_fd]
    mov rsi, r13
    syscall
    cmp rax, 0
    jl .retax
    mov rax, r12
    shl rax, 8                  ; *256 blocks per MB
    mov [rel fs_total], rax
    mov rcx, rax
    add rcx, 32767
    shr rcx, 15
    mov [rel fs_bitmap_blocks], ecx
    mov qword [rel fs_bitmap_start], 2
    lea r14, [rcx+2]            ; root block
    mov [rel fs_root], r14
    mov qword [rel fs_generation], 1
    mov qword [rel fs_next_inode], 257
    mov qword [rel fs_write_seq], 1
    mov dword [rel fs_kdf_iters], KDF_ITERS_DEFAULT
    mov dword [rel fs_flags], 0
    mov rax, [rel fs_total]
    sub rax, r14
    dec rax                     ; blocks 0..root inclusive are used
    mov [rel fs_free], rax
    mov rax, SYS_getuid
    syscall
    mov [rel fs_uid], eax
    mov [rel fs_op_uid], eax
    mov rax, SYS_getgid
    syscall
    mov [rel fs_gid], eax
    mov [rel fs_op_gid], eax

    lea rdi, [rel bitmap_mem]
    xor esi, esi
    mov edx, MAX_BITMAP_BLOCKS * BLOCK_SIZE
    call memset
    xor rbx, rbx
.mark:
    cmp rbx, r14
    ja .marked
    mov rdi, rbx
    call bit_set
    inc rbx
    jmp .mark
.marked:
    lea rax, [r14+1]
    mov [rel alloc_hint], rax

    lea rdi, [rel node_io]
    mov esi, 64
    call fill_random
    test eax, eax
    jnz .ret
    lea rdi, [rel fs_salt]
    lea rsi, [rel node_io]
    mov edx, 16
    call memcpy
    lea rdi, [rel fs_uuid]
    lea rsi, [rel node_io+16]
    mov edx, 16
    call memcpy
    lea rdi, [rel fs_key]
    lea rsi, [rel node_io+32]
    mov edx, 32
    call memcpy
    call kdf_kek
    test eax, eax
    jnz .ret
    lea rdi, [rel fs_verifier]
    lea rsi, [rel fs_kek]
    lea rdx, [rel fs_salt]
    call derive_verifier
    call wrap_key
    lea rdi, [rel fs_data_key]
    lea rsi, [rel fs_key]
    call derive_data_key
    lea rdi, [rel fs_meta_key]
    lea rsi, [rel fs_key]
    call derive_meta_key
    lea rdi, [rel fs_sleep_blob]
    xor esi, esi
    mov edx, 64
    call memset
    call build_root_inode
    test eax, eax
    jnz .ret
    call bitmap_write
    test eax, eax
    jnz .ret
    call super_store
    jmp .ret
.inval:
    mov rax, -EINVAL
    jmp .ret
.retax:
    cmp rax, -4096
    ja .ret
    mov rax, -EIO
.ret:
    EPILOGUE 8

build_root_inode:
    PROLOGUE 8
    lea rdi, [rel node_io]
    xor esi, esi
    mov edx, BLOCK_SIZE
    call memset
    mov dword [rel node_io+NH_MAGIC], MAGIC_NODE
    mov rax, [rel fs_root]
    mov [rel node_io+NH_BYTENR], rax
    mov qword [rel node_io+NH_GEN], 1
    mov byte [rel node_io+NH_LEVEL], 0
    mov byte [rel node_io+NH_FLAGS], NH_FLAG_ENC
    mov word [rel node_io+NH_NITEMS], 1
    ; one inode item packed at the end of the payload
    lea rbx, [rel node_io+PAYLOAD_OFF]
    mov qword [rbx+IH_OBJ], ROOT_INO
    mov byte [rbx+IH_TYPE], TYPE_INODE
    mov qword [rbx+IH_OFF], 0
    mov dword [rbx+IH_DOFF], PAYLOAD_SIZE-64
    mov dword [rbx+IH_DLEN], 64
    lea rdi, [rbx+PAYLOAD_SIZE-64]
    xor esi, esi
    mov edx, 64
    call memset
    mov dword [rbx+PAYLOAD_SIZE-64+INO_MODE], S_IFDIR | 493
    mov dword [rbx+PAYLOAD_SIZE-64+INO_NLINK], 2
    mov eax, [rel fs_uid]
    mov [rbx+PAYLOAD_SIZE-64+INO_UID], eax
    mov eax, [rel fs_gid]
    mov [rbx+PAYLOAD_SIZE-64+INO_GID], eax
    mov qword [rbx+PAYLOAD_SIZE-64+INO_PARENT], ROOT_INO
    call now_ms
    xor edx, edx
    mov rcx, 1000
    div rcx
    mov [rbx+PAYLOAD_SIZE-64+INO_ATIME], rax
    mov [rbx+PAYLOAD_SIZE-64+INO_MTIME], rax
    mov [rbx+PAYLOAD_SIZE-64+INO_CTIME], rax
    lea rdi, [rel node_io]
    call node_write
    EPILOGUE 8

; rdi = path. Full open for read/write of files.
fs_open:
    PROLOGUE 8
    mov rbx, rdi
    call open_super
    test eax, eax
    jnz .ret
    mov eax, [rel fs_flags]
    test eax, FLAG_WIPED
    jnz .wiped
    call kdf_kek
    test eax, eax
    jnz .fail
    call check_verifier
    test eax, eax
    jnz .fail
    mov eax, [rel fs_flags]
    test eax, FLAG_SLEEP
    jnz .sleep
    call unwrap_key
    call bitmap_read
    test eax, eax
    jnz .fail
    mov rax, SYS_getuid
    syscall
    mov [rel fs_op_uid], eax
    mov rax, SYS_getgid
    syscall
    mov [rel fs_op_gid], eax
    mov rdi, [rel fs_root]
    lea rsi, [rel node_io]
    call node_read
    test eax, eax
    jnz .fail
    xor eax, eax
    jmp .ret
.wiped:
    mov rax, -ERR_WIPED
    jmp .fail
.sleep:
    mov rax, -ERR_SLEEP
.fail:
    mov [rsp], eax
    call fs_close
    mov eax, [rsp]
.ret:
    EPILOGUE 8

; Open the image and unpack the superblock. Does not check the passphrase.
open_super:
    PROLOGUE 8
    mov rax, SYS_open
    mov rdi, rbx
    mov rsi, O_RDWR
    xor edx, edx
    syscall
    cmp rax, 0
    jl .syse
    mov [rel fs_fd], rax
    xor edi, edi
    lea rsi, [rel super_buf]
    call block_read
    test eax, eax
    jnz .tryb
    call super_check
    test eax, eax
    jz .un
.tryb:
    mov edi, 1
    lea rsi, [rel super_buf]
    call block_read
    test eax, eax
    jnz .ret
    call super_check
    test eax, eax
    jnz .ret
.un:
    call super_unpack
    xor eax, eax
    jmp .ret
.syse:
    cmp rax, -4096
    ja .keep
    mov rax, -EIO
    jmp .ret
.keep:
    ; rax is already -errno
.ret:
    EPILOGUE 8

fs_close:
    PROLOGUE 8
    mov rax, [rel fs_fd]
    test rax, rax
    jle .z
    mov rdi, rax
    mov rax, SYS_close
    syscall
.z:
    mov qword [rel fs_fd], 0
    lea rdi, [rel fs_key]
    xor esi, esi
    mov edx, 32*4
    call memset
    xor eax, eax
    EPILOGUE 8

; rdi = path
fs_sleep:
    PROLOGUE 8
    mov rbx, rdi
    call open_super
    test eax, eax
    jnz .done
    mov eax, [rel fs_flags]
    test eax, FLAG_WIPED
    jnz .wiped
    call kdf_kek
    call check_verifier
    test eax, eax
    jnz .done
    mov eax, [rel fs_flags]
    test eax, FLAG_SLEEP
    jnz .already
    ; seal root || wrapped || magic
    lea rdi, [rel node_io]
    xor esi, esi
    mov edx, 48
    call memset
    mov rax, [rel fs_root]
    mov [rel node_io], rax
    lea rdi, [rel node_io+8]
    lea rsi, [rel fs_wrapped]
    mov edx, 32
    call memcpy
    lea rdi, [rel node_io+40]
    lea rsi, [rel sleep_magic]
    mov edx, 8
    call memcpy
    lea rdi, [rel wrap_key_buf]
    lea rsi, [rel fs_kek]
    call derive_sleep_key
    lea rbx, [rel nonce_tmp]
    lea rdi, [rbx]
    lea rsi, [rel fs_salt]
    mov edx, 12
    call memcpy
    lea rdi, [rel fs_sleep_blob]
    lea rsi, [rel node_io]
    mov edx, 48
    lea rcx, [rel wrap_key_buf]
    mov r8, rbx
    xor r9d, r9d
    call chacha20_xor
    lea rdi, [rel fs_wrapped]
    xor esi, esi
    mov edx, 32
    call memset
    mov qword [rel fs_root], 0
    or dword [rel fs_flags], FLAG_SLEEP
    call super_store
    jmp .done
.already:
    xor eax, eax
    jmp .done
.wiped:
    mov rax, -ERR_WIPED
.done:
    mov [rsp], eax
    call fs_close
    mov eax, [rsp]
    EPILOGUE 8

fs_wake:
    PROLOGUE 8
    mov rbx, rdi
    call open_super
    test eax, eax
    jnz .done
    mov eax, [rel fs_flags]
    test eax, FLAG_WIPED
    jnz .wiped
    call kdf_kek
    call check_verifier
    test eax, eax
    jnz .done
    mov eax, [rel fs_flags]
    test eax, FLAG_SLEEP
    jz .already
    lea rdi, [rel wrap_key_buf]
    lea rsi, [rel fs_kek]
    call derive_sleep_key
    lea rbx, [rel nonce_tmp]
    lea rdi, [rbx]
    lea rsi, [rel fs_salt]
    mov edx, 12
    call memcpy
    lea rdi, [rel node_io]
    lea rsi, [rel fs_sleep_blob]
    mov edx, 48
    lea rcx, [rel wrap_key_buf]
    mov r8, rbx
    xor r9d, r9d
    call chacha20_xor
    lea rdi, [rel node_io+40]
    lea rsi, [rel sleep_magic]
    mov edx, 8
    call memcmp
    test eax, eax
    jnz .io
    mov rax, [rel node_io]
    mov [rel fs_root], rax
    lea rdi, [rel fs_wrapped]
    lea rsi, [rel node_io+8]
    mov edx, 32
    call memcpy
    lea rdi, [rel fs_sleep_blob]
    xor esi, esi
    mov edx, 64
    call memset
    mov eax, [rel fs_flags]
    and eax, 0xfffffffe
    mov [rel fs_flags], eax
    call super_store
    jmp .done
.already:
    xor eax, eax
    jmp .done
.wiped:
    mov rax, -ERR_WIPED
    jmp .done
.io:
    mov rax, -EIO
.done:
    mov [rsp], eax
    call fs_close
    mov eax, [rsp]
    EPILOGUE 8

; Open for sleep/wipe administration. If the image is sealed, unseal in memory
; only (the on-disk SLEEP flag is left as it is). Leaves the fd open.
global fs_prepare_admin
fs_prepare_admin:
    PROLOGUE 8
    mov rbx, rdi
    call open_super
    test eax, eax
    jnz .ret
    mov eax, [rel fs_flags]
    test eax, FLAG_WIPED
    jnz .wiped
    call kdf_kek
    test eax, eax
    jnz .fail
    call check_verifier
    test eax, eax
    jnz .fail
    mov eax, [rel fs_flags]
    test eax, FLAG_SLEEP
    jz .unwrap
    lea rdi, [rel wrap_key_buf]
    lea rsi, [rel fs_kek]
    call derive_sleep_key
    lea rbx, [rel nonce_tmp]
    mov rdi, rbx
    lea rsi, [rel fs_salt]
    mov edx, 12
    call memcpy
    lea rdi, [rel node_io]
    lea rsi, [rel fs_sleep_blob]
    mov edx, 48
    lea rcx, [rel wrap_key_buf]
    mov r8, rbx
    xor r9d, r9d
    call chacha20_xor
    lea rdi, [rel node_io+40]
    lea rsi, [rel sleep_magic]
    mov edx, 8
    call memcmp
    test eax, eax
    jnz .io
    mov rax, [rel node_io]
    mov [rel fs_root], rax
    lea rdi, [rel fs_wrapped]
    lea rsi, [rel node_io+8]
    mov edx, 32
    call memcpy
.unwrap:
    call unwrap_key
    xor eax, eax
    jmp .ret
.wiped:
    mov rax, -ERR_WIPED
    jmp .fail
.io:
    mov rax, -EIO
.fail:
    mov [rsp], eax
    call fs_close
    mov eax, [rsp]
.ret:
    EPILOGUE 8
