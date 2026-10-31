%include "sys.inc"

extern memcpy, memset, memcmp, crc32c, now_ms, pipeline_apply, strlen
extern block_read, block_write, alloc_block, free_block, bitmap_write, super_store
extern btree_get, btree_insert, btree_update, btree_delete, tree_walk
extern fs_prepare_admin, fs_close, fill_random
extern fs_next_inode, fs_write_seq, fs_op_uid, fs_op_gid, fs_data_key
extern fs_flags, fs_root, node_io
extern fs_salt, fs_wrapped, fs_verifier, fs_sleep_blob, fs_key, dbg_b

section .bss
global ino_buf
ino_buf:        resb 64
global dbg_q
dbg_q:          resq 1
dir_buf:        resb 512
ext_buf:        resb 32
plain_blk:      resb BLOCK_SIZE
cipher_blk:     resb BLOCK_SIZE
cparam:         resb 80
scan_dir:       resq 1
scan_name:      resq 1
scan_nlen:      resq 1
scan_found:     resb 1
scan_ino:       resq 1
scan_off:       resq 1
scan_dtype:     resb 1
ext_off:        resq 256
ext_disk:       resq 256
ext_n:          resq 1
meta_bn:        resq 2048
meta_n:         resq 1
new_extents:    resq 1

section .data
global fs_stage
fs_stage: db 0

section .text
global fs_lookup, fs_create, fs_mkdir, fs_unlink, fs_rmdir
global fs_read, fs_write, fs_truncate, fs_rename, fs_read_inode
global fs_wipe, fs_readdir_step

; rdi name, rsi len -> rax hash
name_hash:
    mov rax, 0xcbf29ce484222325
    test rsi, rsi
    jz .d
.l:
    movzx rdx, byte [rdi]
    xor rax, rdx
    mov rdx, 0x100000001b3
    mul rdx
    inc rdi
    dec rsi
    jnz .l
.d:
    ret

; rdi ino, rsi dst -> 0 or -errno. Copies 64-byte inode.
fs_read_inode:
    PROLOGUE 8
    mov rcx, rsi
    mov rdx, 0
    mov rsi, TYPE_INODE
    mov r8, 64
    call btree_get
    mov [rel dbg_q], rax
    cmp rax, 64
    je .ok
    test rax, rax
    js .neg
    mov [rel fs_stage], al
    mov rax, -EIO
    jmp .ret
.neg:
    mov byte [rel fs_stage], 'N'
    jmp .ret
.ok:
    xor eax, eax
.ret:
    EPILOGUE 8

; reload inode ino_buf. rdi = ino
load_ino:
    lea rsi, [rel ino_buf]
    jmp fs_read_inode

global save_ino
save_ino:
    ; rdi = ino
    PROLOGUE 8
    mov rdx, 0
    mov rsi, TYPE_INODE
    lea rcx, [rel ino_buf]
    mov r8, 64
    call btree_update
    EPILOGUE 8

; '.' / '..' helpers. rdi name, rsi len, rdx dir ino. rax = ino or 0 if not special.
lookup_special:
    cmp rsi, 1
    jne .dotdot
    cmp byte [rdi], '.'
    jne .no
    mov rax, rdx
    ret
.dotdot:
    cmp rsi, 2
    jne .no
    cmp byte [rdi], '.'
    jne .no
    cmp byte [rdi+1], '.'
    jne .no
    push rdx
    mov rdi, rdx
    call load_ino
    test eax, eax
    jnz .bad
    lea r11, [rel ino_buf]
    mov rax, [r11+INO_PARENT]
    pop rdx
    ret
.bad:
    pop rdx
    mov rax, -EIO
    ret
.no:
    xor eax, eax
    ret

dir_on_node:
    PROLOGUE 8
    mov rbx, rdi
    cmp byte [rbx+NH_LEVEL], 0
    jne .d
    movzx r12, word [rbx+NH_NITEMS]
    xor r13, r13
.l:
    cmp r13, r12
    jae .d
    mov rax, r13
    shl rax, 5
    lea r14, [rbx+PAYLOAD_OFF]
    add r14, rax
    cmp byte [r14+IH_TYPE], TYPE_DIR
    jne .n
    mov rax, [r14+IH_OBJ]
    cmp rax, [rel scan_dir]
    jne .n
    mov eax, [r14+IH_DOFF]
    lea r15, [rbx+PAYLOAD_OFF]
    add r15, rax
    movzx eax, byte [r15+DIR_NAMELEN]
    cmp rax, [rel scan_nlen]
    jne .n
    lea rdi, [r15+DIR_NAME]
    mov rsi, [rel scan_name]
    mov rdx, rax
    call memcmp
    test eax, eax
    jnz .n
    mov rax, [r15+DIR_INO]
    mov [rel scan_ino], rax
    mov rax, [r14+IH_OFF]
    mov [rel scan_off], rax
    mov al, [r15+DIR_DTYPE]
    mov [rel scan_dtype], al
    mov byte [rel scan_found], 1
    jmp .d
.n:
    inc r13
    jmp .l
.d:
    xor eax, eax
    EPILOGUE 8

; rdi dir, rsi name, rdx len -> rax ino or -errno
fs_lookup:
    PROLOGUE 8
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    mov rdi, r12
    mov rsi, r13
    mov rdx, rbx
    call lookup_special
    test rax, rax
    jnz .ret
    mov [rel scan_dir], rbx
    mov [rel scan_name], r12
    mov [rel scan_nlen], r13
    mov byte [rel scan_found], 0
    lea rdi, [rel dir_on_node]
    xor esi, esi
    call tree_walk
    test eax, eax
    jnz .ret
    cmp byte [rel scan_found], 0
    je .no
    mov rax, [rel scan_ino]
    jmp .ret
.no:
    mov rax, -ENOENT
.ret:
    EPILOGUE 8

; Find a free directory key offset for this name. rdi dir, rsi name, rdx len -> rax off
alloc_dir_off:
    PROLOGUE 8
    mov rbx, rdi
    mov rdi, rsi
    mov rsi, rdx
    call name_hash
    mov r12, rax
    xor r13, r13
.try:
    cmp r13, 64
    jae .nospc
    mov rdi, rbx
    mov rsi, TYPE_DIR
    mov rdx, r12
    lea rcx, [rel dir_buf]
    mov r8, 8
    call btree_get
    cmp rax, 0
    jl .use
    inc r12
    inc r13
    jmp .try
.use:
    cmp eax, -ENOENT
    jne .ret
    mov rax, r12
    jmp .ret
.nospc:
    mov rax, -ENOSPC
.ret:
    EPILOGUE 8

; rdi dir, rsi name, rdx len, rcx mode, r8 dtype (DT_*), r9 is_dir (1/0)
; returns new ino
create_common:
    PROLOGUE 40
    mov [rsp], rdi
    mov [rsp+8], rsi
    mov [rsp+16], rdx
    mov [rsp+24], rcx
    mov [rsp+32], r8
    cmp rdx, 0
    je .inval
    cmp rdx, MAX_NAME
    ja .long
    mov rdi, rsi
    mov rsi, rdx
    mov rdx, [rsp]
    call lookup_special
    test rax, rax
    jnz .inval
    mov rdi, [rsp]
    mov rsi, [rsp+8]
    mov rdx, [rsp+16]
    call fs_lookup
    cmp rax, 0
    jge .exist
    cmp eax, -ENOENT
    jne .aserr
    mov rdi, [rsp]
    call load_ino
    test eax, eax
    jnz .ret
    lea r11, [rel ino_buf]
    mov eax, [r11+INO_MODE]
    and eax, 0xf000
    cmp eax, S_IFDIR
    jne .notdir
    mov rax, [rel fs_next_inode]
    mov rbx, rax
    inc qword [rel fs_next_inode]
    lea rdi, [rel ino_buf]
    xor esi, esi
    mov edx, 64
    call memset
    mov eax, [rsp+24]
    and eax, 0xfff
    cmp qword [rsp+32], DT_DIR
    jne .filemode
    or eax, S_IFDIR
    lea r11, [rel ino_buf]
    mov dword [r11+INO_NLINK], 2
    jmp .modeok
.filemode:
    or eax, S_IFREG
    lea r11, [rel ino_buf]
    mov dword [r11+INO_NLINK], 1
.modeok:
    lea r11, [rel ino_buf]
    mov [r11+INO_MODE], eax
    mov eax, [rel fs_op_uid]
    lea r11, [rel ino_buf]
    mov [r11+INO_UID], eax
    mov eax, [rel fs_op_gid]
    lea r11, [rel ino_buf]
    mov [r11+INO_GID], eax
    mov rax, [rsp]
    lea r11, [rel ino_buf]
    mov [r11+INO_PARENT], rax
    call now_ms
    xor edx, edx
    mov rcx, 1000
    div rcx
    lea r11, [rel ino_buf]
    mov [r11+INO_ATIME], rax
    lea r11, [rel ino_buf]
    mov [r11+INO_MTIME], rax
    lea r11, [rel ino_buf]
    mov [r11+INO_CTIME], rax
    mov rdi, rbx
    mov rsi, TYPE_INODE
    xor edx, edx
    lea rcx, [rel ino_buf]
    mov r8, 64
    call btree_insert
    test eax, eax
    jnz .ret
    ; directory entry
    mov rdi, [rsp]
    mov rsi, [rsp+8]
    mov rdx, [rsp+16]
    call alloc_dir_off
    cmp rax, -4096
    ja .ret
    mov r12, rax
    lea rdi, [rel dir_buf]
    xor esi, esi
    mov edx, 512
    call memset
    lea r11, [rel dir_buf]
    mov [r11+DIR_INO], rbx
    mov rax, [rsp+32]
    lea r11, [rel dir_buf]
    mov [r11+DIR_DTYPE], al
    mov rax, [rsp+16]
    lea r11, [rel dir_buf]
    mov [r11+DIR_NAMELEN], al
    lea r11, [rel dir_buf]
    lea rdi, [r11+DIR_NAME]
    mov rsi, [rsp+8]
    mov rdx, rax
    call memcpy
    mov rdi, [rsp]
    mov rsi, TYPE_DIR
    mov rdx, r12
    lea rcx, [rel dir_buf]
    mov r8, [rsp+16]
    add r8, DIR_NAME
    call btree_insert
    test eax, eax
    jnz .ret
    cmp qword [rsp+32], DT_DIR
    jne .done
    mov rdi, [rsp]
    call load_ino
    test eax, eax
    jnz .ret
    lea r11, [rel ino_buf]
    inc dword [r11+INO_NLINK]
    mov rdi, [rsp]
    call save_ino
    test eax, eax
    jnz .ret
.done:
    mov rax, rbx
    jmp .ret
.exist:
    mov rax, -EEXIST
    jmp .ret
.notdir:
    mov rax, -ENOTDIR
    jmp .ret
.inval:
    mov rax, -EINVAL
    jmp .ret
.long:
    mov rax, -ENAMETOOLONG
    jmp .ret
.aserr:
    ; rax already negative
.ret:
    EPILOGUE 40

fs_create:
    PROLOGUE 8
    mov r8, DT_REG
    call create_common
    EPILOGUE 8

fs_mkdir:
    PROLOGUE 8
    mov r8, DT_DIR
    call create_common
    EPILOGUE 8

ext_on_node:
    PROLOGUE 8
    mov rbx, rdi
    cmp byte [rbx+NH_LEVEL], 0
    jne .d
    movzx r12, word [rbx+NH_NITEMS]
    xor r13, r13
.l:
    cmp r13, r12
    jae .d
    mov rax, r13
    shl rax, 5
    lea r14, [rbx+PAYLOAD_OFF]
    add r14, rax
    cmp byte [r14+IH_TYPE], TYPE_EXTENT
    jne .n
    mov rax, [r14+IH_OBJ]
    cmp rax, [rel scan_dir]
    jne .n
    mov rcx, [rel ext_n]
    cmp rcx, 256
    jae .d
    mov rax, [r14+IH_OFF]
    lea r11, [rel ext_off]
    mov [r11+rcx*8], rax
    mov eax, [r14+IH_DOFF]
    lea rdx, [rbx+PAYLOAD_OFF]
    mov rax, [rdx+rax+EXT_DISK]
    lea r11, [rel ext_disk]
    mov [r11+rcx*8], rax
    inc qword [rel ext_n]
.n:
    inc r13
    jmp .l
.d:
    xor eax, eax
    EPILOGUE 8

; rdi ino. Fills ext_off/ext_disk/ext_n
collect_extents:
    PROLOGUE 8
    mov [rel scan_dir], rdi
    mov qword [rel ext_n], 0
    lea rdi, [rel ext_on_node]
    xor esi, esi
    call tree_walk
    EPILOGUE 8

; rdi dir, rsi name, rdx len. Deletes a non-directory.
fs_unlink:
    PROLOGUE 8
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    mov rdi, rbx
    mov rsi, r12
    mov rdx, r13
    call fs_lookup
    cmp rax, 0
    jl .ret
    mov r14, rax
    mov rdi, r14
    call load_ino
    test eax, eax
    jnz .ret
    lea r11, [rel ino_buf]
    mov eax, [r11+INO_MODE]
    and eax, 0xf000
    cmp eax, S_IFDIR
    je .isdir
    mov rdi, r14
    call collect_extents
    test eax, eax
    jnz .ret
    xor r15, r15
.fe:
    cmp r15, [rel ext_n]
    jae .di
    lea r11, [rel ext_disk]
    mov rdi, [r11+r15*8]
    call free_block
    mov rdi, r14
    mov rsi, TYPE_EXTENT
    lea r11, [rel ext_off]
    mov rdx, [r11+r15*8]
    call btree_delete
    test eax, eax
    jnz .ret
    inc r15
    jmp .fe
.di:
    mov rdi, r14
    mov rsi, TYPE_INODE
    xor edx, edx
    call btree_delete
    test eax, eax
    jnz .ret
    ; delete the directory entry: rescan for its key
    mov [rel scan_dir], rbx
    mov [rel scan_name], r12
    mov [rel scan_nlen], r13
    mov byte [rel scan_found], 0
    lea rdi, [rel dir_on_node]
    xor esi, esi
    call tree_walk
    cmp byte [rel scan_found], 0
    je .ok
    mov rdi, rbx
    mov rsi, TYPE_DIR
    mov rdx, [rel scan_off]
    call btree_delete
    jmp .ret
.isdir:
    mov rax, -EISDIR
    jmp .ret
.ok:
    xor eax, eax
.ret:
    EPILOGUE 8

fs_rmdir:
    PROLOGUE 8
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    mov rdi, rbx
    mov rsi, r12
    mov rdx, r13
    call fs_lookup
    cmp rax, 0
    jl .ret
    mov r14, rax
    cmp r14, ROOT_INO
    je .inval
    mov rdi, r14
    call load_ino
    test eax, eax
    jnz .ret
    lea r11, [rel ino_buf]
    mov eax, [r11+INO_MODE]
    and eax, 0xf000
    cmp eax, S_IFDIR
    jne .notdir
    ; empty?
    mov [rel scan_dir], r14
    mov qword [rel scan_name], 0
    mov qword [rel scan_nlen], -1
    mov byte [rel scan_found], 0
    lea rdi, [rel dir_any]
    xor esi, esi
    call tree_walk
    cmp byte [rel scan_found], 0
    jne .full
    mov rdi, r14
    mov rsi, TYPE_INODE
    xor edx, edx
    call btree_delete
    test eax, eax
    jnz .ret
    mov [rel scan_dir], rbx
    mov [rel scan_name], r12
    mov [rel scan_nlen], r13
    mov byte [rel scan_found], 0
    lea rdi, [rel dir_on_node]
    xor esi, esi
    call tree_walk
    cmp byte [rel scan_found], 0
    je .pn
    mov rdi, rbx
    mov rsi, TYPE_DIR
    mov rdx, [rel scan_off]
    call btree_delete
    test eax, eax
    jnz .ret
.pn:
    mov rdi, rbx
    call load_ino
    test eax, eax
    jnz .ret
    lea r11, [rel ino_buf]
    cmp dword [r11+INO_NLINK], 2
    jbe .skipn
    lea r11, [rel ino_buf]
    dec dword [r11+INO_NLINK]
.skipn:
    mov rdi, rbx
    call save_ino
    jmp .ret
.full:
    mov rax, -ENOTEMPTY
    jmp .ret
.notdir:
    mov rax, -ENOTDIR
    jmp .ret
.inval:
    mov rax, -EINVAL
.ret:
    EPILOGUE 8

; Any dirent inside scan_dir sets scan_found.
dir_any:
    mov rbx, rdi
    cmp byte [rbx+NH_LEVEL], 0
    jne .d
    movzx rcx, word [rbx+NH_NITEMS]
    xor rdx, rdx
.l:
    cmp rdx, rcx
    jae .d
    mov rax, rdx
    shl rax, 5
    lea r8, [rbx+PAYLOAD_OFF]
    add r8, rax
    cmp byte [r8+IH_TYPE], TYPE_DIR
    jne .n
    mov rax, [r8+IH_OBJ]
    cmp rax, [rel scan_dir]
    jne .n
    mov byte [rel scan_found], 1
    jmp .d
.n:
    inc rdx
    jmp .l
.d:
    xor eax, eax
    ret

; Apply the data pipeline. rdi dst, rsi src, rdx len, rcx ts, r8 gen, r9 off,
; stack: inode, decrypt flag. Uses cparam.
apply_data:
    PROLOGUE 8
    mov rax, [rsp+16]          ; return address then inode? 
    ; The extra args are placed by the caller in [cparam] instead. This
    ; function reads cparam fields that the caller already filled except
    ; dst/src/len/ts/gen/off/dec which we set here.
    lea r11, [rel cparam]
    mov [r11+PP_DST], rdi
    lea r11, [rel cparam]
    mov [r11+PP_SRC], rsi
    lea r11, [rel cparam]
    mov [r11+PP_LEN], rdx
    lea r11, [rel cparam]
    mov [r11+PP_TS], rcx
    lea r11, [rel cparam]
    mov [r11+PP_GEN], r8
    lea r11, [rel cparam]
    mov [r11+PP_OFF], r9
    lea rax, [rel fs_data_key]
    lea r11, [rel cparam]
    mov [r11+PP_KEY], rax
    lea rdi, [rel cparam]
    call pipeline_apply
    EPILOGUE 8

; rdi ino, rsi offset, rdx buf, rcx len -> bytes or -errno
fs_read:
    PROLOGUE 40
    mov [rsp], rdi
    mov [rsp+8], rsi
    mov [rsp+16], rdx
    mov [rsp+24], rcx
    mov qword [rsp+32], 0      ; copied
    mov rdi, [rsp]
    call load_ino
    test eax, eax
    jnz .ret
    lea r11, [rel ino_buf]
    mov eax, [r11+INO_MODE]
    and eax, 0xf000
    cmp eax, S_IFDIR
    je .isdir
    lea r11, [rel ino_buf]
    mov rax, [r11+INO_SIZE]
    cmp [rsp+8], rax
    jae .zero
    mov rcx, [rsp+24]
    mov rdx, [rsp+8]
    add rdx, rcx
    jc .big
    cmp rdx, rax
    jbe .lenok
    sub rax, [rsp+8]
    mov [rsp+24], rax
.lenok:
.loop:
    cmp qword [rsp+24], 0
    je .done
    mov rax, [rsp+8]
    and rax, ~4095
    mov r12, rax               ; block off
    mov rax, [rsp+8]
    and rax, 4095
    mov r13, rax               ; inner
    mov r14, 4096
    sub r14, r13               ; room
    cmp r14, [rsp+24]
    jbe .rm
    mov r14, [rsp+24]
.rm:
    lea rdi, [rel plain_blk]
    xor esi, esi
    mov edx, BLOCK_SIZE
    call memset
    mov rdi, [rsp]
    mov rsi, TYPE_EXTENT
    mov rdx, r12
    lea rcx, [rel ext_buf]
    mov r8, EXT_BYTES
    call btree_get
    cmp rax, EXT_BYTES
    je .have
    cmp eax, -ENOENT
    je .copyz
    test rax, rax
    js .aserr
    mov rax, -EIO
    jmp .ret
.have:
    lea r11, [rel ext_buf]
    mov rdi, [r11+EXT_DISK]
    lea rsi, [rel cipher_blk]
    call block_read
    test eax, eax
    jnz .ret
    lea r11, [rel cparam]
    mov qword [r11+PP_DEC], 1
    lea r11, [rel cparam]
    mov qword [r11+PP_INO], 0
    mov rax, [rsp]
    lea r11, [rel cparam]
    mov [r11+PP_INO], rax
    lea rdi, [rel plain_blk]
    lea rsi, [rel cipher_blk]
    mov rdx, BLOCK_SIZE
    lea r11, [rel ext_buf]
    mov rcx, [r11+EXT_TIME]
    lea r11, [rel ext_buf]
    mov r8, [r11+EXT_GEN]
    mov r9, r12
    call apply_data
    test eax, eax
    jnz .ret
    lea rdi, [rel plain_blk]
    mov esi, BLOCK_SIZE
    call crc32c
    lea r11, [rel ext_buf]
    cmp eax, [r11+EXT_CRC]
    jne .io
.copyz:
    mov rdi, [rsp+16]
    lea rsi, [rel plain_blk]
    add rsi, r13
    mov rdx, r14
    call memcpy
    add [rsp+16], r14
    add [rsp+8], r14
    sub [rsp+24], r14
    add [rsp+32], r14
    jmp .loop
.done:
    mov rax, [rsp+32]
    jmp .ret
.zero:
    xor eax, eax
    jmp .ret
.isdir:
    mov rax, -EISDIR
    jmp .ret
.io:
    mov rax, -EIO
    jmp .ret
.big:
    mov rax, -EINVAL
    jmp .ret
.aserr:
.ret:
    EPILOGUE 40

; rdi ino, rsi off, rdx buf, rcx len
fs_write:
    PROLOGUE 40
    mov [rsp], rdi
    mov [rsp+8], rsi
    mov [rsp+16], rdx
    mov [rsp+24], rcx
    mov qword [rsp+32], 0
    cmp rcx, 0
    je .zero
    mov rdi, [rsp]
    call load_ino
    mov [rel dbg_b], rax
    test eax, eax
    jnz .ret
    lea r11, [rel ino_buf]
    mov eax, [r11+INO_MODE]
    and eax, 0xf000
    cmp eax, S_IFDIR
    je .isdir
    mov qword [rel new_extents], 0
    mov byte [rel fs_stage], 'L'
.loop:
    cmp qword [rsp+24], 0
    je .meta
    mov rax, [rsp+8]
    and rax, ~4095
    mov r12, rax
    mov rax, [rsp+8]
    and rax, 4095
    mov r13, rax
    mov r14, 4096
    sub r14, r13
    cmp r14, [rsp+24]
    jbe .rm
    mov r14, [rsp+24]
.rm:
    lea rdi, [rel plain_blk]
    xor esi, esi
    mov edx, BLOCK_SIZE
    call memset
    mov rdi, [rsp]
    mov rsi, TYPE_EXTENT
    mov rdx, r12
    lea rcx, [rel ext_buf]
    mov r8, EXT_BYTES
    mov byte [rel fs_stage], 'G'
    call btree_get
    mov r15, rax
    cmp rax, EXT_BYTES
    je .have
    cmp eax, -ENOENT
    je .fresh
    test rax, rax
    js .aserr
    mov rax, -EIO
    jmp .ret
.have:
    lea r11, [rel ext_buf]
    mov rdi, [r11+EXT_DISK]
    mov rbx, rdi
    lea rsi, [rel cipher_blk]
    call block_read
    test eax, eax
    jnz .ret
    lea r11, [rel cparam]
    mov qword [r11+PP_DEC], 1
    mov rax, [rsp]
    lea r11, [rel cparam]
    mov [r11+PP_INO], rax
    lea rdi, [rel plain_blk]
    lea rsi, [rel cipher_blk]
    mov rdx, BLOCK_SIZE
    lea r11, [rel ext_buf]
    mov rcx, [r11+EXT_TIME]
    lea r11, [rel ext_buf]
    mov r8, [r11+EXT_GEN]
    mov r9, r12
    mov byte [rel fs_stage], 'D'
    call apply_data
    test eax, eax
    jnz .ret
    jmp .merge
.fresh:
    xor ebx, ebx
.merge:
    lea rdi, [rel plain_blk]
    add rdi, r13
    mov rsi, [rsp+16]
    mov rdx, r14
    call memcpy
    call now_ms
    mov r13, rax               ; timestamp (inner no longer needed)
    inc qword [rel fs_write_seq]
    mov rax, [rel fs_write_seq]
    lea r11, [rel ext_buf]
    mov [r11+EXT_GEN], rax
    lea r11, [rel ext_buf]
    mov [r11+EXT_TIME], r13
    xor edx, edx
    xor edx, edx
    mov rax, r13
    mov ecx, 10
    div rcx
    lea r11, [rel ext_buf]
    mov [r11+EXT_METHOD], dl
    lea r11, [rel ext_buf]
    mov word [r11+EXT_PLEN], 4096
    lea r11, [rel cparam]
    mov qword [r11+PP_DEC], 0
    mov rax, [rsp]
    lea r11, [rel cparam]
    mov [r11+PP_INO], rax
    lea rdi, [rel cipher_blk]
    lea rsi, [rel plain_blk]
    mov rdx, BLOCK_SIZE
    mov rcx, r13
    lea r11, [rel ext_buf]
    mov r8, [r11+EXT_GEN]
    mov r9, r12
    mov byte [rel fs_stage], 'E'
    call apply_data
    test eax, eax
    jnz .ret
    lea rdi, [rel plain_blk]
    mov esi, BLOCK_SIZE
    call crc32c
    lea r11, [rel ext_buf]
    mov [r11+EXT_CRC], eax
    mov byte [rel fs_stage], 'A'
    call alloc_block
    test rax, rax
    jz .nospc
    lea r11, [rel ext_buf]
    mov [r11+EXT_DISK], rax
    mov byte [rel fs_stage], 'W'
    mov rdi, rax
    lea rsi, [rel cipher_blk]
    call block_write
    test eax, eax
    jnz .reldata
    cmp r15, EXT_BYTES
    je .upd
    mov rdi, [rsp]
    mov rsi, TYPE_EXTENT
    mov rdx, r12
    lea rcx, [rel ext_buf]
    mov byte [rel fs_stage], 'I'
    mov r8, EXT_BYTES
    call btree_insert
    test eax, eax
    jnz .reldata
    inc qword [rel new_extents]
    jmp .adv
.upd:
    mov rdi, [rsp]
    mov rsi, TYPE_EXTENT
    mov rdx, r12
    lea rcx, [rel ext_buf]
    mov r8, EXT_BYTES
    call btree_update
    test eax, eax
    jnz .reldata
    test rbx, rbx
    jz .adv
    mov rdi, rbx
    call free_block
    call bitmap_write
    call super_store
.adv:
    mov rax, 4096
    ; r14 is the chunk size but we overwrote r13. chunk is still... 
    ; BUG: r14 still holds chunk. Good.
    add [rsp+16], r14
    add [rsp+8], r14
    sub [rsp+24], r14
    add [rsp+32], r14
    jmp .loop
.meta:
    mov rdi, [rsp]
    call load_ino
    test eax, eax
    jnz .ret
    mov rax, [rsp+8]           ; offset now at end
    lea r11, [rel ino_buf]
    cmp rax, [r11+INO_SIZE]
    jbe .szok
    lea r11, [rel ino_buf]
    mov [r11+INO_SIZE], rax
.szok:
    mov rax, [rel new_extents]
    lea r11, [rel ino_buf]
    add [r11+INO_BLOCKS], rax
    call now_ms
    xor edx, edx
    mov rcx, 1000
    div rcx
    lea r11, [rel ino_buf]
    mov [r11+INO_MTIME], rax
    lea r11, [rel ino_buf]
    mov [r11+INO_CTIME], rax
    mov rdi, [rsp]
    call save_ino
    test eax, eax
    jnz .ret
    mov rax, [rsp+32]
    jmp .ret
.reldata:
    mov ebx, eax
    lea r11, [rel ext_buf]
    mov rdi, [r11+EXT_DISK]
    call free_block
    mov eax, ebx
    jmp .ret
.nospc:
    mov rax, -ENOSPC
    jmp .ret
.isdir:
    mov rax, -EISDIR
    jmp .ret
.zero:
    xor eax, eax
    jmp .ret
.aserr:
.ret:
    EPILOGUE 40

; The `mov rdi, plain_blk` above is missing rel. Fixed below if assemble fails.

fs_truncate:
    PROLOGUE 24
    mov [rsp], rdi
    mov [rsp+8], rsi
    mov rdi, [rsp]
    call load_ino
    test eax, eax
    jnz .ret
    lea r11, [rel ino_buf]
    mov rax, [r11+INO_SIZE]
    cmp rax, [rsp+8]
    je .ok
    jb .grow
    mov rdi, [rsp]
    call collect_extents
    test eax, eax
    jnz .ret
    mov rax, [rsp+8]
    and rax, ~4095
    mov r12, rax               ; partial block, or the cut if aligned
    mov rax, [rsp+8]
    and rax, 4095
    mov r13, rax               ; inner, 0 if aligned
    xor r14, r14
.l:
    cmp r14, [rel ext_n]
    jae .tail
    lea r11, [rel ext_off]
    mov rax, [r11+r14*8]
    cmp r13, 0
    jne .part
    cmp rax, [rsp+8]
    jb .keep
    jmp .drop
.part:
    cmp rax, r12
    jb .keep
    cmp rax, r12
    jne .drop
    ; rewrite this block with the tail zeroed — handled after the loop
    jmp .keep
.drop:
    lea r11, [rel ext_disk]
    mov rdi, [r11+r14*8]
    call free_block
    mov rdi, [rsp]
    mov rsi, TYPE_EXTENT
    lea r11, [rel ext_off]
    mov rdx, [r11+r14*8]
    call btree_delete
    test eax, eax
    jnz .ret
    lea r11, [rel ino_buf]
    dec qword [r11+INO_BLOCKS]
.keep:
    inc r14
    jmp .l
.tail:
    test r13, r13
    jz .setsz
    ; zero the partial tail if the block exists
    mov rdi, [rsp]
    mov rsi, TYPE_EXTENT
    mov rdx, r12
    lea rcx, [rel ext_buf]
    mov r8, EXT_BYTES
    call btree_get
    cmp rax, EXT_BYTES
    jne .setsz
    lea r11, [rel ext_buf]
    mov rdi, [r11+EXT_DISK]
    lea rsi, [rel cipher_blk]
    call block_read
    test eax, eax
    jnz .ret
    lea r11, [rel cparam]
    mov qword [r11+PP_DEC], 1
    mov rax, [rsp]
    lea r11, [rel cparam]
    mov [r11+PP_INO], rax
    lea rdi, [rel plain_blk]
    lea rsi, [rel cipher_blk]
    mov rdx, BLOCK_SIZE
    lea r11, [rel ext_buf]
    mov rcx, [r11+EXT_TIME]
    lea r11, [rel ext_buf]
    mov r8, [r11+EXT_GEN]
    mov r9, r12
    call apply_data
    lea rdi, [rel plain_blk]
    add rdi, r13
    mov rcx, 4096
    sub rcx, r13
    xor al, al
.z:
    mov [rdi], al
    inc rdi
    dec rcx
    jnz .z
    call now_ms
    mov rbx, rax
    inc qword [rel fs_write_seq]
    mov rax, [rel fs_write_seq]
    lea r11, [rel ext_buf]
    mov [r11+EXT_GEN], rax
    lea r11, [rel ext_buf]
    mov [r11+EXT_TIME], rbx
    xor edx, edx
    mov rax, rbx
    mov ecx, 10
    div rcx
    lea r11, [rel ext_buf]
    mov [r11+EXT_METHOD], dl
    lea r11, [rel cparam]
    mov qword [r11+PP_DEC], 0
    mov rax, [rsp]
    lea r11, [rel cparam]
    mov [r11+PP_INO], rax
    lea rdi, [rel cipher_blk]
    lea rsi, [rel plain_blk]
    mov rdx, BLOCK_SIZE
    mov rcx, rbx
    lea r11, [rel ext_buf]
    mov r8, [r11+EXT_GEN]
    mov r9, r12
    call apply_data
    lea rdi, [rel plain_blk]
    mov esi, BLOCK_SIZE
    call crc32c
    lea r11, [rel ext_buf]
    mov [r11+EXT_CRC], eax
    call alloc_block
    test rax, rax
    jz .nospc
    lea r11, [rel ext_buf]
    mov rbx, [r11+EXT_DISK]
    lea r11, [rel ext_buf]
    mov [r11+EXT_DISK], rax
    mov rdi, rax
    lea rsi, [rel cipher_blk]
    call block_write
    mov rdi, [rsp]
    mov rsi, TYPE_EXTENT
    mov rdx, r12
    lea rcx, [rel ext_buf]
    mov r8, EXT_BYTES
    call btree_update
    test eax, eax
    jnz .ret
    mov rdi, rbx
    call free_block
    call bitmap_write
    call super_store
.setsz:
    mov rax, [rsp+8]
    lea r11, [rel ino_buf]
    mov [r11+INO_SIZE], rax
    mov rdi, [rsp]
    call save_ino
    jmp .ret
.grow:
    mov rax, [rsp+8]
    lea r11, [rel ino_buf]
    mov [r11+INO_SIZE], rax
    mov rdi, [rsp]
    call save_ino
    jmp .ret
.nospc:
    mov rax, -ENOSPC
    jmp .ret
.ok:
    xor eax, eax
.ret:
    EPILOGUE 24

; Minimal rename: same-directory or cross-directory, no replace of non-empty dirs.
; rdi olddir, rsi oldname, rdx oldlen, rcx newdir, r8 newname, r9 newlen
fs_rename:
    PROLOGUE 40
    mov [rsp], rdi
    mov [rsp+8], rsi
    mov [rsp+16], rdx
    mov [rsp+24], rcx
    mov [rsp+32], r8
    mov r15, r9
    mov rdi, [rsp]
    mov rsi, [rsp+8]
    mov rdx, [rsp+16]
    call fs_lookup
    cmp rax, 0
    jl .ret
    mov rbx, rax
    mov rdi, [rsp+24]
    mov rsi, [rsp+32]
    mov rdx, r15
    call fs_lookup
    cmp rax, 0
    jge .exist
    cmp eax, -ENOENT
    jne .aserr
    mov rdi, rbx
    call load_ino
    test eax, eax
    jnz .ret
    lea r11, [rel ino_buf]
    mov eax, [r11+INO_MODE]
    mov [rsp+16], eax          ; reuse, oldlen no longer needed after lookup
    mov rdi, [rsp+24]
    mov rsi, [rsp+32]
    mov rdx, r15
    call alloc_dir_off
    cmp rax, -4096
    ja .ret
    mov r12, rax
    lea rdi, [rel dir_buf]
    xor esi, esi
    mov edx, 512
    call memset
    lea r11, [rel dir_buf]
    mov [r11+DIR_INO], rbx
    mov eax, [rsp+16]
    and eax, 0xf000
    cmp eax, S_IFDIR
    jne .reg
    lea r11, [rel dir_buf]
    mov byte [r11+DIR_DTYPE], DT_DIR
    jmp .dtok
.reg:
    lea r11, [rel dir_buf]
    mov byte [r11+DIR_DTYPE], DT_REG
.dtok:
    mov rax, r15
    lea r11, [rel dir_buf]
    mov [r11+DIR_NAMELEN], al
    lea r11, [rel dir_buf]
    lea rdi, [r11+DIR_NAME]
    mov rsi, [rsp+32]
    mov rdx, r15
    call memcpy
    mov rdi, [rsp+24]
    mov rsi, TYPE_DIR
    mov rdx, r12
    lea rcx, [rel dir_buf]
    mov r8, r15
    add r8, DIR_NAME
    call btree_insert
    test eax, eax
    jnz .ret
    ; remove old name
    mov qword [rel scan_dir], 0
    mov rax, [rsp]
    mov [rel scan_dir], rax
    mov rax, [rsp+8]
    mov [rel scan_name], rax
    ; old length was overwritten. Recover from the name pointer via strlen.
    mov rdi, [rsp+8]
    call strlen
    mov [rel scan_nlen], rax
    mov byte [rel scan_found], 0
    lea rdi, [rel dir_on_node]
    xor esi, esi
    call tree_walk
    cmp byte [rel scan_found], 0
    je .np
    mov rax, [rsp]
    mov rdi, rax
    mov rsi, TYPE_DIR
    mov rdx, [rel scan_off]
    call btree_delete
.np:
    mov eax, [rsp+16]
    and eax, 0xf000
    cmp eax, S_IFDIR
    jne .ok
    mov rax, [rsp+24]
    lea r11, [rel ino_buf]
    mov [r11+INO_PARENT], rax
    mov rdi, rbx
    call save_ino
    ; nlink adjust if parents differ
    mov rax, [rsp]
    cmp rax, [rsp+24]
    je .ok
    mov rdi, [rsp]
    call load_ino
    lea r11, [rel ino_buf]
    dec dword [r11+INO_NLINK]
    mov rdi, [rsp]
    call save_ino
    mov rdi, [rsp+24]
    call load_ino
    lea r11, [rel ino_buf]
    inc dword [r11+INO_NLINK]
    mov rdi, [rsp+24]
    call save_ino
.ok:
    xor eax, eax
    jmp .ret
.exist:
    mov rax, -EEXIST
    jmp .ret
.aserr:
.ret:
    EPILOGUE 40

; Readdir cursor: 0 -> ".", 1 -> "..", then real entries in tree order.
; rdi dir, rsi cookie, rdx buf (name out, max 256), rcx out_ino, r8 out_type
; returns rax = next cookie, or 0 if end. Negative on error.
; *out written only when an entry is produced. rax 0 means end.
fs_readdir_step:
    PROLOGUE 24
    mov [rsp], rdi
    mov [rsp+8], rsi
    mov [rsp+16], rdx
    cmp rsi, 0
    jne .c1
    mov byte [rdx], '.'
    mov byte [rdx+1], 0
    mov rax, [rsp]
    mov [rcx], rax
    mov dword [r8], DT_DIR
    mov eax, 1
    jmp .ret
.c1:
    cmp rsi, 1
    jne .real
    mov r12, rcx
    mov r13, r8
    mov byte [rdx], '.'
    mov byte [rdx+1], '.'
    mov byte [rdx+2], 0
    mov rdi, [rsp]
    call load_ino
    test eax, eax
    jnz .ret
    lea r11, [rel ino_buf]
    mov rax, [r11+INO_PARENT]
    mov [r12], rax
    mov dword [r13], DT_DIR
    mov eax, 2
    jmp .ret
.real:
    mov qword [rel ext_n], 0
    mov [rel scan_dir], rdi
    mov rax, rsi
    sub rax, 2
    mov [rel scan_off], rax       ; skip count
    mov byte [rel scan_found], 0
    mov [rel scan_name], rdx
    mov [rel scan_ino], rcx
    mov [rel meta_bn], r8         ; borrow as out_type ptr
    lea rdi, [rel readdir_on_node]
    xor esi, esi
    call tree_walk
    cmp byte [rel scan_found], 0
    je .end
    mov rax, [rsp+8]
    inc rax
    jmp .ret
.end:
    xor eax, eax
.ret:
    EPILOGUE 24

readdir_on_node:
    PROLOGUE 8
    cmp byte [rel scan_found], 0
    jne .d
    mov rbx, rdi
    cmp byte [rbx+NH_LEVEL], 0
    jne .d
    movzx r12, word [rbx+NH_NITEMS]
    xor r13, r13
.l:
    cmp r13, r12
    jae .d
    cmp byte [rel scan_found], 0
    jne .d
    mov rax, r13
    shl rax, 5
    lea r14, [rbx+PAYLOAD_OFF]
    add r14, rax
    cmp byte [r14+IH_TYPE], TYPE_DIR
    jne .n
    mov rax, [r14+IH_OBJ]
    cmp rax, [rel scan_dir]
    jne .n
    mov rax, [rel scan_off]
    test rax, rax
    jz .take
    dec qword [rel scan_off]
    jmp .n
.take:
    mov eax, [r14+IH_DOFF]
    lea r15, [rbx+PAYLOAD_OFF]
    add r15, rax
    movzx edx, byte [r15+DIR_NAMELEN]
    mov rdi, [rel scan_name]
    lea rsi, [r15+DIR_NAME]
    mov rcx, rdx
    call memcpy
    mov rax, [rel scan_name]
    mov byte [rax+rdx], 0
    mov rax, [r15+DIR_INO]
    mov rcx, [rel scan_ino]
    mov [rcx], rax
    movzx eax, byte [r15+DIR_DTYPE]
    mov rcx, [rel meta_bn]
    mov [rcx], eax
    mov byte [rel scan_found], 1
    jmp .d
.n:
    inc r13
    jmp .l
.d:
    xor eax, eax
    EPILOGUE 8

meta_on_node:
    mov rax, [rel meta_n]
    cmp rax, 2048
    jae .d
    lea r11, [rel meta_bn]
    mov [r11+rax*8], rsi
    inc qword [rel meta_n]
.d:
    xor eax, eax
    ret

; rdi = path
fs_wipe:
    PROLOGUE 8
    call fs_prepare_admin
    test eax, eax
    jnz .ret
    mov qword [rel meta_n], 0
    lea rdi, [rel meta_on_node]
    xor esi, esi
    call tree_walk
    xor rbx, rbx
.ow:
    cmp rbx, [rel meta_n]
    jae .keys
    lea rdi, [rel node_io]
    mov esi, BLOCK_SIZE
    call fill_random
    lea r11, [rel meta_bn]
    mov rdi, [r11+rbx*8]
    lea rsi, [rel node_io]
    call block_write
    inc rbx
    jmp .ow
.keys:
    lea rdi, [rel fs_salt]
    xor esi, esi
    mov edx, 16
    call memset
    lea rdi, [rel fs_wrapped]
    xor esi, esi
    mov edx, 32
    call memset
    lea rdi, [rel fs_verifier]
    xor esi, esi
    mov edx, 32
    call memset
    lea rdi, [rel fs_sleep_blob]
    xor esi, esi
    mov edx, 64
    call memset
    lea rdi, [rel fs_key]
    xor esi, esi
    mov edx, 128
    call memset
    mov qword [rel fs_root], 0
    mov dword [rel fs_flags], FLAG_WIPED
    call super_store
    mov ebx, eax
    call fs_close
    mov eax, ebx
.ret:
    EPILOGUE 8
