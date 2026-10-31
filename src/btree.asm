%include "sys.inc"

; Copy-on-write B-tree. Keys are (objectid, type, offset), BTRFS order.
; Leaf items carry a variable payload. Internal nodes are fixed 40-byte records.
; A leaf split of the root promotes a new internal root. Further splits insert a
; sibling into the parent. If that parent is already full the insert returns
; ENOSPC and rolls the allocation back (fanout is 101; enough for the prototype).

extern node_read, node_write, alloc_block, bit_clear, free_block
extern super_store, bitmap_write
extern fs_root, fs_generation, fs_free
extern memcpy, memset, memmove

IM_OBJ  equ 0
IM_TYPE equ 8
IM_OFF  equ 12
IM_LEN  equ 20
IM_PTR  equ 24
IM_SIZE equ 32

section .bss
path_nodes:     resb MAX_TREE_DEPTH * BLOCK_SIZE
path_bn:        resq MAX_TREE_DEPTH
path_slot:      resq MAX_TREE_DEPTH
path_old:       resq MAX_TREE_DEPTH
path_depth:     resq 1
found_exact:    resb 1
item_meta:      resb MAX_LEAF_ITEMS * IM_SIZE
item_bytes:     resb 16384
item_count:     resq 1
item_used:      resq 1
saved_root:     resq 1
saved_gen:      resq 1
saved_free:     resq 1
cow_new:        resq 16
cow_new_n:      resq 1
split_buf:      resb BLOCK_SIZE
root_buf:       resb BLOCK_SIZE
walk_buf:       resb BLOCK_SIZE
walk_cb:        resq 1
walk_ud:        resq 1
seek_obj:       resq 1
seek_type:      resq 1
seek_off:       resq 1

section .text
global btree_get, btree_insert, btree_update, btree_delete, tree_walk

; rdi index -> rax pointer
path_ptr:
    mov rax, rdi
    shl rax, 12
    lea rdx, [rel path_nodes]
    add rax, rdx
    ret

; Compare (rdi,rsi,rdx) ? (rcx,r8,r9). rax = -1/0/1
key_cmp:
    cmp rdi, rcx
    jb .lt
    ja .gt
    cmp rsi, r8
    jb .lt
    ja .gt
    cmp rdx, r9
    jb .lt
    ja .gt
    xor eax, eax
    ret
.lt:
    mov rax, -1
    ret
.gt:
    mov eax, 1
    ret

; rdi = node. Sets found_exact and returns slot in rax.
leaf_slot:
    PROLOGUE 8
    mov rbx, rdi
    mov byte [rel found_exact], 0
    movzx r12, word [rbx+NH_NITEMS]
    xor r13, r13
.l:
    cmp r13, r12
    jae .end
    mov rax, r13
    shl rax, 5
    lea r14, [rbx+PAYLOAD_OFF]
    add r14, rax
    mov rdi, [rel seek_obj]
    mov rsi, [rel seek_type]
    mov rdx, [rel seek_off]
    mov rcx, [r14+IH_OBJ]
    movzx r8, byte [r14+IH_TYPE]
    mov r9, [r14+IH_OFF]
    call key_cmp
    cmp eax, 0
    je .eq
    jl .end                 ; target < item, insert here
    inc r13
    jmp .l
.eq:
    mov byte [rel found_exact], 1
.end:
    mov rax, r13
    EPILOGUE 8

; rdi = internal node. Greatest slot whose key <= target, or 0.
internal_slot:
    PROLOGUE 8
    mov rbx, rdi
    movzx r12, word [rbx+NH_NITEMS]
    xor r13, r13
    xor r15, r15
    test r12, r12
    jz .d
.l:
    cmp r15, r12
    jae .d
    mov rax, r15
    imul rax, INT_IH
    lea r14, [rbx+PAYLOAD_OFF]
    add r14, rax
    mov rdi, [rel seek_obj]
    mov rsi, [rel seek_type]
    mov rdx, [rel seek_off]
    mov rcx, [r14+II_OBJ]
    movzx r8, byte [r14+II_TYPE]
    mov r9, [r14+II_OFF]
    call key_cmp
    cmp eax, 0
    jl .d
    mov r13, r15
    inc r15
    jmp .l
.d:
    mov rax, r13
    EPILOGUE 8

load_path:
    PROLOGUE 8
    mov rax, [rel fs_root]
    test rax, rax
    jz .io
    xor r15, r15
.loop:
    cmp r15, MAX_TREE_DEPTH
    jae .io
    lea r11, [rel path_bn]
    mov [r11+r15*8], rax
    mov rdi, r15
    call path_ptr
    mov r12, rax
    lea r11, [rel path_bn]
    mov rdi, [r11+r15*8]
    mov rsi, r12
    call node_read
    test eax, eax
    jnz .ret
    cmp byte [r12+NH_LEVEL], 0
    je .leaf
    mov rdi, r12
    call internal_slot
    lea r11, [rel path_slot]
    mov [r11+r15*8], rax
    imul rax, INT_IH
    lea rdx, [r12+PAYLOAD_OFF]
    mov rax, [rdx+rax+II_CHILD]
    inc r15
    jmp .loop
.leaf:
    mov rdi, r12
    call leaf_slot
    lea r11, [rel path_slot]
    mov [r11+r15*8], rax
    inc r15
    mov [rel path_depth], r15
    xor eax, eax
    jmp .ret
.io:
    mov rax, -EIO
.ret:
    EPILOGUE 8

; Extract the leaf in path[depth-1] into item_meta / item_bytes.
extract_leaf:
    PROLOGUE 8
    mov rdi, [rel path_depth]
    dec rdi
    call path_ptr
    mov rbx, rax
    movzx r12, word [rbx+NH_NITEMS]
    mov [rel item_count], r12
    mov qword [rel item_used], 0
    xor r13, r13
.l:
    cmp r13, r12
    jae .d
    mov rax, r13
    shl rax, 5
    lea r14, [rbx+PAYLOAD_OFF]
    add r14, rax
    mov rax, r13
    shl rax, 5
    lea r15, [rel item_meta]
    add r15, rax
    mov rax, [r14+IH_OBJ]
    mov [r15+IM_OBJ], rax
    movzx eax, byte [r14+IH_TYPE]
    mov [r15+IM_TYPE], al
    mov rax, [r14+IH_OFF]
    mov [r15+IM_OFF], rax
    mov eax, [r14+IH_DLEN]
    mov [r15+IM_LEN], eax
    mov eax, [rel item_used]
    mov [r15+IM_PTR], eax
    mov edi, eax
    lea rdi, [rel item_bytes]
    add rdi, rax
    mov eax, [r14+IH_DOFF]
    lea rsi, [rbx+PAYLOAD_OFF]
    add rsi, rax
    mov edx, [r14+IH_DLEN]
    call memcpy
    mov eax, [r15+IM_LEN]
    add [rel item_used], rax
    inc r13
    jmp .l
.d:
    xor eax, eax
    EPILOGUE 8

; rdi slot, rsi data, rdx len, rcx obj, r8 type, r9 off
list_insert:
    PROLOGUE 24
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    mov [rsp], rcx
    mov [rsp+8], r8
    ; r9 saved below — prologue only has 8 bytes. Use item scratch tail.
    mov [rel ins_off], r9
    mov rax, [rel item_count]
    sub rax, rbx
    jbe .nocopy
    mov rdi, rbx
    inc rdi
    shl rdi, 5
    lea rdi, [rel item_meta]
    add rdi, rdi
    ; fix: compute dst and src properly
    jmp .shift
.nocopy:
    jmp .put
.shift:
    mov rax, [rel item_count]
    sub rax, rbx
    shl rax, 5                  ; bytes to move
    mov rdx, rax
    mov rax, rbx
    shl rax, 5
    lea rsi, [rel item_meta]
    add rsi, rax
    lea rdi, [rsi+IM_SIZE]
    call memmove
.put:
    mov rax, rbx
    shl rax, 5
    lea r14, [rel item_meta]
    add r14, rax
    mov rax, [rsp]
    mov [r14+IM_OBJ], rax
    mov rax, [rsp+8]
    mov [r14+IM_TYPE], al
    mov rax, [rel ins_off]
    mov [r14+IM_OFF], rax
    mov [r14+IM_LEN], r13d
    mov eax, [rel item_used]
    mov [r14+IM_PTR], eax
    lea rdi, [rel item_bytes]
    add rdi, rax
    mov rsi, r12
    mov rdx, r13
    call memcpy
    add [rel item_used], r13
    inc qword [rel item_count]
    xor eax, eax
    EPILOGUE 24

; rdi = start index, rsi = count -> rax packed bytes
packed_size:
    mov rax, rsi
    shl rax, 5
    mov rcx, rdi
    mov rdx, rsi
.l:
    test rdx, rdx
    jz .d
    mov r8, rcx
    shl r8, 5
    lea r9, [rel item_meta]
    mov r8d, [r9+r8+IM_LEN]
    add r8, 7
    and r8, ~7
    add rax, r8
    inc rcx
    dec rdx
    jmp .l
.d:
    ret

; Remove meta slot rdi. Data bytes are left orphaned in the arena.
list_remove:
    mov rax, [rel item_count]
    dec rax
    cmp rdi, rax
    jae .last
    mov rcx, rax
    sub rcx, rdi
    shl rcx, 5
    mov rdx, rcx
    mov rax, rdi
    shl rax, 5
    lea rsi, [rel item_meta]
    add rsi, rax
    add rsi, IM_SIZE
    lea rdi, [rel item_meta]
    add rdi, rax
    call memmove
.last:
    dec qword [rel item_count]
    xor eax, eax
    ret

; Write items [start, start+count) into a leaf. Header bytenr/gen/magic preserved
; unless the node was zeroed by the caller (magic must already be set).
; rdi node, rsi start, rdx count
store_leaf:
    PROLOGUE 24
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    lea rdi, [rbx+PAYLOAD_OFF]
    xor esi, esi
    mov edx, PAYLOAD_SIZE
    call memset
    mov eax, PAYLOAD_SIZE
    mov [rsp], eax             ; cursor
    xor r14, r14
.l:
    cmp r14, r13
    jae .hdr
    mov rax, r12
    add rax, r14
    shl rax, 5
    lea r15, [rel item_meta]
    add r15, rax
    mov eax, [r15+IM_LEN]
    mov r8d, eax
    add eax, 7
    and eax, ~7
    mov ecx, [rsp]
    sub ecx, eax
    mov [rsp], ecx
    mov edi, ecx
    lea rdi, [rbx+PAYLOAD_OFF]
    add rdi, rcx
    mov eax, [r15+IM_PTR]
    lea rsi, [rel item_bytes]
    add rsi, rax
    mov edx, r8d
    mov [rsp+4], r8d
    mov [rsp+8], ecx
    call memcpy
    mov rax, r14
    shl rax, 5
    lea rdi, [rbx+PAYLOAD_OFF]
    add rdi, rax
    mov rax, [r15+IM_OBJ]
    mov [rdi+IH_OBJ], rax
    movzx eax, byte [r15+IM_TYPE]
    mov [rdi+IH_TYPE], al
    mov dword [rdi+9], 0
    mov rax, [r15+IM_OFF]
    mov [rdi+IH_OFF], rax
    mov eax, [rsp+8]
    mov [rdi+IH_DOFF], eax
    mov eax, [rsp+4]
    mov [rdi+IH_DLEN], eax
    inc r14
    jmp .l
.hdr:
    mov [rbx+NH_NITEMS], r13w
    mov byte [rbx+NH_LEVEL], 0
    mov byte [rbx+NH_FLAGS], NH_FLAG_ENC
    mov dword [rbx+NH_MAGIC], MAGIC_NODE
    xor eax, eax
    EPILOGUE 24

node_clear:
    ; rdi buf, rsi bn, rdx level
    PROLOGUE 8
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    mov rdi, rbx
    xor esi, esi
    mov edx, BLOCK_SIZE
    call memset
    mov dword [rbx+NH_MAGIC], MAGIC_NODE
    mov [rbx+NH_BYTENR], r12
    mov rax, [rel fs_generation]
    mov [rbx+NH_GEN], rax
    mov [rbx+NH_LEVEL], r13b
    mov byte [rbx+NH_FLAGS], NH_FLAG_ENC
    xor eax, eax
    EPILOGUE 8

rollback:
    PROLOGUE 8
    mov rbx, [rel cow_new_n]
    xor r12, r12
.l:
    cmp r12, rbx
    jae .rest
    lea r11, [rel cow_new]
    mov rdi, [r11+r12*8]
    call bit_clear
    inc r12
    jmp .l
.rest:
    mov rax, [rel saved_free]
    mov [rel fs_free], rax
    mov rax, [rel saved_root]
    mov [rel fs_root], rax
    mov rax, [rel saved_gen]
    mov [rel fs_generation], rax
    mov qword [rel cow_new_n], 0
    xor eax, eax
    EPILOGUE 8

; Allocate a block and remember it for rollback. rax = bn or 0.
alloc_tracked:
    PROLOGUE 8
    call alloc_block
    test rax, rax
    jz .d
    mov rcx, [rel cow_new_n]
    cmp rcx, 16
    jae .full
    lea r11, [rel cow_new]
    mov [r11+rcx*8], rax
    inc qword [rel cow_new_n]
.d:
    EPILOGUE 8
.full:
    ; extremely unlikely; treat as ENOSPC by leaking the bit until process exit
    xor eax, eax
    EPILOGUE 8

cow_path:
    PROLOGUE 8
    mov rax, [rel fs_root]
    mov [rel saved_root], rax
    mov rax, [rel fs_generation]
    mov [rel saved_gen], rax
    mov rax, [rel fs_free]
    mov [rel saved_free], rax
    mov qword [rel cow_new_n], 0
    inc qword [rel fs_generation]
    mov r15, [rel path_depth]
    dec r15
.loop:
    call alloc_tracked
    test rax, rax
    jz .nospc
    mov r12, rax
    lea r11, [rel path_bn]
    mov rax, [r11+r15*8]
    lea r11, [rel path_old]
    mov [r11+r15*8], rax
    lea r11, [rel path_bn]
    mov [r11+r15*8], r12
    mov rdi, r15
    call path_ptr
    mov rbx, rax
    mov [rbx+NH_BYTENR], r12
    mov rax, [rel fs_generation]
    mov [rbx+NH_GEN], rax
    mov rax, r15
    inc rax
    cmp rax, [rel path_depth]
    jae .next
    ; parent: point slot at the child's new bytenr
    mov rdi, r15
    call path_ptr
    mov rbx, rax
    lea r11, [rel path_slot]
    mov rcx, [r11+r15*8]
    imul rcx, INT_IH
    lea rdx, [rbx+PAYLOAD_OFF]
    lea r11, [rel path_bn]
    mov rax, [r11+r15*8+8]
    mov [rdx+rcx+II_CHILD], rax
    mov rax, [rel fs_generation]
    mov [rdx+rcx+II_GEN], rax
.next:
    test r15, r15
    jz .root
    dec r15
    jmp .loop
.root:
    mov rax, [rel path_bn]
    mov [rel fs_root], rax
    xor eax, eax
    EPILOGUE 8
.nospc:
    call rollback
    mov rax, -ENOSPC
    EPILOGUE 8

commit_path:
    PROLOGUE 8
    mov rbx, [rel path_depth]
    xor r12, r12
.w:
    cmp r12, rbx
    jae .sup
    mov rdi, r12
    call path_ptr
    mov rdi, rax
    call node_write
    test eax, eax
    jnz .ret
    inc r12
    jmp .w
.sup:
    call super_store
    test eax, eax
    jnz .ret
    mov rbx, [rel path_depth]
    xor r12, r12
.fr:
    cmp r12, rbx
    jae .bm
    lea r11, [rel path_old]
    mov rdi, [r11+r12*8]
    call free_block_safe
    inc r12
    jmp .fr
.bm:
    call bitmap_write
    test eax, eax
    jnz .ret
    call super_store
.ret:
    EPILOGUE 8

free_block_safe:
    jmp free_block

; rdi obj, rsi type, rdx off, rcx dst, r8 dstmax -> rax len or -errno
btree_get:
    PROLOGUE 24
    mov [rel seek_obj], rdi
    mov [rel seek_type], rsi
    mov [rel seek_off], rdx
    mov [rsp], rcx
    mov [rsp+8], r8
    call load_path
    test eax, eax
    jnz .ret
    cmp byte [rel found_exact], 0
    je .no
    mov rdi, [rel path_depth]
    dec rdi
    call path_ptr
    mov rbx, rax
    lea r11, [rel path_slot]
    mov rcx, [r11+rdi*8]
    ; path_slot index is depth-1, rdi was depth-1 but path_ptr clobbered. reload.
    mov rdi, [rel path_depth]
    dec rdi
    lea r11, [rel path_slot]
    mov rcx, [r11+rdi*8]
    shl rcx, 5
    lea r12, [rbx+PAYLOAD_OFF]
    add r12, rcx
    mov r13d, [r12+IH_DLEN]
    mov eax, r13d
    cmp rax, [rsp+8]
    jbe .fit
    mov rax, [rsp+8]
    mov r13, rax
.fit:
    mov rdi, [rsp]
    mov eax, [r12+IH_DOFF]
    lea rsi, [rbx+PAYLOAD_OFF]
    add rsi, rax
    mov rdx, r13
    call memcpy
    mov rax, r13
    jmp .ret
.no:
    mov rax, -ENOENT
.ret:
    EPILOGUE 24

; rdi obj, rsi type, rdx off, rcx data, r8 len
btree_insert:
    PROLOGUE 40
    mov [rel seek_obj], rdi
    mov [rel seek_type], rsi
    mov [rel seek_off], rdx
    mov [rsp], rcx
    mov [rsp+8], r8
    mov [rsp+16], rdi
    mov [rsp+24], rsi
    mov [rsp+32], rdx
    call load_path
    test eax, eax
    jnz .ret
    cmp byte [rel found_exact], 0
    jne .exist
    call extract_leaf
    mov rdi, [rel path_depth]
    dec rdi
    lea r11, [rel path_slot]
    mov rdi, [r11+rdi*8]
    mov rsi, [rsp]
    mov rdx, [rsp+8]
    mov rcx, [rsp+16]
    mov r8, [rsp+24]
    mov r9, [rsp+32]
    call list_insert
    xor edi, edi
    mov rsi, [rel item_count]
    call packed_size
    cmp rax, PAYLOAD_SIZE
    ja .split
    call cow_path
    test eax, eax
    jnz .ret
    mov rdi, [rel path_depth]
    dec rdi
    call path_ptr
    mov rdi, rax
    xor esi, esi
    mov rdx, [rel item_count]
    call store_leaf
    call commit_path
    jmp .ret
.split:
    call cow_path
    test eax, eax
    jnz .ret
    mov rax, [rel item_count]
    shr rax, 1
    test rax, rax
    jz .nospc
    mov [rsp], rax             ; mid, data ptr no longer needed
    mov rdi, [rel path_depth]
    dec rdi
    call path_ptr
    mov rdi, rax
    xor esi, esi
    mov rdx, [rsp]
    call store_leaf
    call alloc_tracked
    test rax, rax
    jz .nospc
    mov r12, rax
    lea rdi, [rel split_buf]
    mov rsi, r12
    xor edx, edx
    call node_clear
    lea rdi, [rel split_buf]
    mov rsi, [rsp]
    mov rdx, [rel item_count]
    sub rdx, rsi
    call store_leaf
    lea rdi, [rel split_buf]
    call node_write
    test eax, eax
    jnz .rb
    ; link the right leaf
    mov rax, [rsp]
    shl rax, 5
    lea r13, [rel item_meta]
    add r13, rax
    mov r14, [rel path_depth]
    cmp r14, 1
    jne .haspar
    call promote_root
    test eax, eax
    jnz .rb
    call commit_path
    jmp .ret
.haspar:
    mov rdi, r14
    sub rdi, 2
    mov rsi, r12
    call parent_insert
    test eax, eax
    jnz .rb
    call commit_path
    jmp .ret
.exist:
    mov rax, -EEXIST
    jmp .ret
.nospc:
    call rollback
    mov rax, -ENOSPC
    jmp .ret
.rb:
    call rollback
    mov rax, -ENOSPC
.ret:
    EPILOGUE 40

; New internal root. Left is path_bn[0], right is r12, right key is [r13] meta.
promote_root:
    PROLOGUE 8
    call alloc_tracked
    test rax, rax
    jz .nospc
    mov rbx, rax
    lea rdi, [rel root_buf]
    mov rsi, rbx
    mov edx, 1
    call node_clear
    ; item 0 = first key of left leaf (meta 0)
    lea r11, [rel root_buf]
    lea rdi, [r11+PAYLOAD_OFF]
    lea r11, [rel item_meta]
    mov rax, [r11+IM_OBJ]
    mov [rdi+II_OBJ], rax
    lea r11, [rel item_meta]
    movzx eax, byte [r11+IM_TYPE]
    mov [rdi+II_TYPE], al
    lea r11, [rel item_meta]
    mov rax, [r11+IM_OFF]
    mov [rdi+II_OFF], rax
    mov rax, [rel path_bn]
    mov [rdi+II_CHILD], rax
    mov rax, [rel fs_generation]
    mov [rdi+II_GEN], rax
    ; item 1
    lea r11, [rel root_buf]
    lea rdi, [r11+PAYLOAD_OFF+INT_IH]
    mov rax, [r13+IM_OBJ]
    mov [rdi+II_OBJ], rax
    movzx eax, byte [r13+IM_TYPE]
    mov [rdi+II_TYPE], al
    mov rax, [r13+IM_OFF]
    mov [rdi+II_OFF], rax
    mov [rdi+II_CHILD], r12
    mov rax, [rel fs_generation]
    mov [rdi+II_GEN], rax
    lea r11, [rel root_buf]
    mov word [r11+NH_NITEMS], 2
    lea rdi, [rel root_buf]
    call node_write
    test eax, eax
    jnz .ret
    mov [rel fs_root], rbx
    xor eax, eax
    jmp .ret
.nospc:
    mov rax, -ENOSPC
.ret:
    EPILOGUE 8

; rdi = parent path index, rsi = right child bn. Right key at [r13].
parent_insert:
    PROLOGUE 8
    mov rbx, rdi
    mov r12, rsi
    mov rdi, rbx
    call path_ptr
    mov r14, rax
    movzx eax, word [r14+NH_NITEMS]
    cmp eax, 100
    jae .nospc
    lea r11, [rel path_slot]
    mov rcx, [r11+rbx*8]
    inc rcx                     ; insert after the left child
    mov r15, rcx
    ; shift records [r15, nitems) up by one
    movzx eax, word [r14+NH_NITEMS]
    sub rax, r15
    jbe .nos
    imul rax, INT_IH
    mov rdx, rax
    mov rax, r15
    imul rax, INT_IH
    lea rsi, [r14+PAYLOAD_OFF]
    add rsi, rax
    lea rdi, [rsi+INT_IH]
    call memmove
.nos:
    mov rax, r15
    imul rax, INT_IH
    lea rdi, [r14+PAYLOAD_OFF]
    add rdi, rax
    mov rax, [r13+IM_OBJ]
    mov [rdi+II_OBJ], rax
    movzx eax, byte [r13+IM_TYPE]
    mov [rdi+II_TYPE], al
    mov rax, [r13+IM_OFF]
    mov [rdi+II_OFF], rax
    mov [rdi+II_CHILD], r12
    mov rax, [rel fs_generation]
    mov [rdi+II_GEN], rax
    inc word [r14+NH_NITEMS]
    xor eax, eax
    EPILOGUE 8
.nospc:
    mov rax, -ENOSPC
    EPILOGUE 8

; rdi obj, rsi type, rdx off, rcx data, r8 len (len must match)
btree_update:
    PROLOGUE 24
    mov [rel seek_obj], rdi
    mov [rel seek_type], rsi
    mov [rel seek_off], rdx
    mov [rsp], rcx
    mov [rsp+8], r8
    call load_path
    test eax, eax
    jnz .ret
    cmp byte [rel found_exact], 0
    je .no
    mov rdi, [rel path_depth]
    dec rdi
    mov r12, rdi
    call path_ptr
    mov rbx, rax
    lea r11, [rel path_slot]
    mov rcx, [r11+r12*8]
    shl rcx, 5
    lea r13, [rbx+PAYLOAD_OFF]
    add r13, rcx
    mov eax, [r13+IH_DLEN]
    cmp rax, [rsp+8]
    jne .inval
    call cow_path
    test eax, eax
    jnz .ret
    ; buffer was updated in place (same path_ptr); data_off unchanged
    mov rdi, [rel path_depth]
    dec rdi
    call path_ptr
    mov rbx, rax
    lea r11, [rel path_slot]
    mov rcx, [r11+rdi*8]
    shl rcx, 5
    lea r13, [rbx+PAYLOAD_OFF]
    add r13, rcx
    mov eax, [r13+IH_DOFF]
    lea rdi, [rbx+PAYLOAD_OFF]
    add rdi, rax
    mov rsi, [rsp]
    mov rdx, [rsp+8]
    call memcpy
    call commit_path
    jmp .ret
.no:
    mov rax, -ENOENT
    jmp .ret
.inval:
    mov rax, -EINVAL
.ret:
    EPILOGUE 24

; rdi obj, rsi type, rdx off
btree_delete:
    PROLOGUE 8
    mov [rel seek_obj], rdi
    mov [rel seek_type], rsi
    mov [rel seek_off], rdx
    call load_path
    test eax, eax
    jnz .ret
    cmp byte [rel found_exact], 0
    je .no
    call extract_leaf
    mov rdi, [rel path_depth]
    dec rdi
    lea r11, [rel path_slot]
    mov rdi, [r11+rdi*8]
    call list_remove
    call cow_path
    test eax, eax
    jnz .ret
    mov rdi, [rel path_depth]
    dec rdi
    call path_ptr
    mov rdi, rax
    xor esi, esi
    mov rdx, [rel item_count]
    call store_leaf
    call commit_path
    jmp .ret
.no:
    mov rax, -ENOENT
.ret:
    EPILOGUE 8

; rdi = callback(node, bn, userdata), rsi = userdata
tree_walk:
    PROLOGUE 8
    mov [rel walk_cb], rdi
    mov [rel walk_ud], rsi
    mov rdi, [rel fs_root]
    test rdi, rdi
    jz .io
    call walk_rec
    jmp .ret
.io:
    mov rax, -EIO
.ret:
    EPILOGUE 8

; rdi = bytenr
walk_rec:
    PROLOGUE 824
    mov r12, rdi
    mov rdi, r12
    lea rsi, [rel walk_buf]
    call node_read
    test eax, eax
    jnz .ret
    lea rdi, [rel walk_buf]
    mov rsi, r12
    mov rdx, [rel walk_ud]
    call [rel walk_cb]
    lea r11, [rel walk_buf]
    cmp byte [r11+NH_LEVEL], 0
    je .ok
    lea r11, [rel walk_buf]
    movzx r13, word [r11+NH_NITEMS]
    xor r14, r14
.cp:
    cmp r14, r13
    jae .go
    mov rax, r14
    imul rax, INT_IH
    lea r11, [rel walk_buf]
    lea rdx, [r11+PAYLOAD_OFF]
    mov rax, [rdx+rax+II_CHILD]
    mov [rsp+r14*8], rax
    inc r14
    jmp .cp
.go:
    xor r14, r14
.rc:
    cmp r14, r13
    jae .ok
    mov rdi, [rsp+r14*8]
    call walk_rec
    test eax, eax
    jnz .ret
    inc r14
    jmp .rc
.ok:
    xor eax, eax
.ret:
    EPILOGUE 824

section .bss
ins_off:    resq 1
