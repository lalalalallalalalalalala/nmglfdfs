; NMGLFDFS constants and on-disk offsets.

BLOCK_SIZE          equ 4096
MAX_BITMAP_BLOCKS   equ 32
MAX_NAME            equ 255
MAX_PASS            equ 128
KDF_ITERS_DEFAULT   equ 2048
MAX_TREE_DEPTH      equ 8
PAYLOAD_OFF         equ 32
PAYLOAD_SIZE        equ 4064
LEAF_IH             equ 32
INT_IH              equ 40
MAX_LEAF_ITEMS      equ 120
MAX_INT_ITEMS       equ 101

MAGIC_SUPER         equ 0x534644464C474D4E   ; "NMGLFDFS" little-endian
MAGIC_NODE          equ 0x4E544D4E           ; "NMTN"
VERSION             equ 1

FLAG_SLEEP          equ 1
FLAG_WIPED          equ 2

; Superblock
SB_MAGIC            equ 0
SB_VERSION          equ 8
SB_FLAGS            equ 12
SB_BLOCK_SIZE       equ 16
SB_BITMAP_BLOCKS    equ 20
SB_TOTAL_BLOCKS     equ 24
SB_BITMAP_START     equ 32
SB_ROOT             equ 40
SB_GENERATION       equ 48
SB_NEXT_INODE       equ 56
SB_FREE_BLOCKS      equ 64
SB_KDF_ITERS        equ 72
SB_PAD76            equ 76
SB_SALT             equ 80
SB_UUID             equ 96
SB_WRAPPED          equ 112
SB_SLEEP            equ 144
SB_VERIFIER         equ 208
SB_WRITE_SEQ        equ 240
SB_CRC              equ 248

; Node header
NH_MAGIC            equ 0
NH_CRC              equ 4
NH_BYTENR           equ 8
NH_GEN              equ 16
NH_LEVEL            equ 24
NH_FLAGS            equ 25
NH_NITEMS           equ 26
NH_RES              equ 28
NH_FLAG_ENC         equ 1

; Leaf item header
IH_OBJ              equ 0
IH_TYPE             equ 8
IH_OFF              equ 12
IH_DOFF             equ 20
IH_DLEN             equ 24

; Internal item
II_OBJ              equ 0
II_TYPE             equ 8
II_OFF              equ 16
II_CHILD            equ 24
II_GEN              equ 32

TYPE_INODE          equ 1
TYPE_DIR            equ 2
TYPE_EXTENT         equ 3

; Inode item (64 bytes)
INO_MODE            equ 0
INO_NLINK           equ 4
INO_UID             equ 8
INO_GID             equ 12
INO_SIZE            equ 16
INO_ATIME           equ 24
INO_MTIME           equ 32
INO_CTIME           equ 40
INO_BLOCKS          equ 48
INO_PARENT          equ 56

; Directory item
DIR_INO             equ 0
DIR_DTYPE           equ 8
DIR_NAMELEN         equ 9
DIR_NAME            equ 12

; Extent item (32 bytes)
EXT_DISK            equ 0
EXT_TIME            equ 8
EXT_GEN             equ 16
EXT_METHOD          equ 24
EXT_PLEN            equ 26
EXT_CRC             equ 28
EXT_BYTES           equ 32

ROOT_INO            equ 256
S_IFREG             equ 0x8000
S_IFDIR             equ 0x4000
DT_DIR              equ 4
DT_REG              equ 8

; errno
EPERM               equ 1
ENOENT              equ 2
EIO                 equ 5
EEXIST              equ 17
ENOTDIR             equ 20
EISDIR              equ 21
EINVAL              equ 22
ENOSPC              equ 28
EROFS               equ 30
ENAMETOOLONG        equ 36
ENOSYS              equ 38
ENOTEMPTY           equ 39
; private
ERR_SLEEP           equ 200
ERR_WIPED           equ 201

; FUSE
FUSE_ROOT_ID        equ 1
FUSE_KERNEL_VERSION equ 7
FUSE_KERNEL_MINOR   equ 39
FUSE_LOOKUP         equ 1
FUSE_FORGET         equ 2
FUSE_GETATTR        equ 3
FUSE_SETATTR        equ 4
FUSE_MKNOD          equ 8
FUSE_MKDIR          equ 9
FUSE_UNLINK         equ 10
FUSE_RMDIR          equ 11
FUSE_RENAME         equ 12
FUSE_OPEN           equ 14
FUSE_READ           equ 15
FUSE_WRITE          equ 16
FUSE_STATFS         equ 17
FUSE_RELEASE        equ 18
FUSE_FSYNC          equ 20
FUSE_FLUSH          equ 25
FUSE_INIT           equ 26
FUSE_OPENDIR        equ 27
FUSE_READDIR        equ 28
FUSE_RELEASEDIR     equ 29
FUSE_FSYNCDIR       equ 30
FUSE_ACCESS         equ 34
FUSE_CREATE         equ 35
FUSE_INTERRUPT      equ 36
FUSE_DESTROY        equ 38
FUSE_BATCH_FORGET   equ 42
FUSE_RENAME2        equ 45

FUSE_BIG_WRITES     equ (1 << 5)
FATTR_MODE          equ (1 << 0)
FATTR_UID           equ (1 << 1)
FATTR_GID           equ (1 << 2)
FATTR_SIZE          equ (1 << 3)
FATTR_ATIME         equ (1 << 4)
FATTR_MTIME         equ (1 << 5)
FATTR_ATIME_NOW     equ (1 << 7)
FATTR_MTIME_NOW     equ (1 << 8)
FATTR_CTIME         equ (1 << 10)

FUSE_IN_HEADER      equ 40
FUSE_OUT_HEADER     equ 16
FUSE_ATTR_SIZE      equ 88
FUSE_ENTRY_OUT      equ 128
FUSE_ATTR_OUT       equ 104
FUSE_INIT_OUT       equ 64
FUSE_WRITE_IN       equ 40
FUSE_READ_IN        equ 40
FUSE_SETATTR_IN     equ 88
FUSE_CREATE_IN      equ 16
FUSE_MKDIR_IN       equ 8
FUSE_MKNOD_IN       equ 16
FUSE_OPEN_IN        equ 8
FUSE_RENAME2_IN     equ 16

; pipeline parameter block
PP_DST              equ 0
PP_SRC              equ 8
PP_LEN              equ 16
PP_KEY              equ 24
PP_TS               equ 32
PP_GEN              equ 40
PP_OFF              equ 48
PP_INO              equ 56
PP_DEC              equ 64

; crypto
MUL64_CONST         equ 0x9E3779B97F4A7C15
MUL64_INV           equ 0xF1DE83E19937733D
ARX_C1              equ 0xA5A5A5A5A5A5A5A5
ARX_C2              equ 0x3C6EF372FE94F82B
ARX_C3              equ 0x1F83D9ABFB41BD6B
ARX_C4              equ 0x9E3779B97F4A7C15
FEISTEL_XOR32       equ 0xA5A5A5A5
GF_CONST            equ 0x53
GF_INV              equ 0xCA
