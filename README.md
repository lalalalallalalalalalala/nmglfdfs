> Languages: [English](README.md) · [Русский](README.ru.md) · [中文](README.zh.md)

# NMGLFDFS

**NMGLFDFS** (*No More Good Life For Decrypting File System*) is a standalone encrypting filesystem for Linux x86-64. It is not a patch to Btrfs: it is a separate image and separate code, but its on-disk layout deliberately mirrors Btrfs ideas in simplified form (a superblock, a metadata B-tree, copy-on-write, checksums).

The code is written in **NASM** (x86-64, Linux syscalls). There is no kernel module: mounting happens from userspace over the low-level `/dev/fuse` protocol. The only external helper is the system utility `fusermount3`, which performs the unprivileged `mount(2)` and hands over the device file descriptor. The FUSE protocol itself is parsed and answered by the NASM code, with no libfuse and no C code of its own.

## Build

You need `nasm`, `ld`, and for mounting `fusermount3` (the `fuse3` package) plus access to `/dev/fuse`.

```bash
make
make test
```

`make` builds:

| Program | Purpose |
| --- | --- |
| `mkfs.nmglfdfs` | create an image |
| `nmglfdfs` | mount an image |
| `nmglfdfs-ctl` | `sleep`, `wake`, `wipe` |
| `nmglfdfs-selftest` | crypto and filesystem self-tests |

## Usage

The passphrase is supplied through the `NMGLFDFS_PASSPHRASE` environment variable or the `-p` flag.

```bash
export NMGLFDFS_PASSPHRASE='secret-phrase'
./mkfs.nmglfdfs image.img 64
mkdir -p /mnt/nmgl
./nmglfdfs image.img /mnt/nmgl
# in another terminal:
echo hello > /mnt/nmgl/file.txt
ls /mnt/nmgl
fusermount3 -u /mnt/nmgl

./nmglfdfs-ctl sleep image.img    # metadata hidden, a normal mount will refuse
./nmglfdfs-ctl wake  image.img    # restore with the same passphrase
./nmglfdfs-ctl wipe  image.img    # irreversibly destroy the key
```

`sleep` is reversible: the pointer to the tree root and the wrapped key are sealed with a separate key derived from the passphrase, and the working fields of the superblock are cleared. While the SLEEP flag is set, `nmglfdfs` will not open files — an explicit `wake` is required.

`wipe` is irreversible. The random filesystem key is stored only in the superblock, encrypted with the passphrase. `wipe` clears that field, the salt, the verification code, and the metadata tree nodes. Even knowing the passphrase, the key cannot be recovered, and the data blocks remain unreadable ciphertext.

## How a block is encrypted

For each 4096-byte file block, the time in milliseconds is read at the moment of writing. The last digit (`timestamp % 10`) selects one of ten methods. Alongside it, inside the encrypted B-tree leaf, the extent record stores the timestamp, the write generation number, the method index, the CRC32C of the plaintext, and an HMAC-SHA256 of the ciphertext truncated to 16 bytes. The tag is computed from the data key and bound to the block number, inode, offset, and extent fields. On read it is verified before decryption: a flipped byte yields an I/O error. Without the metadata key these fields themselves cannot be read.

The **encryption** order:

1. **Bit flip.** SHA-256 is computed over the data key, the timestamp, the generation, the in-file offset, and the inode number, and used to seed ChaCha20. For each byte `i`, the timestamp bit `(timestamp >> (i mod 64))` and the parity of the number of set bits in the timestamp are taken. If their XOR is 1, the whole byte is inverted (`NOT`), and all of this is laid over the ChaCha20 keystream. The operation is its own inverse and is uniquely determined by the stored timestamp.
2. **One of ten reversible layers** (see below).
3. **ChaCha20** with a SHA-256 subkey that includes the method number, timestamp, generation, offset, and inode. The block counter is 1, so the keystream does not coincide with the bit-flip step.

Decryption runs in reverse. The method index must match the last digit of the stored timestamp.

The ten layers (all reversible, with ChaCha20 after or before them):

| Digit | Layer |
| --- | --- |
| 0 | multiply each `u64` by an odd constant modulo 2^64 |
| 1 | Feistel network, 4 rounds, 32-bit halves |
| 2 | bijective bit permutation within each `u64` |
| 3 | byte multiplication in GF(2^8) (the AES polynomial) and XOR with a constant |
| 4 | AES S-box substitution |
| 5 | ARX: add, rotate, XOR |
| 6 | nibble swap, add modulo 256, XOR with the index |
| 7 | AES affine transform over GF(2) |
| 8 | Feistel network over 16 bytes, 64-bit halves |
| 9 | AES MixColumns on each group of four bytes |

The data key and the metadata key are derived from a random 32-byte filesystem key. It is created at `mkfs` (`getrandom`) and stored in the superblock, encrypted with ChaCha20. The key that encrypts this field comes from PBKDF2-HMAC-SHA256 (200000 iterations, salt in the superblock). The iteration count is written in the superblock, so an already-created image opens with its own count.

The full on-disk layout is in [docs/FORMAT.md](docs/FORMAT.md).

## Honest note on security

Security is meant to rest on **ChaCha20** and on the filesystem key being random and destroyed by `wipe`. The mathematical layers add diffusion, as the scheme's author asked, but they **do not replace vetted cryptography**. This is a learning prototype:

- the ChaCha20, SHA-256, HMAC, and PBKDF2 implementations are written here in NASM and are **not audited**;
- the mode (bit flip + "millisecond digit" + a custom subkey) is **not** standard ChaCha20-Poly1305: authentication is a separate HMAC-SHA256 truncated to 16 bytes, not Poly1305;
- 200000 PBKDF2-HMAC-SHA256 iterations are a normal modern minimum, but a weak passphrase is still best avoided;
- there is no protection against rolling the whole image back to an older copy: the tag catches byte tampering, but not replacing a file wholesale with a previous version;
- `sleep` hides the key from a normal mount, but the sealed blob stays on disk and is reopened with the same passphrase via `wake`.

Do not keep data in this prototype that you would hate to lose or expose.

## Prototype limitations

- No snapshots, hard links, symbolic links, extended attributes, or sparse files as a separate structure (a hole reads as zeros until written into).
- Free space is a bitmap, not a Btrfs extent tree. The superblock is written in place (two copies: block 0 and block 1). Crash resilience is best-effort: new nodes are written before the root pointer moves, but this is not a full journal.
- An internal node holds up to 101 children. A full node splits in half, and if it is the root the tree grows a level. "No space" remains the answer when the image runs out of blocks or the depth reaches eight.
- A single FUSE request-handling thread. Directories with thousands of files are read by a full tree walk.
- Image size at creation is from 4 to 2048 MiB.

## Tests

`make test` runs `tests/run_tests.sh`: the self-test (all 10 methods, bit-flip determinism, known-answer tests for SHA-256 / ChaCha20 / CRC32C / PBKDF2, write and read, reopen, B-tree growth to a new level and splitting of a non-root internal node, re-reading, read failure after flipping a ciphertext byte and after tampering with a node and recomputing its CRC, `sleep`/`wake`/`wipe`) and, if `/dev/fuse` is present, an end-to-end mount scenario.

## License

See [LICENSE](LICENSE). In short: do what you want with the source, including modifying it, but you take all responsibility and risk yourself; **not recommended for everyday use** and **not recommended for commercial use**; provided with no warranty.
