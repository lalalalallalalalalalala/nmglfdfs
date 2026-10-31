#!/bin/sh
# Самопроверка и, если доступен FUSE, сквозной сценарий монтирования.
set -eu

cd "$(dirname "$0")/.."
make -s

echo "== самопроверка =="
./nmglfdfs-selftest

if [ ! -e /dev/fuse ] || ! command -v fusermount3 >/dev/null 2>&1; then
    echo "FUSE недоступен, сквозной тест монтирования пропущен."
    exit 0
fi

echo "== монтирование =="
PASS="${NMGLFDFS_PASSPHRASE:-test-passphrase}"
export NMGLFDFS_PASSPHRASE="$PASS"
IMG="$(mktemp /tmp/nmgl-test-XXXXXX.img)"
MNT="$(mktemp -d /tmp/nmgl-mnt-XXXXXX)"
PID=""

cleanup() {
    if [ -n "$PID" ]; then
        fusermount3 -u "$MNT" >/dev/null 2>&1 || true
        wait "$PID" >/dev/null 2>&1 || true
        PID=""
    fi
    rm -rf "$MNT" "$IMG" /tmp/nmgl-big-$$.bin
}
trap cleanup EXIT

./mkfs.nmglfdfs "$IMG" 16

start_mount() {
    ./nmglfdfs "$IMG" "$MNT" >"$MNT.daemon" 2>&1 &
    PID=$!
    i=0
    while [ "$i" -lt 50 ]; do
        if grep -q " $MNT " /proc/mounts && stat "$MNT" >/dev/null 2>&1; then
            return 0
        fi
        if ! kill -0 "$PID" 2>/dev/null; then
            echo "демон завершился:"
            cat "$MNT.daemon" || true
            return 1
        fi
        i=$((i + 1))
        sleep 0.1
    done
    echo "таймаут монтирования"
    cat "$MNT.daemon" || true
    return 1
}

stop_mount() {
    fusermount3 -u "$MNT"
    wait "$PID"
    PID=""
    i=0
    while grep -q " $MNT " /proc/mounts && [ "$i" -lt 50 ]; do
        i=$((i + 1))
        sleep 0.1
    done
}

start_mount
printf '%s\n' 'HELLO-NMGLFDFS-SECRET' > "$MNT/hello"
[ "$(cat "$MNT/hello")" = "HELLO-NMGLFDFS-SECRET" ]
mv "$MNT/hello" "$MNT/renamed"
[ "$(cat "$MNT/renamed")" = "HELLO-NMGLFDFS-SECRET" ]
mv "$MNT/renamed" "$MNT/hello"
ls "$MNT" | grep -q hello
mkdir "$MNT/sub"
printf '%s\n' nested > "$MNT/sub/a.txt"
[ "$(cat "$MNT/sub/a.txt")" = "nested" ]
dd if=/dev/zero bs=1000 count=5 status=none | tr '\0' 'B' > /tmp/nmgl-big-$$.bin
cp /tmp/nmgl-big-$$.bin "$MNT/big.bin"
cmp /tmp/nmgl-big-$$.bin "$MNT/big.bin"
rm "$MNT/sub/a.txt"
rmdir "$MNT/sub"
printf '%s\n' 'HELLO-NMGLFDFS-SECRET-2' > "$MNT/hello"
[ "$(cat "$MNT/hello")" = "HELLO-NMGLFDFS-SECRET-2" ]
ls "$MNT" | grep -q hello
ls "$MNT" | grep -q big.bin
if grep -a -q 'HELLO-NMGLFDFS-SECRET-2' "$IMG"; then
    echo "открытый текст найден в образе"
    exit 1
fi
stop_mount

start_mount
[ "$(cat "$MNT/hello")" = "HELLO-NMGLFDFS-SECRET-2" ]
cmp /tmp/nmgl-big-$$.bin "$MNT/big.bin"
stop_mount

./nmglfdfs-ctl sleep "$IMG"
if ./nmglfdfs "$IMG" "$MNT" >"$MNT.daemon" 2>&1; then
    echo "sleep не запретил монтирование"
    exit 1
fi
./nmglfdfs-ctl wake "$IMG"
start_mount
[ "$(cat "$MNT/hello")" = "HELLO-NMGLFDFS-SECRET-2" ]
stop_mount

./nmglfdfs-ctl wipe "$IMG"
if ./nmglfdfs "$IMG" "$MNT" >"$MNT.daemon" 2>&1; then
    echo "wipe не запретил монтирование"
    exit 1
fi

echo "== монтирование прошло =="
