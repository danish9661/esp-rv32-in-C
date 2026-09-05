#!/usr/bin/env python3
"""Make a P4 Arduino merged.bin single-core friendly (TEST SCAFFOLDING).

Patches (verified by pattern, then SHA256 re-signed):
 1. CPU1-wait loop in system_early_init (`beqz s0, wait` -> `nop`) so CPU0
    does not spin forever waiting for the second core (the emulator is
    single-core; CPU1 never boots).
 2. loopTask affinity (`li a6,1` -> `li a6,0`) so Arduino setup()/loop()
    run on CPU0 instead of the dead CPU1. Priority (`mv a4,a6`) is kept
    at 1 via `li a4,1`.
 3. Recomputes the appended SHA256 over the app image (bootloader verifies
    it; any byte change would otherwise fail "Image hash failed").

Usage: p4_mkunicore.py <in_merged.bin> <out_merged.bin>
"""
import struct
import sys
import hashlib


def patch_once(d, old, new, name, start=0x10000):
    idx = d.find(old, start)
    if idx < 0:
        raise SystemExit(f"pattern not found: {name} {old.hex()}")
    if d.find(old, idx + 1) >= 0:
        raise SystemExit(f"pattern not unique: {name} {old.hex()}")
    d[idx:idx + len(new)] = new
    print(f"patched {name} at file {idx:#x}")
    return idx


def main():
    src, dst = sys.argv[1], sys.argv[2]
    d = bytearray(open(src, 'rb').read())

    # 1. CPU1-wait in system_early_init (`and s0,s0,a5; auipc; jalr delay;
    #    beqz s0,wait` -> nop the branch). NOTE: patterns are raw file bytes
    #    (little-endian), i.e. byte-swapped vs objdump halfword display.
    seq = bytes.fromhex('7d8c9780bf0fe780a0ea7dd0')
    idx = d.find(seq, 0x10000)
    if idx < 0 or d.find(seq, idx + 1) >= 0:
        raise SystemExit("cpu1-wait sequence not found/unique")
    assert d[idx + 10:idx + 12] == bytes.fromhex('7dd0')
    d[idx + 10:idx + 12] = bytes.fromhex('0100')  # c.nop
    print(f"patched cpu1-wait nop at file {idx + 10:#x}")

    # 1b. Second CPU1-sync wait in system_early_init (`lbu a5,0x41(sp);
    #     beqz a5,wait` on s_cpu_inited[1]) -> nop the branch.
    seq2 = bytes.fromhex('8347410099c7')
    jdx = d.find(seq2, 0x10000)
    if jdx < 0 or d.find(seq2, jdx + 1) >= 0:
        raise SystemExit("cpu-inited-wait sequence not found/unique")
    d[jdx + 4:jdx + 6] = bytes.fromhex('0100')  # c.nop
    print(f"patched cpu-inited-wait nop at file {jdx + 4:#x}")

    # 1c. Third CPU1-sync wait in start_cpu0 (`lbu a5,0xf(sp);
    #     beqz a5,wait` on a CPU1-set flag) -> nop the branch.
    #     NOTE: file bytes are LE (byte-swapped vs halfword display).
    seq3 = bytes.fromhex('8347f10099cf')
    kdx = d.find(seq3, 0x10000)
    if kdx < 0 or d.find(seq3, kdx + 1) >= 0:
        raise SystemExit("sys-inited-wait sequence not found/unique")
    d[kdx + 4:kdx + 6] = bytes.fromhex('0100')  # c.nop
    print(f"patched sys-inited-wait nop at file {kdx + 4:#x}")

    # 1d. main_task SMP rendezvous (`lui a4,0x4ff55; lbu a5,-1096(a4);
    #     beqz a5,.-4` on s_other_cpu_startup_done, set by CPU1 which never
    #     boots here) -> nop the branch so CPU0 proceeds to app_main.
    #     vma 0x40028614-1c, file bytes LE.
    patch_once(d, bytes.fromhex('3757f54f834787bbf5df'),
               bytes.fromhex('3757f54f834787bb0100'),
               'main-task-cpu1-rendezvous')

    # 1e. spi_flash stall-other-CPU wait (`lbu a5,-1357(s1); beqz a5,.-4`
    #     in spi_flash_disable_interrupts_caches_and_other_cpu, vma
    #     0x4ff408de): CPU1 never acks the stall. Single-core: nothing to
    #     stall, nop the branch. Context: li a1,145; j ...; lbu; beqz.
    patch_once(d, bytes.fromhex('930510098dbf83c734abf5df'),
               bytes.fromhex('930510098dbf83c734ab0100'),
               'flash-stall-cpu1-wait')

    # 1f. spi_flash IPC-stall retry (`beqz a0,wait` after a failed
    #     esp_ipc_call_nonblocking to CPU1, vma 0x4ff408be): CPU1 is dead
    #     so the IPC always fails and the op resumes+retries forever (falling
    #     through would hit a defensive assert). Single-core: make it an
    #     unconditional jump to the wait (nothing runs on CPU1 to stall).
    #     c.beqz a0,+32 (c105) -> c.j +32 (05a0), verified by disassembly.
    patch_once(d, bytes.fromhex('05c1ef80e004e1bf'),
               bytes.fromhex('05a0010001000100'),
               'flash-ipc-retry')
    # 2. loopTask affinity in app_main: `li a6,1 ... mv a4,a6`
    #    (a6 doubles as priority via mv and core ID). Set core 0, keep prio 1.
    li6 = bytes.fromhex('0548')
    mv = bytes.fromhex('4287')
    idx = d.find(li6, 0x10000)
    found = None
    while idx >= 0:
        j = d.find(mv, idx, idx + 40)
        if j >= 0:
            if found is not None:
                raise SystemExit("loop affinity sequence not unique")
            found = (idx, j)
        idx = d.find(li6, idx + 1)
    if found is None:
        raise SystemExit("loop affinity sequence not found")
    d[found[0]:found[0] + 2] = bytes.fromhex('0540')  # c.li a6,0
    d[found[1]:found[1] + 2] = bytes.fromhex('0547')  # c.li a4,1
    print(f"patched loop core+prio at file {found[0]:#x},{found[1]:#x}")

    # 3. Fix integrity: ESP image v2 layout after segments is
    #    [checksum:1B][pad to 16B][SHA256:32B].
    #    Checksum byte = XOR-fold of checksum_word (0xEF ^ XOR of all LE
    #    segment-data words). Update differentially from our patches.
    #    SHA256 covers [image_base : hash_pos] (incl. checksum+pad).
    import functools
    base = 0x10000
    assert d[base] == 0xE9, "app magic missing at 0x10000"
    nsegs = d[base + 1]
    off = base + 24
    for _ in range(nsegs):
        _, length = struct.unpack_from('<II', d, off)
        off += 8 + length
    total = off - base  # header + segments
    cklen = ((total + 1 + 15) & ~15) - total  # checksum+pad length
    ckpos = base + total + cklen - 1  # checksum byte position
    hashpos = base + total + cklen  # SHA256 position

    def fold32(w):
        return ((w >> 24) ^ (w >> 16) ^ (w >> 8) ^ w) & 0xFF

    # coverage: XOR of LE words of SEGMENT DATA only (headers excluded)
    segranges = []
    _o = base + 24
    for _ in range(nsegs):
        _, _ln = struct.unpack_from('<II', d, _o)
        segranges.append((_o + 8, _o + 8 + _ln))
        _o += 8 + _ln

    def checksum_of(buf):
        cw = 0xEF
        for a, b in segranges:
            for i in range(a, b, 4):
                cw ^= struct.unpack_from('<I', buf, i)[0]
        return fold32(cw)

    # self-check on pristine bytes first
    pristine = bytearray(open(src, 'rb').read())
    if checksum_of(pristine) != pristine[ckpos]:
        raise SystemExit(
            f"checksum coverage wrong: formula={checksum_of(pristine):#04x} "
            f"stored={pristine[ckpos]:#04x}")
    print(f"checksum coverage verified (stored {pristine[ckpos]:#04x})")

    new_ck = checksum_of(d)
    print(f"checksum [{ckpos:#x}]: {d[ckpos]:#04x} -> {new_ck:#04x}")
    d[ckpos] = new_ck

    old_hash = bytes(d[hashpos:hashpos + 32])
    new_hash = hashlib.sha256(bytes(d[base:hashpos])).digest()
    d[hashpos:hashpos + 32] = new_hash
    print(f"app image total={total:#x} cklen={cklen} "
          f"hash {old_hash.hex()[:16]}... -> {new_hash.hex()[:16]}...")

    open(dst, 'wb').write(d)
    print(f"wrote {dst}")


if __name__ == '__main__':
    main()
