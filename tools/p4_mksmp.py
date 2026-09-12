#!/usr/bin/env python3
"""Make a P4 Arduino SMP image bootable in the emulator (TEST SCAFFOLDING).

NOTE (2026-09-11): SUPERSEDED for bringup — the unpatched dual-core
image now boots to HELLO+TICK on -C esp32p4smp with no patches (the
F1/S7' failure modes were diagnosed on broken emulator code: missing
MINTTHRESH masking, missing TARGET1 tick, always-succeed SC). Real
esp_ipc_call traffic also works unpatched (see fw/p4ipc + AGENTS log).
Kept for reproducing earlier results and as a faster-boot option.

Root cause (verified by tracing): hart0's first scheduler yield
no-switch-starts ipc0, which blocks forever in ulTaskGenericNotifyTake
(portMAX_DELAY) while HOLDING xKernelLock. Hart1's first context switch
needs xKernelLock and spins forever (in lockstep emulation this wedges
the whole machine; on HW it livelocks until the WDT bites). No IPC
traffic ever notifies the ipc tasks during bringup, so the lock never
frees.

This tool makes two minimal, build-independent changes:
  F1: ipc notify wait portMAX_DELAY (-1) -> 31 ticks. The ipc tasks
      still block (leaving ready lists, no starvation) and still take
      the lock normally (mutual exclusion intact, no scheduler races),
      but wake every 31ms to re-poll, releasing the lock each cycle.
      Combined with flowing ticks, cross-hart takers always find a
      free window. Pattern: `li a2,-1` feeding ulTaskGenericNotifyTake
      inside ipc_task (sole caller, verified unique).
  S7': main_task suicide -> self-park. main_task calls app_main then
      vTaskDelete(NULL); deleting self holds xKernelLock forever (the
      dead task never resumes to release). Park (c.j self) instead so
      the lock stays free. Starves hart0's IDLE-0 (pri0 < pri1);
      harmless for hello.

Scheduler mutual exclusion is otherwise untouched (earlier attempts
that NOPped takes or capped take timeouts caused scheduler races and
corruption under concurrent switches - reverted).

Caveats (bringup scaffold, revisit):
- 31-tick ipc polling adds wakeups; fine for hello (no IPC traffic).
- hart1 still needs its tick (SYSTIMER TARGET1) for delays on core 1;
  loopTask (pinned to core 1) needs it for delay(). Emulator SoC work,
  separate (observe: hart0's tick may drive shared delayed lists).

Usage: p4_mksmp.py <app.elf> <in_merged.bin> <out_merged.bin>
Requires: riscv32-esp-elf-objdump in PATH (or $RISCV_OBJDUMP).
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import p4_mkunicore as U


def main():
    if len(sys.argv) != 4:
        raise SystemExit("usage: p4_mksmp.py <app.elf> "
                         "<in_merged.bin> <out_merged.bin>")
    elf, src, dst = sys.argv[1], sys.argv[2], sys.argv[3]
    objdump = U.find_objdump()
    syms = U.parse_syms(elf, objdump)

    patches = []  # (vma, new_bytes, old_expected, why)

    def sym(name):
        if name not in syms:
            raise SystemExit(f"symbol not found: {name}")
        return syms[name]

    # F1: ipc notify wait -1 -> 31 ticks. The ipc tasks still block
    # (leaving ready lists, no starvation) and still take the lock
    # normally (mutual exclusion intact, no scheduler races), but wake
    # every 31ms to re-poll, freeing the lock each cycle. Combined with
    # flowing ticks, cross-hart takers always find a free window fast.
    # (1 tick overloaded the lock: the woken hart collided with every
    # tick section, forcing full crosscore-handshake timeouts.)
    # Pattern: `li a2,-1` feeding ulTaskGenericNotifyTake inside ipc_task
    # (sole caller, verified unique).
    faddr, fsize = sym("ipc_task")
    insns = U.disasm(elf, objdump, faddr, faddr + fsize)
    calls = [x for x in insns
             if x["mn"] in ("jal", "jalr", "call")
             and "ulTaskGenericNotifyTake" in x["raw"]]
    if len(calls) != 1:
        raise SystemExit(f"F1: NotifyTake call sites != 1 ({len(calls)})")
    ci = insns.index(calls[0])
    found = None
    for j in range(ci - 1, max(ci - 12, -1), -1):
        y = insns[j]
        if y["mn"] in ("jal", "jalr", "call"):
            break
        m = re.match(r"([a-z]+\d*),", y["op"])
        if m and m.group(1) == "a2":
            if (y["mn"] == "li"
                    and y["op"].replace(" ", "") == "a2,-1"
                    and y["len"] == 2):
                found = y
            break
    if found is None:
        raise SystemExit("F1: li a2,-1 timeout not found")
    # c.li a2,31 = 0x467d (LE bytes 7d 46); old c.li a2,-1 = 0x567d
    patches.append((found["addr"], bytes.fromhex("7d46"),
                    bytes.fromhex("7d56"), "SMP ipc wait -1->31 ticks"))
    print(f"SMP: finite ipc wait at {found['addr']:#x}")

    # S7': main_task suicide -> self-park. main_task calls app_main then
    # vTaskDelete(NULL); deleting self holds xKernelLock forever (the
    # dead task never resumes to release), wedging hart1 (which needs
    # the lock to run loopTask on core 1). Park instead: c.j 0 + c.nop.
    # (Starves hart0's IDLE-0 (pri0 < pri1); harmless for hello.)
    faddr, fsize = sym("main_task")
    insns = U.disasm(elf, objdump, faddr, faddr + fsize)
    dels = [x for x in insns
            if x["mn"] in ("jal", "jalr", "call")
            and "vTaskDelete" in x["raw"]]
    if len(dels) != 1 or dels[0]["len"] != 4:
        raise SystemExit(f"S7': vTaskDelete call not unique/32-bit "
                         f"in main_task ({len(dels)})")
    patches.append((dels[0]["addr"], bytes.fromhex("01a00100"), None,
                    "SMP main_task suicide->park"))
    print(f"SMP: park main_task at {dels[0]['addr']:#x}")

    # ---- map vma -> file offset via merged.bin segments (shared) ----
    import struct
    import hashlib
    d = bytearray(open(src, "rb").read())
    base = 0x10000
    assert d[base] == 0xE9, "app magic missing at 0x10000"
    nsegs = d[base + 1]
    segs = []
    off = base + 24
    for _ in range(nsegs):
        la, ln = struct.unpack_from("<II", d, off)
        segs.append((la, off + 8, ln))
        off += 8 + ln
    total = off - base
    cklen = ((total + 1 + 15) & ~15) - total
    ckpos = base + total + cklen - 1
    hashpos = base + total + cklen

    def fold32(w):
        return ((w >> 24) ^ (w >> 16) ^ (w >> 8) ^ w) & 0xFF

    segranges = [(data, data + ln) for _, data, ln in segs]

    def checksum_of(buf):
        cw = 0xEF
        for a, b in segranges:
            for i in range(a, b, 4):
                cw ^= struct.unpack_from("<I", buf, i)[0]
        return fold32(cw)

    pristine = bytearray(open(src, "rb").read())
    if checksum_of(pristine) != pristine[ckpos]:
        raise SystemExit("checksum coverage wrong")

    def vma_to_file(vma):
        for la, data, ln in segs:
            if la <= vma < la + ln:
                return data + (vma - la)
        raise SystemExit(f"vma {vma:#x} not in any segment")

    for vma, new, old_exp, why in patches:
        fo = vma_to_file(vma)
        old = bytes(d[fo:fo + len(new)])
        if old_exp is not None and old != old_exp:
            raise SystemExit(
                f"stale bytes at {vma:#x}: {old.hex()} != {old_exp.hex()}")
        if old_exp is None:
            if len(new) == 4 and (old[0] & 0x7F) not in (0x6F, 0x67):
                raise SystemExit(
                    f"not a jal/jalr at {vma:#x}: {old.hex()}")
            if len(new) == 2 and (old[0] & 0x3) != 0x1:
                raise SystemExit(
                    f"not compressed at {vma:#x}: {old.hex()}")
        d[fo:fo + len(new)] = new
        print(f"patched {why} at file {fo:#x} "
              f"({old.hex()} -> {new.hex()})")

    new_ck = checksum_of(d)
    print(f"checksum [{ckpos:#x}]: {d[ckpos]:#04x} -> {new_ck:#04x}")
    d[ckpos] = new_ck
    new_hash = hashlib.sha256(bytes(d[base:hashpos])).digest()
    d[hashpos:hashpos + 32] = new_hash
    print(f"re-signed SHA256 at {hashpos:#x}")
    open(dst, "wb").write(d)
    print(f"wrote {dst}")


if __name__ == "__main__":
    main()
