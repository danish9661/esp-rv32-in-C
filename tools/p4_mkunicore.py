#!/usr/bin/env python3
"""Make a P4 Arduino image single-core friendly (TEST SCAFFOLDING).

CPU1 never boots in the emulator, so every wait for CPU1 would hang and
loopTask (pinned to CPU1) would never run. This tool neutralizes those
sites in a build-independent way (ELF symbols + disassembly, no hardcoded
byte patterns):

  R1. CPU-sync waits: backward conditional branches whose loop body loads
      one of s_cpu_up / s_cpu_inited / s_system_inited /
      s_other_cpu_startup_done / s_flash_op_can_start -> nop the branch.
      (Scanned only in system_early_init, start_cpu0, main_task and
      spi_flash_disable_interrupts_caches_and_other_cpu.)
  R2. loopTask affinity in app_main: `li a6,1` before the
      xTaskCreateUniversal call -> `li a6,0`; following `mv a4,a6` ->
      `li a4,1` (keep priority 1).
  R3. spi_flash IPC-stall retry: on failed esp_ipc_call_nonblocking the
      firmware resumes+retries forever. Nop the resume+retry and flip the
      defensive `beqz s1,skip` assert-guard to `bnez` so failure falls
      through to the op path (nothing runs on CPU1 that needs stalling).

Then recomputes the appended checksum byte and SHA256 (the bootloader
verifies both; any byte change would otherwise fail boot).

Usage: p4_mkunicore.py <app.elf> <in_merged.bin> <out_merged.bin>
Requires: riscv32-esp-elf-objdump in PATH (or $RISCV_OBJDUMP).
"""
import os
import re
import struct
import subprocess
import sys
import hashlib


def sh(cmd):
    return subprocess.run(cmd, capture_output=True, text=True,
                          check=True).stdout


def find_objdump():
    for cand in [os.environ.get("RISCV_OBJDUMP", ""),
                 "riscv32-esp-elf-objdump"]:
        if cand and shutil_which(cand):
            return cand
    # arduino toolchain fallback
    home = os.path.expanduser("~/.arduino15/packages/esp32/tools/esp-rv32")
    if os.path.isdir(home):
        for ver in sorted(os.listdir(home), reverse=True):
            p = os.path.join(home, ver, "bin", "riscv32-esp-elf-objdump")
            if os.path.isfile(p):
                return p
    raise SystemExit("riscv32-esp-elf-objdump not found")


def shutil_which(c):
    for d in os.environ.get("PATH", "").split(":"):
        if os.path.isfile(os.path.join(d, c)):
            return True
    return os.path.isfile(c)


SYM_RE = re.compile(r"^([0-9a-f]+)\s+\S+\s+\S+\s+\S+\s+([0-9a-f]+)\s+(\S.*\S|\S)\s*$")
INSN_RE = re.compile(r"^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s)+)\s*(\S+)(.*)$")


def parse_syms(elf, objdump):
    syms = {}
    for line in sh([objdump, "-t", elf]).splitlines():
        m = SYM_RE.match(line)
        if m:
            syms[m.group(3).strip()] = (int(m.group(1), 16),
                                        int(m.group(2), 16))
    return syms


def disasm(elf, objdump, start, end):
    out = sh([objdump, "-d", "--start-address=%#x" % start,
              "--stop-address=%#x" % end, elf])
    insns = []
    for line in out.splitlines():
        # `400033be:\t1141      \taddi\tsp,sp,-16` (this objdump prints
        # whole-word hex, not space-separated bytes)
        m = re.match(r"^\s*([0-9a-f]+):\s+(.*)$", line)
        if not m:
            continue
        addr = int(m.group(1), 16)
        toks = m.group(2).split()
        nbytes = 0
        i = 0
        while i < len(toks) and re.fullmatch(r"[0-9a-f]+", toks[i]):
            nbytes += len(toks[i]) // 2
            i += 1
        if nbytes not in (2, 4) or i >= len(toks):
            continue
        rest = " ".join(toks[i + 1:])
        insns.append({"addr": addr, "len": nbytes,
                      "mn": toks[i], "op": rest,
                      "raw": line.strip()})
    return insns


BRANCH_MN = {"beqz", "bnez", "beq", "bne", "blt", "bge", "bltu", "bgeu"}


def branch_target(insn):
    m = re.search(r"([0-9a-f]{6,8})\s*(<[^>]*>)?\s*$", insn["op"])
    if m:
        return int(m.group(1), 16)
    return None


def loads_flag_addr(insn, flag_addrs):
    # objdump annotates loads: `lbu a5,-204(s1) # 4ff54f34 <s_cpu_up>`
    m = re.search(r"#\s*([0-9a-f]{8})\b", insn["raw"])
    if m and int(m.group(1), 16) in flag_addrs:
        return True
    return False


def track_lui_loads(insns, flag_addrs):
    """Dataflow fallback: track `lui rd,imm` (+`addi`) values per register
    so loads via a computed base resolve to flag addresses even when
    objdump prints no `#` comment. Calls clear caller-saved regs only
    (s0-s11/gp/tp/sp survive per the ABI). Returns set of insn indexes
    that load from a flag address."""
    caller_saved = {"x1", "x5", "x6", "x7", "x10", "x11", "x12", "x13",
                    "x14", "x15", "x16", "x17", "x28", "x29", "x30",
                    "x31", "ra", "t0", "t1", "t2", "t3", "t4", "t5", "t6",
                    "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"}
    # instructions that never write a tracked register
    nowrite = {"sb", "sh", "sw", "beqz", "bnez", "beq", "bne", "blt",
               "bge", "bltu", "bgeu", "fence", "ecall", "ebreak", "unimp",
               "wfi", "mret", "nop", "j", "ret"}
    known = {}
    hits = set()

    def kill(rd):
        if rd != "x0" and rd != "zero":
            known.pop(rd, None)

    for idx, ins in enumerate(insns):
        mn, op = ins["mn"], ins["op"]
        m = re.match(r"([a-z]+\d*),(.+)$", op)
        if mn == "lui" and m:
            if m.group(1) not in ("x0", "zero"):
                try:
                    known[m.group(1)] = int(m.group(2).strip(), 0) << 12
                except ValueError:
                    kill(m.group(1))
            continue
        if mn == "addi" and m:
            parts = [p.strip() for p in m.group(2).split(",")]
            if len(parts) == 2 and parts[0] in known:
                try:
                    known[m.group(1)] = (known[parts[0]] +
                                         int(parts[1], 0)) & 0xFFFFFFFF
                except ValueError:
                    kill(m.group(1))
            else:
                kill(m.group(1))
            continue
        if mn in ("lbu", "lb", "lhu", "lh", "lw") and m:
            mm = re.match(r"(-?(?:0x[0-9a-f]+|\d+))\((\w+)\)$", m.group(2))
            if mm and mm.group(2) in known:
                try:
                    eff = (known[mm.group(2)] + int(mm.group(1), 0)) & 0xFFFFFFFF
                    if eff in flag_addrs:
                        hits.add(idx)
                except ValueError:
                    pass
            # NOTE: loads never kill base tracking: they are overwhelmingly
            # callee-saved restores of the same value (and real HW proves
            # the polled address is the flag, so tracked == actual).
            continue
        # any other write to rd kills tracking (conservative)
        if mn in ("jal", "jalr", "call"):
            for r in caller_saved:
                known.pop(r, None)
            if m:
                kill(m.group(1))
        elif mn in nowrite:
            pass
        elif m:
            kill(m.group(1))
    return hits


def nop_for(length):
    if length == 2:
        return bytes.fromhex("0100")  # c.nop
    if length == 4:
        return bytes.fromhex("00000013")  # addi x0,x0,0
    raise SystemExit(f"cannot nop insn of length {length}")


def enc_c_j(offset):
    """Encode C.J (2 bytes) for a PC-relative byte offset (must be even,
    fit in 12 bits)."""
    assert offset % 2 == 0 and -(1 << 11) <= offset < (1 << 11), offset
    u = offset & 0xFFF
    imm = {11: (u >> 11) & 1, 4: (u >> 4) & 1, 9: (u >> 9) & 1,
           8: (u >> 8) & 1, 10: (u >> 10) & 1, 6: (u >> 6) & 1,
           7: (u >> 7) & 1, 3: (u >> 3) & 1, 2: (u >> 2) & 1,
           1: (u >> 1) & 1, 5: (u >> 5) & 1}
    w = (0b101 << 13) | (imm[11] << 12) | (imm[4] << 11) | \
        (imm[9] << 10) | (imm[8] << 9) | (imm[10] << 8) | \
        (imm[6] << 7) | (imm[7] << 6) | (imm[3] << 5) | \
        (imm[2] << 4) | (imm[1] << 3) | (imm[5] << 2) | 0b01
    return bytes([w & 0xFF, (w >> 8) & 0xFF])


def dec_c_j(word, pc):
    """Decode a C.J word back to its absolute target (self-check)."""
    assert (word & 0xFFFF) >> 13 == 0b101 and (word & 3) == 1
    imm = (((word >> 12) & 1) << 11) | (((word >> 11) & 1) << 4) | \
          (((word >> 10) & 3) << 8) | (((word >> 8) & 1) << 10) | \
          (((word >> 7) & 1) << 6) | (((word >> 6) & 1) << 7) | \
          (((word >> 3) & 7) << 1) | (((word >> 2) & 1) << 5)
    if imm & (1 << 11):
        imm -= 1 << 12
    return pc + imm
    if length == 2:
        return bytes.fromhex("0100")  # c.nop
    if length == 4:
        return bytes.fromhex("00000013")  # addi x0,x0,0
    raise SystemExit(f"cannot nop insn of length {length}")


def main():
    if len(sys.argv) != 4:
        raise SystemExit("usage: p4_mkunicore.py <app.elf> "
                         "<in_merged.bin> <out_merged.bin>")
    elf, src, dst = sys.argv[1], sys.argv[2], sys.argv[3]
    objdump = find_objdump()
    syms = parse_syms(elf, objdump)

    def sym(name):
        if name not in syms:
            raise SystemExit(f"symbol not found: {name}")
        return syms[name]

    flag_names = ["s_cpu_up", "s_cpu_inited", "s_system_inited",
                  "s_other_cpu_startup_done", "s_flash_op_can_start"]
    flag_addrs = set()
    flag_ranges = []
    for fn in flag_names:
        fa, fsz = sym(fn)
        flag_addrs.add(fa)
        flag_ranges.append((fa, fa + max(fsz, 1)))
    for a, b in flag_ranges:
        for addr in range(a + 1, b):
            flag_addrs.add(addr)

    def in_flag_range(eff):
        return any(a <= eff < b for a, b in flag_ranges)

    patches = []  # (vma, new_bytes, why)

    # ---- R1: CPU-sync waits (backward branch over a flag load) ----
    # Idiom (a): backward conditional branch closing the poll loop.
    # Idiom (b): do-while closed by an unconditional backward `j`; the
    #   loop-exit is a single forward beqz/bnez on the flag. Nopping that
    #   branch falls straight through to the done path.
    # Both require the tested register to be flag-derived (loaded from a
    # sync flag, possibly via mv/and/or) so error-check branches on call
    # return values are never touched.
    for func in ["system_early_init", "start_cpu0", "main_task",
                 "spi_flash_disable_interrupts_caches_and_other_cpu"]:
        faddr, fsize = sym(func)
        insns = disasm(elf, objdump, faddr, faddr + fsize)
        lui_hits = track_lui_loads(insns, flag_addrs)

        def reg_is_flag_loaded(idx):
            x = insns[idx]
            if x["mn"] in ("lb", "lbu", "lh", "lhu", "lw"):
                if loads_flag_addr(x, flag_addrs) or idx in lui_hits:
                    m = re.match(r"([a-z]+\d*),", x["op"])
                    return m.group(1) if m else None
            return None

        def body_derived_regs(lo, hi):
            """Regs holding flag values inside [lo,hi], flow-insensitive:
            direct flag loads plus mv/and/or/add/addi/seqz/snez closure.
            (Wait-loop bodies are tiny; kills are ignored because values
            flow around the loop back-edge.)"""
            derived = set()
            changed = True
            while changed:
                changed = False
                for j, x in enumerate(insns):
                    if not (lo <= x["addr"] <= hi):
                        continue
                    if reg_is_flag_loaded(j):
                        m = re.match(r"([a-z]+\d*),", x["op"])
                        if m and m.group(1) not in derived:
                            derived.add(m.group(1))
                            changed = True
                        continue
                    m = re.match(r"([a-z]+\d*),(.+)$", x["op"])
                    if m and x["mn"] in ("mv", "and", "or", "add",
                                         "addi", "seqz", "snez"):
                        op2 = m.group(2)
                        srcs = re.findall(r"[a-z]+\d*", op2)
                        if any(s in derived for s in srcs):
                            if m.group(1) not in derived:
                                derived.add(m.group(1))
                                changed = True
            return derived

        def branch_tests_derived(ins, derived):
            m = re.match(r"([a-z]+\d*),", ins["op"])
            return bool(m and m.group(1) in derived)

        for i, ins in enumerate(insns):
            if ins["mn"] in BRANCH_MN:
                tgt = branch_target(ins)
                if tgt is None or tgt >= ins["addr"]:
                    continue
                if ins["addr"] - tgt > 64:
                    continue
                derived = body_derived_regs(tgt, ins["addr"])
                if not derived:
                    continue
                if not branch_tests_derived(ins, derived):
                    continue
                patches.append((ins["addr"], nop_for(ins["len"]),
                                f"R1a cpu-sync wait in {func}"))
                print(f"R1a: nop branch at {ins['addr']:#x} "
                      f"({ins['mn']} {ins['op']}) [{func}]")
            elif ins["mn"] == "j":
                tgt = branch_target(ins)
                if tgt is None or tgt >= ins["addr"]:
                    continue
                if ins["addr"] - tgt > 128:
                    continue
                derived = body_derived_regs(tgt, ins["addr"])
                if not derived:
                    continue
                conds = [x for x in insns
                         if tgt <= x["addr"] <= ins["addr"]
                         and x["mn"] in ("beqz", "bnez")
                         and branch_tests_derived(x, derived)]
                if len(conds) != 1:
                    print(f"R1b: SKIP j-loop at {ins['addr']:#x} [{func}]: "
                          f"{len(conds)} flag-testing beqz/bnez, need 1")
                    continue
                b = conds[0]
                patches.append((b["addr"], nop_for(b["len"]),
                                f"R1b cpu-sync wait in {func}"))
                print(f"R1b: nop branch at {b['addr']:#x} "
                      f"({b['mn']} {b['op']}) [{func}]")

    # ---- R2: loopTask affinity in app_main ----
    aaddr, asize = sym("app_main")
    ains = disasm(elf, objdump, aaddr, aaddr + asize)
    create = [x for x in ains if "xTaskCreateUniversal" in x["raw"]]
    if len(create) != 1:
        raise SystemExit("R2: xTaskCreateUniversal call site not unique "
                         f"in app_main ({len(create)})")
    ci = ains.index(create[0])
    li6 = [x for x in ains[max(0, ci - 24):ci]
           if x["mn"] == "li" and x["op"] == "a6,1"]
    if len(li6) != 1:
        raise SystemExit(f"R2: li a6,1 not unique ({len(li6)})")
    mv = [x for x in ains[ains.index(li6[0]):ci + 8]
          if x["mn"] in ("mv", "or", "add") and "a4,a6" in x["op"].replace(" ", "")]
    if len(mv) != 1 or mv[0]["len"] != 2:
        raise SystemExit("R2: mv a4,a6 not found/unique")
    patches.append((li6[0]["addr"], bytes.fromhex("0540"),
                    "R2 loopTask core 1->0"))
    patches.append((mv[0]["addr"], bytes.fromhex("0547"),
                    "R2 loopTask prio keep 1"))
    print(f"R2: loopTask core+prio at {li6[0]['addr']:#x},{mv[0]['addr']:#x}")

    # ---- R3: flash IPC-stall retry ----
    # On failed esp_ipc_call_nonblocking (CPU1 dead) the firmware resumes
    # and retries forever. Convert the `beqz a0,wait` into an unconditional
    # jump to the same wait target so failure proceeds like success (the
    # stall is vacuous single-core). The resume+retry tail becomes dead
    # code. NOTE: do NOT fall through into the defensive `beqz s1` assert
    # guard below it: that guard is live on the scheduler-not-running path
    # (entry s1==0 must keep skipping it).
    faddr, fsize = sym("spi_flash_disable_interrupts_caches_and_other_cpu")
    fins = disasm(elf, objdump, faddr, faddr + fsize)
    ipc = [x for x in fins if "esp_ipc_call_nonblocking" in x["raw"]]
    if len(ipc) != 1:
        raise SystemExit(f"R3: IPC call site not unique ({len(ipc)})")
    ii = fins.index(ipc[0])
    tail = fins[ii:ii + 12]
    beqz = [x for x in tail
            if x["mn"] == "beqz" and x["op"].startswith("a0,")]
    if len(beqz) != 1 or beqz[0]["len"] != 2:
        raise SystemExit("R3: beqz a0 after IPC not unique/16-bit")
    b = beqz[0]
    tgt = branch_target(b)
    if tgt is None or tgt <= b["addr"]:
        raise SystemExit("R3: beqz a0 target not forward")
    new_j = enc_c_j(tgt - b["addr"])
    rt = struct.unpack("<H", new_j)[0]
    if dec_c_j(rt, b["addr"]) != tgt:
        raise SystemExit("R3: c.j roundtrip mismatch")
    patches.append((b["addr"], new_j, "R3 beqz->j over IPC retry"))
    print(f"R3: beqz->j at {b['addr']:#x} to {tgt:#x}")

    # ---- map vma -> file offset via merged.bin segments ----
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

    for vma, new, why in patches:
        fo = vma_to_file(vma)
        old = bytes(d[fo:fo + len(new)])
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
