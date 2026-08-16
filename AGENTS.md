# AGENTS.md — ESP32 RISC-V Emulator (based on rv32emu)

Project: A WebAssembly emulator for **ESP32-C3, ESP32-C6, ESP32-H2, ESP32-P4** built by
extending [sysprog21/rv32emu](https://github.com/sysprog21/rv32emu) with ESP32 SoC models.

## Important paths

- Repo (build work): `/home/danish1075/Documents/esp-rv32emu/`
- Original workspace (has a SPACE in path): `/home/danish1075/Documents/esp rv/`
- Build logs: `/tmp/opencode/wasm_build.log`
- Emscripten SDK: `~/emsdk` (must `source ~/emsdk/emsdk_env.sh` before make)
- Current emcc version: 6.0.6

> **WARNING: Do NOT move the repo back into a path containing spaces.**
> rv32emu's Makefiles use unquoted paths and break on spaces (verified:
> `/home/danish1075/Documents/esp rv` caused "target given more than once in
> the same rule" and sha1 verification failures).

## Goals & decisions (confirmed with user)

1. Take rv32emu, add SoC support for 4 chips: **ESP32-C3, ESP32-C6, ESP32-H2, ESP32-P4**.
2. Compile to **WebAssembly** (rv32emu already supports `make CC=emcc` builds).
3. **DECISION: ONE combined WASM binary** with runtime chip selection, NOT one WASM per chip.
   - SoC models are mostly register-map data tables (~10–40 KB each).
   - Per-chip builds only save ~10–30% each and cost 4× build/maintenance.
4. Goal end-state: run ESP-IDF firmware in the browser for all 4 chips.
5. **LANGUAGE: C (not Rust).** rv32emu is C99; our SoC layer is C. Rust is NOT inherently
   faster in WASM (both go through LLVM); rv32emu's speed comes from block-chaining +
   tail-call interpreter design. No rewrite. Speed levers: interpreter core stays as-is;
   JIT (native) possible later.

## Target chip facts (verified)

| Chip | ISA (HP core) | FPU | Cores | Notes |
|---|---|---|---|---|
| ESP32-C3 | RV32IMC | no | 1 | WiFi+BLE, 160 MHz |
| ESP32-C6 | RV32IMC | no | 1 | WiFi6+BLE+802.15.4 |
| ESP32-H2 | RV32IMC | no | 1 | BLE+802.15.4, 96 MHz |
| ESP32-P4 | RV32IMAFC + Zc(Zcb/Zcmp/Zcmt) + Zb + XespV/XespLoop | **yes (single-precision F)** | 2 HP + 1 LP | 400 MHz, huge peripheral set |

- rv32emu covers RV32I/M/A/F/C + Zicsr/Zifencei + Zba/Zbb/Zbc/Zbs. ✅ covers C3/C6/H2 fully; P4 partially.
- P4 gaps in rv32emu: **Zc (Zcmp/Zcmt) not implemented**, **single-core only** (needs SMP), custom XespV/XespLoop missing (optional, not used by default in ESP-IDF).
- ESP-IDF firmware needs real SoC memory maps: SRAM base 0x3FC88000 (C3), peripherals at 0x40000000+, SYSTIMER, UART, GPIO, SPI0 flash cache, eFuse, RTC/PMU registers.

## Architecture plan

```
rv32emu core (interpreter/JIT, ELF loader, GDB stub)   [upstream, keep]
        │
        └── ESP32 SoC layer (new, C, per-chip table-driven)
              ├── memory map / register banks per chip (data tables)
              ├── SYSTIMER, UART0 (console), GPIO, SPI0 (flash cache stub)
              ├── interrupt controller (PLIC/INTC per chip)
              └── chip select at runtime (JS API: pass chip name + ELF)
                     → single WASM serves all 4 chips
```

Build strategy:
- SoC code mostly declarative register tables → small binary, shared across chips.
- `#ifdef CONFIG_CHIP_*` / Kconfig options to strip unused peripherals later if size matters.
- WASM export API: `chip_select(name)`, `load_elf(bytes)`, `run()`, UART in/out callbacks.

## Build commands

```bash
source ~/emsdk/emsdk_env.sh
cd /home/danish1075/Documents/esp-rv32emu

# WASM build (baseline)
make CC=emcc wasm_defconfig        # minimal config (no SDL)
make CC=emcc -j8                   # produces build/rv32emu.js + rv32emu.wasm

# Serve web demo
make CC=emcc start-web              # or: prepare-web, then serve-web
```

Note: `artifact` target fetches prebuilt ELFs from GitHub releases — needs network;
verification must pass (fails if path contains spaces).

## WASM size — REAL BASELINE (measured 2026-08-13, no SDL)

Baseline build (`make CC=emcc wasm_defconfig` + SDL disabled in .config):
- `build/rv32emu.wasm`: **6,608,500 B raw (~6.3 MiB)**
- gzip -9: **3,277,471 B (~3.1 MiB)**
- `build/rv32emu.js` glue: 71,312 B raw, ~20 KB gzip
- Brotli: not measured (brotli not installed on host)

Breakdown:
- Embedded demo ELFs (9 files, incl. jit-bf.elf 865 KB): ~1.67 MB total
- Core interpreter (RV32IMACF+Zb, softfloat, mimalloc, -O3): ~4.9 MB raw / ~2.5 MB gzip
- SDL was NOT enabled (default wasm config enables it → needs SDL2 port download)

So: a lean ESP32-targeted build (no demo ELFs, no SDL) should land ~4.9 MB raw / ~2.5 MB gzip,
+4 chip SoC models ≈ +40–160 KB. My earlier 300–600 KB estimate was too optimistic;
rv32emu's interpreter with full ISA + softfloat is ~5 MB code.

## Roadmap

| Phase | Milestone | Est. time |
|---|---|---|
| 0 | Baseline WASM build works, sizes measured | in progress |
| 1 | ESP32-C3 SoC layer: memory map, SYSTIMER, UART, GPIO, SPI0 stub; bare-metal hello world | 1–2 weeks |
| 2 | C3 boots real ESP-IDF app (minimal periph set) | +1–3 months |
| 3 | Port SoC layer to C6 (adds 802.15.4, USB-serial-JTAG, TWAI) | +2–4 weeks |
| 4 | Port to H2 (different memory map, 802.15.4/BLE) | +2–4 weeks |
| 5 | P4: dual-core SMP, Zc support, big peripheral surface (Ethernet/USB/MIPI/I3C/SDIO) | +2–3 months |
| 6 | Full peripheral coverage incl. WiFi/BT stubs, polish, docs | 6+ months total |

## Progress log (keep updating)

- [x] Researched rv32emu: supports RV32IMACF + Zb ext + WASM build (docs/wasm.md). MIT license.
- [x] Confirmed chip ISA facts from Espressif datasheets/forum (P4 = RV32IMAFC single-FPU per HP core).
- [x] Decided: single combined WASM, runtime chip selection.
- [x] Cloned rv32emu (shallow) into `~/Documents/esp rv/rv32emu`.
- [x] Found space-in-path breaks Makefile → moved repo to `/home/danish1075/Documents/esp-rv32emu`.
- [x] Verified emcc 6.0.6 (Emscripten) available at ~/emsdk.
- [x] Verified prebuilt artifact ELFs checksums pass after path fix.
- [x] **Baseline WASM build complete** (no SDL): wasm 6.6 MB raw / 3.1 MB gzip, js 71 KB. Details above.
- [x] Baseline sizes recorded → done, see "WASM size" section above.
- [x] Phase 1: C3 SoC layer (memory map, SYSTIMER, UART, GPIO, SPI0 flash cache, INTC, eFuse, RTC) — native build.
- [x] Phase 2: C3 boots a real ESP-IDF/Arduino app (`esp32test.ino` blink sketch) to `setup()`/`loop()` — 2026-08-16.
  - Key fixes: MMU table reads (0x600C5000) for `esp_ota_get_running_partition`; SYSTIMER TARGET0/TARGET2 with
    correct INTC sources (37/39), unit1 select, period-mode tick, live counter reads for `esp_timer_get_time`.
  - App is a silent LED blink (debug report disabled) → no UART output expected; runs stable, no panics.
  - Emulator throughput with ticks: ~18–20 M cycles/s (tick trap overhead dominates).
- [ ] Phase 3: Port SoC layer to C6 (adds 802.15.4, USB-serial-JTAG, TWAI) — next.

## Known issues / gotchas

- Makefile breaks on spaces in path (see warning above).
- `artifact` target re-fetches from GitHub releases if verification fails; slow network caused corruption once.
- Background builds get killed when the shell session ends → use `setsid bash -c 'make ... > log 2>&1' < /dev/null &`.
- WASM requires tail-call support: Chrome 112+, Firefox 121+, Safari 18.2+.
- P4 needs Zc + SMP before real ESP-IDF apps can run (rv32emu doesn't have either).
- WiFi/BT RF + WLAN MAC coprocessor firmware is out of scope for a faithful model → stub.

## Reference links

- rv32emu repo: https://github.com/sysprog21/rv32emu
- rv32emu wasm docs: docs/wasm.md (in repo)
- Espressif QEMU fork (alternative for real firmware): https://github.com/espressif/qemu
- ESP32-P4 datasheet (RV32IMAFC, Zc, XespV): documentation.espressif.com
