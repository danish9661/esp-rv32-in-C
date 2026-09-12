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
  - Follow-up 2026-09-10: SYSTIMER `INT_CLR` reads as 0 (WT), GPIO
    level-triggered interrupts re-assert while the level persists
    (edge checker only fires transitions). Verified: hello+TICK,
    gptimer 5 alarms, level IRQ fires once per asserted transition
    with no storm.
- [x] Phase 2: C3 boots a real ESP-IDF/Arduino app (`esp32test.ino` blink sketch) to `setup()`/`loop()` — 2026-08-16.
  - Key fixes: MMU table reads (0x600C5000) for `esp_ota_get_running_partition`; SYSTIMER TARGET0/TARGET2 with
    correct INTC sources (37/39), unit1 select, period-mode tick, live counter reads for `esp_timer_get_time`.
  - App is a silent LED blink (debug report disabled) → no UART output expected; runs stable, no panics.
  - Emulator throughput with ticks: ~18–20 M cycles/s (native, tick trap overhead dominates).
- [x] **WASM build + browser test of C3** — 2026-08-16.
  - `make CC=emcc wasm_defconfig` + `CONFIG_SYSTEM=y CONFIG_ELF_LOADER=y CONFIG_ESP32_C3=y` (no SDL).
  - wasm 631 KB + js 70 KB (no embedded demos/DTB in ELF-loader mode). ~100–115 M cycles/s in wasm (faster than
    native due to block chaining).
  - Fixed mk/wasm.mk: DTB embed only when `!CONFIG_ELF_LOADER` (C3 needs no /minimal.dtb; system wasm mode needs it).
  - Node headless test + headless-Chrome CDP test pass: full ROM banner, bootloader, app to idle task.
  - Browser glue: `system.html` gained "Run ESP32-C3 App" button (fetches esp32c3/{elf,merged.bin}, writes MEMFS);
    `system-pre.js` gained `run_esp32c3(elf, flash)` → `callMain(['-C','esp32c3','-F',flash,elf])`.
  - Demo: `make prepare-web` or serve `demo/system/` (dev server: `python3 tools/dev-server.py --directory demo`),
    open http://127.0.0.1:8000/system/system.html.
  - Note: rebuilding wasm after native and vice versa needs `rm -rf build/softfloat build/devices` (archive/objects
    are toolchain-specific; make does not detect the toolchain switch).
- [x] Phase 3: Port SoC layer to C6 (adds 802.15.4, USB-serial-JTAG, TWAI).
  - Peripheral work done via arduino-cli-built test sketches (fqbn esp32:esp32:esp32c6),
    each verified against the model: I2C, SPI, UART RX (host `-U` injection), GPIO
    (virtual button pin 7), GPTIMER, ADC (adc_oneshot), RMT TX, LEDC, TSENS, CAN (TWAI RX),
    PCNT (pulse counting from the virtual button via GPIO matrix FUNC_IN_SEL),
    MCPWM (timers 0..peak with up/down/updown modes, generator events utez/utep/ucmp/
    dtep/dtez/dcmp, continuous + one-shot force levels; pins routed via FUNC_OUT_SEL
    to PWM0_OUT{0,1,2}{A,B} = signals 87..92).
  - WASM build (`make CC=emcc wasmc6_defconfig` + `make CC=emcc`) verified headless in
    node: C6 firmware boots to setup()/loop() and produces identical peripheral test
    output (e.g. pcnttest `PCNT_GET 0 count=8`). 2026-08-19.
  - Browser demo for C6: added "Run ESP32-C6 App" button (pcnttest firmware) to
    demo/system/ via assets/wasm/js/system-pre.js `run_esp32c6` + system.html;
    firmware at demo/system/esp32c6/. 2026-08-19.
  - MCPWM model verified 2026-08-19: mcpwmtest measures lo% via digitalRead over 10 ms
    — 50/25/75% duty at 1 kHz, continuous force pins to 100%, release restores PWM.
    Also fixed LEDC pad routing: FUNCx_OUT_SEL index read was 0x554 instead of 0x91554
    (tests passed by coincidence), pins now reset to SIG_GPIO_OUT (0x80) like real HW.
  - RMT RX model verified 2026-08-19 (commit 78fbe54): rmtrxtest receives the virtual
    pulse source on pin 6 (high 2^17 cycles, low rest of a 3*2^20-cycle period) via
    GPIO matrix FUNC71_IN_SEL; per-transition symbols {level,duration} are written into
    the channel memory (0x6580/0x6640 for HW channels 2/3), the chmstatus writer offset
    is maintained, and RX_END (raw bit 2+c) frames the message after idle_thres ticks;
    the driver ISR copies the symbols straight from channel memory. Measured high pulse
    = 819 ticks exactly at 1 MHz resolution (80 MHz PLL_F80M source, div 80: step =
    2*div emulated cycles). Full regression: 13/13 tests pass headless in wasm.
  - Browser demo upgrade 2026-08-19: the C6 demo firmware is now `demotest` — a single
    sketch exercising GPIO/PCNT (15 pulses on the virtual button), LEDC + MCPWM PWM
    (50% duty measured via digitalRead), RMT RX (819-tick pulse on pin 6), I2C scan
    (finds the virtual 0x50 device), SPI (JEDEC ID), TWAI (virtual frame 0x123 DE AD),
    TSENS (temperature) and ADC — prints a full report ending with DEMO_DONE.
     demo/system/esp32c6/ + demo/system/rv32emu.{js,wasm} refreshed (wasm now includes
     the RMT RX model).
  - **CRITICAL FIX 2026-08-22: interrupt controller UB miscompile + bit-69 (I2S DMA TX)**.
    `intc_status` was declared `uint64_t` but `esp32_intc_raise` loops `s < 72` and does
    `soc->intc_status |= (1ULL << s)`. Shifts by 64..71 on a 64-bit type are UB, which
    `-O3` (plus `-mtail-call`) exploited to miscompile `esp32_intc_raise` into a
    void/noreturn stub, so `esp32c6_check_interrupt` became `call esp32_intc_raise;
    unreachable` → `RuntimeError: unreachable` on the first check with MIE=1 (the boot
    crash). Worse, a 64-bit status **cannot represent source 69** (`C6_DMA_OUT_CH0_INTR_-
    SOURCE`), so the I2S DMA TX interrupt could never be set/delivered → i2stest timed out
    with err=263. Fixes in src/esp32c6.c:
      1. `uint64_t intc_status` → `__uint128_t intc_status` (sources 0..127).
      2. All pending/set/test shifts made 128-bit-safe (`((__uint128_t)1) << s`, incl. the
         EMIP read path) via replaceAll of `1ull << ` / `1ULL << `.
      3. `mcpwm_reg[76]` → `mcpwm_reg[128]` (was indexed at 101/102 → OOB UB).
      4. Tautological `(o & 0xFu) == 0x10u` → `(o & 0xFu) == 0x0u` (always-false compare).
      5. Debug counters: `dbg_trap_deliv` was a set-but-unused static redeclared at use
         site (made a single global); removed unused `delta` in RMT RX.
    After fix, `-O3` esp32c6.o disassembles with a *full* `esp32c6_check_interrupt` body
    (no `unreachable` in the interrupt path; remaining `unreachable`s are only in
    esp32c6_new/esp32c6_boot assert paths).
  - **i2stest PASSES end-to-end (headless node) 2026-08-22.** Run method that actually
    executes the guest: the bundle sets `Module["noInitialRun"]=true`, so bare
    `node build/rv32emu.js -C esp32c6 -F x` does NOT run main. Instead mount the firmware
    into MEMFS and call the exported harness:
    `Module.FS.writeFile('/flash.bin', bin); Module.run_system('-C esp32c6 -F /flash.bin')`
    (inside `onRuntimeInitialized`; stub `globalThis.document = {getElementById:()=>({disabled:false})}`
    to satisfy the browser UI helpers `_disable/_enable_run_button`). Captured output:
    `i2stest: starting` → four `write N: err=0 written=960` → `i2stest: OK` → `DEMO_DONE`.
     This confirms bit-69 DMA-out interrupt delivery works (4 sequential writes cycle the
     descriptor ring twice). Headless does not self-exit (guest idles after DEMO_DONE);
     wrap in `timeout` and capture console.log to a file.
   - **I2S RX (GDMA IN channel + I2S RX engine) implemented & verified 2026-08-22.**
     The model previously had GDMA OUT + I2S TX only. Added the mirror IN path:
       * GDMA `in_intr[3]` (device 0x60080000+0x00..0x2F: RAW/ST/ENA/CLR at
         0x00+0x10*ch) and the IN block (in_conf0/in_conf1/infifo_status/in_link/
         in_state/in_suc_eof_des_addr/in_dscr/in_pri/in_peri_sel at channel base
         0x70 + 0xC0*ch). `in_link.start = bit 22` arms the walker; `in_conf0.in_rst`
         (bit 0, WT) resets the RX FIFO + walker.
       * I2S `RX_CONF` (0xC020) `rx_start` (bit 2) kept set so the RX engine runs
         (mirrors TX_CONF at 0xC024).
       * Periodic-update RX engine: when `rx_start` is set and the walker is armed, it
         synthesizes **one 32-bit sample per 256 cycles** into a 12-word RX FIFO (a
         monotonic counter 0,1,2,… — left = word, right = word>>16), copies FIFO words
         into the current descriptor buffer, and on descriptor completion raises
         **IN_SUC_EOF (bit 1)** of `in_intr` + `intc_status` bit **66+ch**
         (`C6_DMA_IN_CH0_INTR_SOURCE = 66`); the descriptor ring is walked via DW2 and
         parked when the next pointer is 0.
       * New `esp32c6_gdma_load_rx_desc` mirrors `esp32c6_gdma_load_desc` but loads into
         the rx_* walker fields.
     Sketch `sketches/i2srxtest/i2srxtest.ino` opens an I2S0 std RX channel (note:
     `i2s_new_channel(cfg, *tx, *rx)` — RX is the 3rd arg, not 2nd) and reads 4×960 B,
     asserting each 32-bit word equals the expected counter. Headless result: four
     `read N: err=0 read=960` → `i2srxtest: OK` → `DEMO_DONE`. The synthesized-counter
     stream is sufficient to validate the DMA-in + interrupt + descriptor-walk path;
     real codec data can replace the synth later. Debug `fprintf` scaffolding from this
     session was stripped after verification (the per-descriptor `RX EOF` print alone
     emitted ~7k lines).
   - **MWDT (Timer Group Watchdog) implemented & verified 2026-08-22.** Modeled the
     ESP32-C6 MWDT0/MWDT1 inside the existing TIMG0/1 region (0x60008000 / 0x60009000):
     `WDTCONFIG0` (0x48, `wdt_en` bit31 + stage0 action bits29-30), `WDTCONFIG1` (0x4c,
     `wdt_clk_prescale` bits[31:16]), `WDTCONFIG2` (0x50, `stg0_hold`), `WDT_FEED`
     (0x60), `WDTWPROTECT` (0x64, unlock key `0x50D83AA1`). Writes are gated on the
     write-protect unlock (faithful to HW). When armed and the expiry cycle passes
     without a feed, the combined TIMG `INT_RAW` (0x74) bit 1 (WDT) is set and, if the
     WDT interrupt is enabled in `INT_ENA` (0x70), the group's WDT source is raised
     (`C6_TG0_WDT_INTR_SOURCE = 52`, `C6_TG1_WDT_INTR_SOURCE = 55`). Feeding or
     disabling clears the raw bit and the pending source. A `wdt_cycles` helper
     approximates the timeout as `stg0_hold * (prescale+1) * 2` guest cycles (WDT ~40 MHz
     vs the ~80 MHz guest cycle clock). Sketch `sketches/wdtlintest/wdtlintest.ino`
     unlocks + arms MWDT0 with a short stage0-interrupt timeout, polls `INT_RAW` until
     the WDT bit sets (`wdtlintest: FIRED`), feeds the dog, and confirms the bit clears
     (`after feed raw cleared=1`) → `wdtlintest: OK` → `DEMO_DONE`. Note: the model
     raises the interrupt source but does not perform the CPU/system reset that a real
     WDT stage2/3 would trigger (that would be destructive in the emulator); stage0
     interrupt behavior is what is exercised here. RNG (0x600B2808 WDEV_RND_REG) and
     TWAI TX + GPIO input interrupts were found to already be modeled — RNG via a
     xorshift PRNG seeded by the SYSTIMER counter, TWAI TX via `twai_tx_pending`, and
     GPIO ISRs via the virtual-button → per-pin `GPIO_PINn` type/enable → `gpio_status`
      + source 30 path.
    - **UART1 (ESP32-C6 has only UART0 + UART1) MMIO model + TX→RX loopback,
      verified 2026-08-22.** Generalized the previous UART0-only model to a
      2-port array (`uart_rx[2]`, `uart_rx_head[1]`, `uart_rx_tail[1]`). Key
      facts learned:
        * UART register windows are at the **APB** bases `0x60000000` (UART0)
          and `0x60001000` (UART1 = `DR_REG_UART_BASE + 0x1000`); the AHB
          alias `0x60010000` collides with the **interrupt matrix** and must
          NOT be used for UART. (Caught this the hard way — mapping UART1 to
          0x60010000 hijacked the matrix MMIO and crashed every interrupt.)
        * Loopback is CONF0 bit 12. On a TX-FIFO write with loopback set, the
          byte is pushed into that port's RX FIFO and `INT_RAW` RX bits
          (RXFIFO_FULL 0x1 | RXFIFO_TOUT 0x100) are raised, which makes the
          esp-idf uart RX ISR drain the FIFO into the driver ring buffer.
        * Added `uart_tx_cnt[2]`/`uart_tx_idle[2]` + a paced **TXFIFO_EMPTY**
          (bit 1) interrupt in the periodic update so the driver's TX ISR is
          actually triggered to drain its ring buffer (the model reports the TX
          FIFO as always-empty).
      Sketch `sketches/uart1regtest/uart1regtest.ino` pokes UART1 FIFO/CONF0
      directly and asserts equality → `uart1regtest: OK` → `DEMO_DONE`.
      Critically, the loopback bit is in **`conf0_sync` at offset 0x20**, NOT
      `conf0` at 0x14 (0x14 is now `clkdiv_sync`). The earlier "the driver
      never writes the FIFO register" theory was wrong — the real bug was the
      loopback register offset. With it fixed, the **full esp-idf driver**
      works end-to-end: `sketches/uart1e2e/uart1e2e.ino` uses `Serial1` +
      `uart_set_loop_back(UART_NUM_1, true)`, writes 22 bytes, reads them back
      (`uart1e2e: wrote=22 read=22` → `uart1e2e: OK`). Regression: `i2srxtest`
      and `wdtlintest` still pass.

    - **AES hardware accelerator (0x60088000) modeled + verified 2026-08-22.**
      Added a 256-byte `aes_reg[]` bank and a from-scratch FIPS-197 block
      cipher (SubBytes/ShiftRows/MixColumns + equivalent-inverse for decrypt,
      full key schedule; ECB + CBC chaining). The trigger write (0x48) runs the
      transform **synchronously** (state stays idle) so the esp-idf driver's
      busy-wait on the state register sees the result immediately. Encrypt/
      decrypt for 128/192/256 and CBC verified against FIPS-197 / NIST
      SP800-38A vectors via `sketches/aesregtest/aesregtest.ino` (direct
      register pokes): `AES128 ECB enc/dec`, `AES256 ECB enc`, `AES128 CBC enc`
      all → `aesregtest: OK`. Byte order follows the esp-idf `aes_ll`
      convention (word `i = b0<<24 | b1<<16 | b2<<8 | b3`, no swapping).
      Gotcha: the high-level **mbedtls AES API hangs** because the esp-idf
      `esp_aes` driver feeds the peripheral via **GDMA** (the AES GDMA trigger
      exists but is not modeled); only software/poll-mode (register) access
      works. Verified at the register level only.
    - **I2S0 (ESP32-C3) TX + RX via GDMA modeled & verified 2026-08-30.**
      I2S0 at `0x6002D000` (`DR_REG_I2S_BASE`), interrupt source 38.
        * Register model: `i2s_reg[32]` + `i2s_rx_counter` for synthesized RX.
        * MMIO read: INT_ST = raw & ena, STATE = 1 (tx_idle), DATE = 0x26062022.
        * MMIO write: INT_CLR W1C at 0x18, self-clearing `tx_update` (bit 8 of
          TX_CONF 0x24) and `rx_update` (bit 8 of RX_CONF 0x20).
        * GDMA FIFO status: INFIFO_STATUS/OUTFIFO_STATUS at block offset 0x08
          return 0x02 (empty); IN_POP/OUT_PUSH at 0x0C return 0.
        * GDMA unpaired peripheral DMA: INLINK_START and OUTLINK_START schedule
          `gdma_m2m_pending` + `gdma_m2m_done_cycle` when paired channel isn't
          running. Completion fires IN_SUC_EOF or OUT_EOF, advances descriptor
          chain, re-arms for circular DMA.
        * I2S0 GDMA peripheral select = 3 (confirmed via debug traces).
        * Critical fix: `gdma_in_dscr`/`gdma_out_dscr` must be updated on each
          descriptor advance; otherwise `in_suc_eof_des_addr` returns the wrong
          address and the driver's ISR reads stale data.
        * Critical fix: `gdma_int_ena` write re-checks pending raw bits so
          interrupts set before ENA is enabled are not lost.
        * GDMA FIFO status registers (INFIFO_STATUS at IN block 0x08, OUTFIFO
          at OUT block 0x08) added so the I2S driver's channel init doesn't hang.
      Sketches: `i2stest` (4×960 B TX writes) and `i2srxtest` (4×960 B RX
      reads checking monotonic counter 0,1,2,...,959). Both pass headless:
      `i2stest: OK`, `i2srxtest: OK`, `DEMO_DONE`. Committed `abfb4f5`.

- [x] **ESP32-C6 peripheral bring-up — verified via arduino-cli sketches on the WASM emulator** (2026-08-22):
      - **AES** (`aestest`): ECB/CBC enc+dec for 128/192/256 → `aestest: OK`. Hang
        fixed: `esp32c6_aes_run_dma` now writes back the GDMA OUT/IN descriptors
        (clears owner bit dw0[31], sets EOF/SUC_EOF) so the esp_aes driver's
        descriptor-owner poll exits; AES INT_CLR (0xB8) write clears source 73.
        Also removed debug-print floods (DBG_R + trap/CSR prints) → ~70 KB/run.
      - **UART1** (`uart1loopbacktest`/`uart1regtest`/`uart1e2e`): TX/RX loopback OK.
      - **I2C master** (`i2ctest`, new sketch): write 8 → virtual EEPROM @0x50 →
        read 8 matching bytes OK. Model already correct (base 0x60004000).
      - **I2S RX** (`i2srxtest`): 4×960-byte GDMA reads OK.
      - **WDT / timers** (`wdtlintest`): arm → FIRED → feed clears raw OK.
      - **SPI master** (`spitest`, new sketch): loopback echo + virtual-SRAM R/W OK.
        Model at 0x60081000 (base confirmed for C6 `SPI`/`GPSPI2`).
      - **CAN/TWAI** (`twaitest`, new sketch, ESP-IDF `driver/twai.h`): virtual node
        frame (ID 0x123, DLC 2, DE AD) received OK + TX completion OK. Model @0x6000B000.
      - **GPIO** (`gpiotest`): output→input readback (GPIO_IN = gpio_in | gpio_out&enable)
        OK. Model @0x60091000.
      - **ADC** (`adctest`): oneshot `analogRead(0)` returns 1024 (model: 1024+ch*128 for
        ADC1 ch0-7) OK. Model @0x6000E000.
      - **LEDC** (`ledctest`, new `ledcAttachChannel`/`ledcWriteChannel` API): duty latched
        into DUTY_R on CONF1.start, DUTY==DUTY_R OK. Model @0x60007000.
      Sketches built under `/tmp/opencode/{aestest,uart1test,uart1regtest,
      uart1e2e,i2srxtest,wdtlintest,i2ctest,spitest,twaitest,gpiotest,adctest,ledctest}`.
       All run clean (~65-70 KB/run, no interrupt storms).
       - **I2C multi-byte register addressing** (`i2cregtest`, new sketch): the
         model changed from naive loopback to a register-addressed EEPROM. Write
         txns use tx_fifo[1] as the register address and auto-increment; reads
         return from the current pointer. The Arduino Wire `endTransmission
         (false)`+`requestFrom` emits a combined repeated-start `[WADDR,REG,
         RADDR]` which the pump now decodes as set-pointer-then-read. `i2ctest`
         (reg0 = 0x11..0x88) and `i2cregtest` (reg0x05 = AA BB CC) read back OK.
       - **SPI JEDEC ID** (`spijedectest`, new sketch): the SPI2 virtual device
         now returns the 3-byte ID (0xEF 0x40 0x15) within the same transfer
         (manufacturer byte clocks out during 0x9F; later clocks return
         type/capacity; stateful continuation handles the one-byte-per-xfer path
         the Arduino SPI lib uses). `spijedectest: manuf=ef type=40 cap=15 OK`.
       - **GPIO interrupt** (`gpiointtest`, new sketch): edge detection now runs
         on the *live* input (gpio_in | gpio_out&gpio_enable), so a pin driven
         as output and toggled raises its own pad-input edge. 5 rising edges on a
         self-loopback pin fire 5 ISR calls (`gpiointtest: ints=5 OK`). The old
         virtual-button→GPIO_PINn type/enable edge path is now shared via
         `esp32c6_gpio_edge_check`.
       - **ADC2 / SAR2** (`adc2test`, new sketch): C6 exposes only ADC_UNIT_1 via
         the driver (SOC_ADC_PERIPH_NUM==1), so a unit-2 `adc_oneshot` is invalid;
         the SARADC peripheral still has a 2nd converter (SAR2, bit30 of 0x20).
         Exercised directly: onetime start with bit30 sets 0x30 to 1024+ch*128
         and int_raw bit30 → `adc2test: raw=1024 OK`.
        NOTE: full `esp_light_sleep_start()` (PMU power-down) is NOT yet emulated —
        the firmware busy-waits on an unmodeled PMU FSM status register and hangs.
        The GPIO *interrupt* path (the actual wake mechanism) is verified above;
        PMU/RTC sleep + WFI resume is a separate, larger feature.
- [x] Phase 4: H2 SoC layer (`src/esp32h2.c`, new) — 2026-09-04.
  - C6-style dispatch with corrected H2 bases (RMT 0x7000, LEDC 0x8000, TIMG0
    0x9000, TIMG1 0xA000, SYSTIMER 0xB000, TWAI 0xC000, I2S 0xD000) and H2
    interrupt sources (SYSTIMER_T0 45/T2 47). Added missing
    `esp32h2_periodic`/`check_interrupt` hooks in `src/emulate.c`.
  - Verified headless (node): arduino-cli hello (`esp32:esp32:esp32h2`) boots:
    `rst:0x1 (POWERON)`, `entry 0x4083c2d0`, `HELLO_UART_OK`, then `TICK`.
- [x] Phase 5: P4 SoC layer (`src/esp32p4.c`, new) to Arduino HELLO+TICK — 2026-09-04.
  - Real P4 ROM linked (`src/esp32p4_rom.h`, wokwi dump, alias 0x4FC00000);
    P4 map (SRAM 0x4FF00000, flash window 0x40000000, MMIO 0x50000000) with
    `p4_xlate()` onto the C6-style dispatch; MCYCLE/MINSTRET CSRs; cache/QIO/
    SHA/AES/GDMA stubs sufficient for boot.
  - Interrupt fixes: INTMTX MAP holds `line+16` (ROM adds 0x10; 0=unmapped);
    CLIC model at 0x20800000 (all-vectored via MTVT address table, deliver
    when level>=threshold); crosscore/yield source 79 cleared on delivery.
  - Core fix (`src/emulate.c`): enforce `X[0]=0` after each block — unguarded
    RVOP handlers (e.g. MUL) clobbered x0 and tripped the constopt assert.
  - Unicore test scaffold (`tools/p4_mkunicore.py`, re-signs SHA256): nops
    CPU1 boot/rendezvous waits, flash-stall IPC retry, pins loopTask to CPU0.
    (Real SMP is future work; unpatched dual-core images still wait on CPU1.)
  - Verified headless (node, `-C esp32p4`, postv3 variant + patched image):
    `rst:0x1 (POWERON)`, `entry 0x4ffac2c0`, `HELLO_UART_OK`, then steady
    `TICK` (FreeRTOS tick + yield interrupts delivering, tasks switching).
- [ ] Phase 8: dual-core SMP for P4 (scaffolding landed 2026-09-10, dual boot WIP).
  - New chip variant `-C esp32p4smp` (main.c): boots/schedules the APP
    CPU. Plain `-C esp32p4` is unchanged single-hart (unicore-patched
    images keep working; full P4/H2/C3 matrix re-verified green).
  - Landed in src/esp32p4.c + emulate.c + riscv_private.h + main.c:
    second `riscv_t` (hart1, mhartid CSR now per-hart), shared SoC with
    per-hart CLIC views / per-CPU INTMTX MAPs (CPU1 @0x500D6800) /
    per-hart CLINT MSIP/MTIMECMP, FROM_CPU_INT1 (source 80) + INT0/INT1
    regs, APP-CPU boot mailbox 0x50110164 (found by disassembling ROM
    `ets_set_appcpu_boot_addr`), time-sliced alternation in rv_step,
    per-hart block-chaining swap + map-clear guards, WASM halt-epilogue
    only on hart0, heap-allocated `vm_attr_t` (was stack-use-after-
    unwind: shared fields flapped nondeterministically once two harts
    changed stack-reuse patterns).
  - Verified: unpatched postv3 hello boots dual ROM, hart1 parks +
    releases via mailbox, MAP1/CLIC1 program, crosscore ISR delivers
    (line-0 routing), both harts reach scheduler bringup.
  - NOT YET: unpatched HELLO+TICK. hart1 aborts at its first scheduler
    yield (`xPortStartScheduler` returns): its first task switch finds
    current==next (pxCurrentTCBs[1] preset to the ipc task at creation)
    so no switch happens. Suspect boot-ordering race: hart1's lean
    bringup path outruns hart0's loopTask creation under fair per-block
    alternation (on HW, slow init calibrations likely order it the other
    way). Holding hart1 for loopTask deadlocks the other way (main_task
    waits s_other_cpu_startup_done first). Next: find what makes the
    first switch select a runnable task (IDLE-1 existence? creation
    order?) or pace hart1 (e.g. realistic init delays) — do NOT paper
    over with scheduling gates; both directions deadlocked in testing.
  - Perf: INTMTX pending bits are u64 pairs now (was __uint128_t →
    emcc libcalls in the per-block check, ~100x). Quantum stays 32M
    (50K experiment reverted; CDP socket timeout raised to 300
    instead). Demo P4 (patched) still boots in-browser (CDP TICK).
  - Validation (when dual boot lands): unpatched postv3 hello prints
    HELLO+TICK with main and loopTask on different cores (check
    `pxCurrentTCBs[0/1]`).
  - LANDED 2026-09-11: unpatched dual boot works on the fixed emulator
    (`fw/p4smp/unpatched.bin`, no F1/S7'): 1 HELLO + 46 TICKs over
    5 min, zero faults. The old blockers (ipc0 portMAX_DELAY lock wedge
    vs hart1's first switch; main_task self-delete lock leak) do not
    manifest — with TARGET1 ticks, real critical-section masking, and
    working LR/SC, hart1 makes progress and main's self-delete
    completes (a main abort would park hart0, stop T0 ticks, and freeze
    TICKs; TICKs continue linearly). Functional proof of split: TICKs
    print (loopTask is core-1-affined, runs only on hart1) while T0
    ticks advance delays (hart0); DIAG shows per-core IDLEs
    (tcb=[IDLE-0, IDLE-1]). No emulator or patcher change was needed —
    F1/S7' remain a faster bringup scaffold only. Next: WASM SMP demo
    entry, then peripherals on SMP / real IPC.
  - DONE 2026-09-11: WASM SMP demo entry. `run_esp32p4smp` glue in
    `assets/wasm/js/system-pre.js` + "Run ESP32-P4 SMP App" button in
    `assets/wasm/html/system.html` (incl. enabling it in
    `onRuntimeInitialized`), serving the stock unpatched dual-core
    image (`demo/system/esp32p4smp/p4hellov3.ino.{elf,merged.bin}`).
    Verified headless-Chrome CDP: button click → HELLO_UART_OK in 27 s
    (node equivalent also green). Note: `tools/cdp_boot_test.py` binds
    fixed ports 8932/9331 — a killed run leaves a stale dev-server
    squatting on 8932 and later runs fail with "button never enabled";
    use fresh ports or clear strays first.
  - DONE 2026-09-11: real IPC on SMP, no FW patches. New sketch
    `fw/p4ipc/p4ipc.ino` (arduino-cli, `esp32:esp32:esp32p4`,
    `ChipVariant=postv3`): setup prints HELLO, runs
    `esp_ipc_call_blocking(1, fn, 1..2)` twice, checks
    `e1==e2==ESP_OK`, count==3, ran-on-core==1 → `IPC_DONE`, then loop
    TICKs. Unpatched `merged.bin` on `-C esp32p4smp` prints
    `IPC_RES 0 0 3 1`, `IPC_DONE`, plus steady TICKs first try — the
    full crosscore path works with infinite-wait ipc tasks (hart0 send
    → hart1 crosscore ISR → ipc1 notify-take → fn → ack). This retires
    the F1/S7' failure theories (they were diagnosed pre-MINTTHRESH /
    pre-TARGET1 / pre-LRSC-fix); `tools/p4_mksmp.py` marked superseded
    but kept. Next: SMP peripheral proof (below), then WiFi/BLE stubs last.
  - DONE 2026-09-11: SMP peripheral proof, no emulator change needed.
    Extended `fw/p4ipc` so the APP-core `ipc_fn` drives GPIO8 high,
    reads back the pad input, and drives low; setup requires the
    readback: `IPC_RES 0 0 3 1 1` + `IPC_DONE` + steady TICKs on
    `-C esp32p4smp`, unpatched. GPIO driven and observed from hart1
    through the existing OUT-echo model.
  - DONE 2026-09-11: full peripheral matrix on dual-core, unpatched
    `merged.bin` images, `-C esp32p4smp`, zero faults everywhere:
    gpio/gptimer/i2c/spi/adc/ledc/twai/pcnt/mcpwm/tsens/rmt/rmtdir/
    rmtleg/rmtrx/i2s/i2stx/hello/ipc DONE markers all green (uart via
    native `-U rxfile`: `UART_GOT 4 PING` + `UART_DONE` both unicore
    and SMP). Key fix this round: per-hart cycle-counter divergence
    wrapped TIMG/SYSTIMER/LEDC/MCPWM time-delta math (u64 underflow
    exploded the TG0 counter past its alarm → 200k/s level-locked
    interrupt storm on hart1 that also starved every LR/SC window);
    all delta accumulations now clamp future anchors to zero elapsed.
    Methodology notes: stale Sep-5 `patched.bin`s had masked this
    (regenerated with current patcher first); `grep -c PATTERN` over
    counts on CRLF logs — anchor with `$'...\r?$'`; box load swings
    wall-time 3-10x, use generous timeouts. Follow-up: node/WASM uart
    RX feeding never worked (`/uartrx` written but rx path unset in
    WASM) — native `-U` is the working path.
  - Breakthrough 2026-09-11: dual HELLO+TICK on `-C esp32p4smp` with the
    scaffolded image (`tools/p4_mksmp.py` F1+S7', `fw/p4smp/smp.bin`):
    hart0 runs main_task (parks after setup), hart1 runs IDLE-1 + ipc1 +
    loopTask (TICKs via delay). Native HELLO + steady TICKs, no panics;
    WASM boots to HELLO with main parked (slower, no crash yet). Real
    emulator bugs fixed (all in normal code paths, TEMP tracing since
    removed): (1) core ignored CLIC MINTTHRESH (0x347 — the SMP port's
    critical-section mask), so ticks preempted takes and register spills
    smashed tick_cb/idle_cb with wild hook pointers (0x03ffffff,
    data addrs); new `csr_mintthresh` per hart, honored in P4 CLIC
    arbitration. (2) CLIC level was `CTL>>5` compared against raw
    threshold bytes, so take()'s 127 never masked anything; compare in
    level domain (`>>5` both sides: idle 31→0 fires-all like baseline,
    take 127→3 masks levels 0-3 incl. tick/yield). (3) SYSTIMER TARGET1
    unmodeled (hart1's tick; guest enables T0+T1, ena=0x3) → hart1 never
    ticked, hart0's crosscore handshake waited full s6 timeout every
    tick (~1 Hz); added comp1/conf/crossed state, source 54, INT_CLR
    bit1, with the CPU interrupt gated on INT_ENA like HW (guest arms
    T1's comparator while enabling only T0 — ungated T1 spuriously
    wedged unicore gptimer/i2c). (4) LR/SC had no reservation: `sc.w`
    always succeeded, so both harts held xKernelLock at once; now
    value-based (`lr_value`/`lr_valid` in riscv_private.h). (5) trap
    handler never yields spinning SMP traps: 20000-insn pause budget in
    `__trap_handler` (resume next schedule). Scaffolding kept in the FW
    patcher only: F1 ipc wait -1→31 ticks (1 tick overloaded the lock
    into per-tick full handshake timeouts), S7' main suicide→park
    (self-delete wins a same-block race vs the pending yield ISR and
    main "returns" into `panic_abort`; also fixed S7' byte order —
    `01a00100`, the old `a0010100` decoded as addi4spn+nop and fell
    through). Also fixed: native `-Werror` breakage (H2_SRAM_SIZE
    rename, AES/`Nb` cleanups) and a `.config` footgun (wasm defconfig
    + native make silently misbuilds; always `rm -rf
    build/softfloat build/devices` + re-apply defconfig when switching
    toolchains; plain `make` needs `CC=gcc` once `.config` says WASM).
    Follow-up: peripheral matrix re-verified green on current code
    (native hello/gpio/gptimer/i2c DONE, node hello+TICKs/uart+RX/gpio,
    node SMP HELLO) after regenerating all `patched.bin` with the
    current unicore patcher (Sep-5 images were stale). Methodology: this
    box runs other tenants' emulators at ~100% CPU (load 3-6); wall-time
    test windows flake — use 40-100 s timeouts and confirm by log
    content, and always verify the binary is fresh (`strings` check)
    after toolchain switches. Still scaffolded, not upstream-clean:
    S7'/F1 guest patches, trap-pause budget, no WASM SMP demo entry
    yet. Next: rate (~1 TICK/20-30 s native; batching periodic 8-64x was
    tried and reverted — unsafe), then unpatched dual boot (needs real
    IPC progress, not F1 polling).
- [x] Phase 6: P4 peripheral verification with arduino-cli test sketches
  (`esp32:esp32:esp32p4:ChipVariant=postv3`, each unicore-patched) — in progress.
  - **GPIO** (`p4gpio`): `GPIO_OUT 1 0` (echo readback), `GPIO_INT 1`
    (self-loopback rising edge), `GPIO_DONE`. Model fix: P4 OUT_SEL is
    9 bits, SIG_GPIO_OUT_IDX=256 (was treated as 8-bit/0x80).
  - **UART** (`p4uart`): TX prints plus RX of MEMFS-preloaded bytes
    (`P4_RX_FILE` env -> `/uartrx`, `-U /uartrx`): `UART_GOT 4 PING`.
    (Host fifos are invisible to WASM; run_p4.js preloads instead.)
  - **GPTIMER** (`p4gptimer`): 1 MHz periodic 100 ms alarm ISR fires 5x,
    no model change needed.
  - **I2C** (`p4i2c`): scan finds `0x50`, write 8 + readback `11..88`
    exact, no model change needed.
  - **SPI** (`p4spi`): JEDEC `EF 40 15` (manuf clocks out during `0x9F`,
    as on C6), no model change needed.
  Sketches live under `/home/danish1075/fw/p4{hello,gpio,uart,gptimer,i2c,spi}/`.
- [x] Phase 6 (cont.): more P4 peripherals — 2026-09-06.
  - **ADC** (`p4adc`): LP_ADC (0x50127000) was unmodeled so calinit hung
    polling MEAS DONE; now instant-complete with channel DATA
    (1024+ch*128). `ADC_READ 0=1024 3=1408`, `ADC_DONE`.
  - **LEDC** (`p4ledc`): P4 output signals are 126-131 (not 0-5);
    `LEDC_DUTY 128`, LO ~49% at 1 kHz/8-bit.
  - **TWAI** (`p4twai`): virtual RX frame + TX, no model change:
    `TWAI_RX 123 2 DE AD`, `TWAI_TX OK`.
  - **PCNT** (`p4pcnt`): input signals are 141+4u+2ch (not 101+);
    `PCNT_COUNT 8`, `PCNT_DONE`.
  - **MCPWM** (`p4mcpwm`): outputs are signals 89-94 (not 87-92), 9-bit
    OUT_SEL mask; `MCPWM_LO ~50%`, `MCPWM_DONE`.
  - **TSENS** (`p4tsens`): LP_TSENSOR (0x5012F000) instant-ready, raw 120:
    `TSENS_READ OK 32.0`.
  - Parked (need dedicated passes): **RMT TX** — RESOLVED 2026-09-08,
    see below (test sketches were missing `rmt_enable()`, not a model
    bug) — and **I2S RX** (driver never sets RX_START nor programs GDMA;
    I2S0 remapped to the 0x6000C000 block with self-clearing UPDATE).
  - RMT/I2S deep-dive findings 2026-09-08: new-driver `rmt_transmit`
    returns OK having only enqueued (polls an event queue, takes the
    empty path); `rmt_tx_do_transaction` runs ONLY from TX ISRs, so the
    first kick never happens — no CONF0 writes, no AHB/AXI GDMA writes
    at all. Legacy RMT driver stalls in config/install (softfloat-heavy
    retry-looking loop, never reaches transmit). I2S RX: no GDMA writes
    (AHB 0x50081000 nor AXI 0x5008A000), RX_START bit never set; read
    times out. Common thread to investigate: what gates the drivers'
    first DMA/START programming (likely a clock/reset/event handshake
    the model doesn't satisfy, not the register offsets which are now
    correct per TRM headers).
    (Update 2026-09-08: both premises were wrong — RMT TX was a missing
    `rmt_enable()` in the sketches, and I2S RX was three model bugs:
    I2S handler at `0xC000` vs xlate `0xD000`, AHB_GDMA at `0x50085000`
    not `0x50081000`, AHB link START/ADDR regs. See fix entry below.)
- [x] Phase 7: H2 peripheral matrix (no unicore patch needed, single-core
  chip) + browser demo — 2026-09-08.
  - H2 verified headless, all first-try green: GPIO (`OUT 1 0`, `INT 1`),
    UART RX (`GOT 4 PING` via `H2_RX_FILE` MEMFS preload in run_h2.js),
    I2C (scan `0x50`, rd `11..88`), SPI (`JEDEC EF 40 15`), ADC
    (`0=1024 1=1152`), GPTIMER (5 alarms), LEDC (`DUTY 128`, LO ~49%),
    PCNT (`COUNT 8`), TSENS (`32.0`), MCPWM (`LO ~50%`). RMT TX same
    stall as P4 (`TX OK`, `WAIT FAIL`); parked with P4 RMT.
  - Browser demo: `run_esp32h2`/`run_esp32p4` glue (system-pre.js), buttons
    + handlers (system.html; P4 flash is the unicore-patched image),
    firmware under demo/system/esp32h2 + esp32p4. printErr now goes to
    the browser console only (was corrupting the guest UART terminal).
    `tools/cdp_boot_test.py` drives headless Chrome over CDP
    (click-to-boot, xterm scrollback match via `window.__espTerm`).
    Verified: page loads clean, P4 boots in-browser with TICKs.
- [x] Phase 6 (cont.): RMT TX + I2S RX root-caused and fixed — 2026-09-08.
  - **RMT TX was a sketch bug, not a model bug.** Both `p4rmt` and `h2rmt`
    sketches called `rmt_transmit()` without `rmt_enable()`; IDF queues
    the transaction and returns OK but the FSM never leaves ENABLE so
    `rmt_tx_do_transaction` never runs (no CONF0/GDMA writes — the
    "parked" trace). Fix: one line `ESP_ERROR_CHECK(rmt_enable(ch))`
    in `/home/danish1075/fw/p4rmt/p4rmt.ino` + `h2rmt/h2rmt.ino`
    (rebuilt + re-patched). Now `RMT_TX OK`, `RMT_WAIT OK` on P4 and H2;
    direct-HAL `p4rmtdir` still `TXEND SET`; `p4rmtrx` still `DONE n=32`.
    No emulator change needed. Legacy `p4rmtleg` driver still parked.
  - **P4 I2S RX: three model bugs, all in `src/esp32p4.c`.**
    1. I2S0 handler lived at translated `0x6000C000` but `p4_xlate()`
       maps `0x500C6000` → `0x6000D000`, so RX_CONF writes (incl.
       rx_update self-clear) landed in plain storage and
       `i2s_rx_channel_start` spun forever polling UPDATE. Fix: handler
       moved to `0xD000` (INT_CLR `0xD00C`, engine checks `0xD020/0xD024`).
    2. AHB_GDMA mapped at `0x50081000` (that is DW_GDMA, now explicitly
       unmapped); the I2S driver uses AHB_DMA at **`0x50085000`**
       (confirmed via `DW_GDMA`/`AHB_DMA`/`AXI_DMA` ELF symbols +
       `esp-pacs` PAC offsets). Fix: `p4_xlate()` maps
       `0x50085000-0x50085400` → `0x80000` (covers `IN_LINK_ADDR_CH`
       `0x3AC` / `OUT_LINK_ADDR_CH` `0x3B8`).
    3. AHB_GDMA register mismatch: IN_LINK.START is bit 2 (not 22),
       OUT_LINK.START bit 1 (not 21); descriptor addresses live in the
       separate `IN/OUT_LINK_ADDR_CH` regs as full 32-bit addresses (link
       reg low bits unused). Fix: new `gdma_{in,out}_link_addr[3]` state,
       START/STOP/RESTART bits per the HAL disassembly
       (`gdma_ahb_hal_start_with_desc`/`_reset`/`_stop`), full-addr
       walker arming with 20-bit fallback.
    Verified: `p4i2s` → `I2S_READ OK 960`, `WORDS 0 1` (monotonic
    counter, 6-desc ring `...e700→...f4c0→e700`). Regression: P4 hello,
    GPIO, I2C, RMT TX/RX, RMTRX; H2 hello + RMT TX — all green.
  - Follow-up 2026-09-10: P4 I2S TX (`I2S_WRITE OK 960` first try, no
    model change), legacy RMT driver (`RMT_WR/WAIT OK` — earlier stall
    resolved by the merged RMT rework), H2 RMT TX green with the same
    `rmt_enable()` fix. Full P4 matrix re-verified after later SMP +
    u64 changes (gpio/uart/gptimer/i2c/spi/adc/ledc/twai/pcnt/mcpwm/
    tsens/rmt/rmtrx/i2s-tx/i2s-rx/legacy, all DONE).

## Known issues / gotchas

- Makefile breaks on spaces in path (see warning above).
- `artifact` target re-fetches from GitHub releases if verification fails; slow network caused corruption once.
- Background builds get killed when the shell session ends → use `setsid bash -c 'make ... > log 2>&1' < /dev/null &`.
- WASM requires tail-call support: Chrome 112+, Firefox 121+, Safari 18.2+.
- P4 needs Zc + SMP before real ESP-IDF apps can run (rv32emu doesn't have either).
- WiFi/BT RF + WLAN MAC coprocessor firmware is out of scope for a faithful model → stub.
- **ESP32-C6 `conf0_sync` (UART loopback) is at offset 0x20, not 0x14.**
  The header register struct shifted: 0x14 is now `clkdiv_sync`, 0x20 is
  `conf0_sync` (loopback bit 12). Any new UART-register model must use 0x20.
- **High-level mbedtls/esp_aes AES API hangs** in the emulator. The esp-idf
  `esp_aes` driver feeds the AES peripheral via **GDMA** (the AES0 GDMA
  trigger exists in the C6 trigger list but GDMA-to-AES is not modeled), so a
  DMA-completion interrupt never arrives and the caller blocks forever. The
  AES peripheral itself works correctly in software/poll mode — verified via
  direct register pokes (`sketches/aesregtest`). Adding AES (and any GDMA-
  backed peripheral's) *DMA* path is the remaining work.

## Reference links

- rv32emu repo: https://github.com/sysprog21/rv32emu
- rv32emu wasm docs: docs/wasm.md (in repo)
- Espressif QEMU fork (alternative for real firmware): https://github.com/espressif/qemu
- ESP32-P4 datasheet (RV32IMAFC, Zc, XespV): documentation.espressif.com
