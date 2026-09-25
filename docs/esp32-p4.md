# ESP32-P4 bring-up (rv32emu port)

Status as of 2026-09-23 (`b5c2efc` + working tree below). All model code is
`src/esp32p4.c` (+ `src/esp32p4.h` map, `src/esp32p4_rom.h` ROM dump);
progress log lives in `AGENTS.md`.

## Verified firmware

| Image | Cmd | Result |
|---|---|---|
| Arduino hello `patched.bin` (Sep-4, `15ce4229…`) | `./build/rv32emu -C esp32p4 -F …` (native, 100 s) | `HELLO_UART_OK` + ~175 `TICK`s, zero errors |
| Same image | `node run_p4.js …` (WASM, 300 s) | 327 `TICK`s, zero errors |
| MicroPython NOPSRAM `mpy_p4_nopsram.bin` | native `-C esp32p4` | partition MD5 green, factory image hash `32cf9a57…` MATCHES stored hash |
| Same MPY image | native `-C esp32p4smp` | both harts load segments, crash-dump + `ELF file SHA256: 086cb2bbd` + `Rebooting...` |

## ROM-slot hook model

The P4 ROM exposes APIs through JAL slots at `0x4FC00000+`. Slots whose
bodies JAL to LP stubs (unmapped `0x4fb0xxxx`) or decode to illegal words
cannot run natively. Each hooked slot is covered on **both** paths:

1. live-gated `esp32p4_ifetch` hook (`rv->PC == addr`, else the fetch is
   translator scratch) returning a block-terminal ECALL;
2. a `PC`-dispatched case in `esp32p4_ecall_handler` (a first-visit slot
   block can translate + chain before the hook fires live).

Current hooks: `ets_delay_us` (`0x4fc0003c` + body `0x4fc012f8`, nop),
`ets_get_cpu_frequency` (`0x4fc00040`, 360 MHz), `uart_tx_wait_idle`
(`0x4fc00078`), `rtc_get_reset_reason` (`0x4fc00018`, POR=1),
`ets_set_appcpu_boot_addr` (`0x4fc000a8`, records `0x50110164`),
MD5Update/Final bodies + slots, BASE SHA `62C/630/634` (per-ctx session),
MD5Init/crc32_le `0x4FC005EC` (caller-gated), libgcc `770/7a0/844`.

Dual-ABI note: Arduino links the ECO5 table, MicroPython the BASE table;
slot `0x4FC005EC` is MD5Init (BASE) vs `crc32_le` (ECO5) and slot
`0x4FC00620` is `sha_init` (BASE) vs `sha_update` (ECO5). Slots are NEVER
rewritten — a remap was tried and reverted (fixes one ABI, breaks the
other).

## Notable model values

- eFuse `RD_MAC_SYS_2 @+0x4C` = `0x30` (CHIP v3.0 = real ECO5 silicon,
  BLK v0; inside MPY BL+APP [300..399] and Arduino postv3 [0..empty]).
  (Was `0x810`/v1.0 — predates MPY's min-v3.0 headers.)
- `RTC_XTAL_FREQ_REG` (`LP_STORE4 @0x5011003C`) = `0x00280028` (40 MHz).
- `SHAGUARD`: digest `0x4ffbcc24` (Arduino in-place header hash) skips
  the write; all other digests write normally.
- `ets_sha_clone` (`0x4FC00634`) copies the 104 B caller ctx.
- hart1 (SMP) gets `PC=P4_ROM_LINK`, `SP`=SRAM top,
  `esp32p4_install_io(h1)` — `rv_create` leaves it zeroed with the
  default io table.

## Open work

- SMP post-`Rebooting...` wedge (both harts parked, mailbox never set).
- Unicore MPY spin at app `0x4000752e` (s0==0 yet no exit).
- Then: REPL prompt → `print(6*7)` → protocol matrix (I2C/SPI/UART/net).
