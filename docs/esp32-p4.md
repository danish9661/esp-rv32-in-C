# ESP32-P4 bring-up (rv32emu port)

Status as of 2026-09-27 (`0bb8810`). All model code is `src/esp32p4.c`
(+ `src/esp32p4.h` map, `src/esp32p4_rom.h` ROM dump); progress log
lives in `AGENTS.md`.

## Verified firmware (WASM, node headless)

| Image | Cmd | Result |
|---|---|---|
| Arduino hello `demo/system/esp32p4/p4hello.ino.patched.bin` | `node run_p4.js … -C esp32p4` | `HELLO_UART_OK` + `TICK`s, zero errors |
| Arduino hello `demo/system/esp32p4smp/p4hellov3.ino.merged.bin` (stock dual-core) | `node run_p4.js … "-C esp32p4smp -F /merged.bin"` | `HELLO_UART_OK`, zero errors |
| MicroPython P4EMU `ESP32_GENERIC_P4` + `P4EMU` variant, no PSRAM (see below) | `node run_p4.js … -C esp32p4smp` | past rev gate to `entry 0x4ffac2c0`; both harts reach app code |

## ROM-slot hook model

The P4 ROM exposes APIs through JAL slots at `0x4FC00000+`. Slot JAL
targets are verified against the real 128 KB dump (single ECO5 table —
there is no second ABI table; an earlier off-by-one in the ROM copy
made every target decode as garbage and spawned stale LP-stub/illegal
theories, since fixed). Each hooked slot is covered on **both**
paths:

1. live-gated `esp32p4_ifetch` hook (`rv->PC == addr`, else the fetch is
   translator scratch) returning a block-terminal ECALL;
2. a `PC`-dispatched case in `esp32p4_ecall_handler` (a first-visit slot
   block can translate + chain before the hook fires live).

Current hooks: `ets_delay_us` (`0x4fc0003c` + body `0x4fc012f8`, nop —
the body is a long MCYCLE spin), `ets_get_cpu_frequency`
(`0x4fc00040`, 360 MHz), UART out (`0x4fc00030` install_printf plants
`ets_write_char_uart` into putc1/putc2, `0x4fc00054/58/5c/80` forward
`a0[7:0]` to the console, `0x4fc00074/78` drain instantly,
`0x4fc00070/84/88` nop), `rtc_get_reset_reason` (`0x4fc00018`, POR=1),
`ets_set_appcpu_boot_addr` (`0x4fc000a8`, records `0x50110164`),
MD5Init `0x4FC005E0` (host IV write), crc32_le `0x4FC005EC` (host CRC),
MD5Update/Final bodies + slots `0x4fc06ec4/5E4`, `0x4fc06f8c/5E8`
(host ports — the bodies call shared ROM helpers that don't complete
under the emulator), ECO5 SHA `0x4FC00608/614/620/624/628` (per-ctx
host session with the rom/sha.h `SHA_CTX` layout), libgcc
`0x4fc00770/7a0/844`. SPI-flash helpers (`0x4fc00118/168`) run
natively (nop-hooking them wedged boot on missing status side
effects). The slots are NEVER rewritten.

## Notable model values

- eFuse `RD_MAC_SYS_2 @+0x4C` = `0x30` (CHIP v3.0 = real ECO5 silicon,
  BLK v0; inside current MPY BL+APP [300..399] and Arduino postv3
  [0..empty]).
- `RTC_XTAL_FREQ_REG` (`LP_STORE4 @0x5011003C`) = `0x00280028` (40 MHz).
- Flash RDID = `EF 40 18` (16 MB part, matches `P4_FLASH_SIZE` and the
  image headers; a smaller ID fails the bootloader size-vs-header
  probe). The SPI2 virtual-device JEDEC (`EF 40 15`) is intentionally
  different: separate GPSPI peripheral model, Arduino-SPI path.
- `SHAGUARD`: skips the digest write only for the exact legacy address
  `0x4ffbcc24`. Current Arduino + MPY digests land at `0x4ffbcba0`
  and take the normal write path.
- `ets_sha_clone` (`0x4FC00628`) copies the 216 B caller ctx.
- SMP: 256-block hart quantum + never preempt a hart with a live LR
  reservation (bounded 512-switch pin); hart1 gets `PC=P4_ROM_LINK`,
  `SP`=SRAM top, `esp32p4_install_io(h1)`. CLIC word writes are W1C
  for IP-clear (SDK RMW config must not re-pend a stale latch).
- hart1 (SMP) boots the ROM reset vector; IDF releases it via the
  `0x50110164` mailbox.

## MicroPython P4EMU build (reproducible)

Upstream MicroPython v1.29.0, no tree changes needed except the
`P4EMU` board variant: `ports/esp32/boards/ESP32_GENERIC_P4/
mpconfigvariant_P4EMU.cmake` (in the micropython tree) plus
`~/mpywork/sdkconfig.p4emu` (ECO5 v3.0 headers, no PSRAM / hosted /
wifi-remote; the slave-target Kconfig only resolves with
`ESP_IDF_VERSION=5.5` exported). One-command rebuild + merge:

```sh
tools/build-mpy-p4emu.sh   # -> /tmp/mpy_p4emu_16.bin (16 MB, 0xFF-padded)
node run_p4.js /tmp/mpy_p4emu_16.bin "-C esp32p4smp -F /merged.bin"
```

The 16 MB image is NOT committed (too big); rebuild with the above.

## Open work

- MPY SMP from `entry` to REPL: both harts reach app code; next is
  the `s_cpu_up` handoff → clock init → REPL prompt → `print(6*7)` →
  protocol matrix (I2C/SPI/UART/net).
- WiFi/BLE stubs are out of scope (last step per project plan).
