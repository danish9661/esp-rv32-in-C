# ESP32 RISC-V emulator (C3 / C6 / H2 / P4, WebAssembly)

A WebAssembly emulator for **ESP32-C3, ESP32-C6, ESP32-H2, ESP32-P4**,
built by extending [sysprog21/rv32emu](https://github.com/sysprog21/rv32emu)
with ESP32 SoC models (memory maps, ROM hooks, peripherals, interrupt
controllers). One combined binary serves all four chips with runtime chip
selection. This fork is ESP-only: upstream user-mode games, SDL, JIT, GDB
stub, arch-test, and Linux-image tooling are not part of this tree
(see [docs/esp32-p4.md](docs/esp32-p4.md) for scope notes).

```
rv32emu core (interpreter, ELF loader)   [upstream, kept]
        │
        └── ESP32 SoC layer (new, C, per-chip table-driven)
              ├── memory map / register banks per chip
              ├── SYSTIMER, UART (console), GPIO, SPI0 flash cache
              ├── interrupt controllers (PLIC/INTC/CLIC per chip)
              └── chip select at runtime (`-C esp32c3|c6|h2|p4|p4smp`)
```

| Chip | Core | Notes |
|---|---|---|
| ESP32-C3 | RV32IMC, 1 core | WiFi+BLE |
| ESP32-C6 | RV32IMC, 1 core | WiFi6+BLE+802.15.4 |
| ESP32-H2 | RV32IMC, 1 core | BLE+802.15.4 |
| ESP32-P4 | RV32IMAFC, 2 HP cores + LP | No wireless; SMP via `-C esp32p4smp` |

## Quick start

Prerequisites: `gcc`, `arduino-cli` (esp32 core 3.3.10), node; for WASM:
Emscripten SDK (`source ~/emsdk/emsdk_env.sh`, emcc 6.0.6).

```shell
# Native build (fast iteration only):
make -j$(nproc)                              # -> build/rv32emu

# WASM build (the real target):
source ~/emsdk/emsdk_env.sh
rm -rf build/softfloat build/devices         # when switching toolchains
make CC=emcc wasmc6_defconfig
make CC=emcc -j$(nproc)                      # -> build/rv32emu.js + .wasm
```

Switching between native and WASM toolchains requires
`rm -rf build/softfloat build/devices` (objects are toolchain-specific;
make does not detect the switch).

## Running firmware

Build firmware with `arduino-cli`, flash it as a `merged.bin` image:

```shell
# P4 hello (ChipVariant=postv3), then unicore-patch + run:
arduino-cli compile --fqbn esp32:esp32:esp32p4:ChipVariant=postv3 <sketchdir> --output-dir <out>
python3 tools/p4_mkunicore.py <out>/<name>.ino.elf <out>/<name>.ino.merged.bin <out>/patched.bin
timeout 100 ./build/rv32emu -C esp32p4 -F <out>/patched.bin   # expect HELLO_UART_OK + TICKs
timeout 300 node run_p4.js <out>/patched.bin                 # WASM headless (run_c3/c6/h2.js likewise)
```

The WASM bundle sets `Module["noInitialRun"]=true`, so bare
`node build/rv32emu.js -C ...` does NOT run `main()` — use the
`run_*.js` harnesses (MEMFS image + `run_system`, `document` stub).
Browser demo: serve `demo/` (`python3 tools/dev-server.py --directory demo`)
and open the system page; firmware + runner glue live under
`demo/system/esp32*/` and `assets/wasm/js/system-pre.js`.
UART RX injection: `-U <file>` native, `P4_RX_FILE`/`H2_RX_FILE` env on node.

## Verified status

- Arduino hello on all four chips boots to `setup()`/`loop()` with UART
  output (`HELLO_UART_OK` + `TICK`s), native and WASM-node.
- C6 full peripheral report (`demotest` → `DEMO_DONE`); H2 11-test matrix;
  P4 18-test peripheral matrix incl. dual-core SMP (`IPC_DONE`, GPIO).
- MicroPython v1.29.0 REPL on C3/C6/H2 (interactive `print(6*7)` → `42`
  plus peripheral matrix); P4 MicroPython boots through partition-MD5 and
  factory image-hash verify (`32cf9a57…` match), app bring-up in progress.
- WiFi/BT are stubs (out of scope for a faithful model).

Details: [docs/esp32-p4.md](docs/esp32-p4.md); full project spec and
progress log: `AGENTS.md`.

## Documentation

| Topic | Document |
| ----- | -------- |
| ESP32-P4 bring-up status, hook model, images | [docs/esp32-p4.md](docs/esp32-p4.md) |
| ESP build configs and options | [docs/build.md](docs/build.md) |
| ESP WebAssembly build + node/browser runs | [docs/wasm.md](docs/wasm.md) |
| RISC-V instruction reference | [docs/instruction.md](docs/instruction.md) |

## Upstream credit

Core interpreter, ELF loader, and build system by the
[rv32emu project](https://github.com/sysprog21/rv32emu) (MIT license,
see [LICENSE](LICENSE)). VMIL'24 paper:
[Accelerate RISC-V Instruction Set Simulation by Tiered JIT Compilation](https://dl.acm.org/doi/10.1145/3689490.3690399).
