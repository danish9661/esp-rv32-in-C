# Build (ESP32 targets)

Single supported WASM config: `configs/wasmc6_defconfig` (C3+C6+H2+P4,
interpreter, no SDL). Native builds use the ambient `.config`
(`CONFIG_BUILD_NATIVE=y`, same four chips, `CONFIG_ELF_LOADER=y`).

```shell
# Native (fast iteration only):
make -j$(nproc)                              # -> build/rv32emu

# WASM (the real target):
source ~/emsdk/emsdk_env.sh                  # emcc 6.0.6
rm -rf build/softfloat build/devices         # when switching toolchains
make CC=emcc wasmc6_defconfig
make CC=emcc -j$(nproc)                      # -> build/rv32emu.js + .wasm
```

Switching toolchains without `rm -rf build/softfloat build/devices`
silently misbuilds (objects are toolchain-specific; make does not
detect the switch). `file build/rv32emu` must say ELF x86-64 after a
native build; a stale WASM-object binary is the classic false red/green.

`wasmc6_defconfig` sets: RV32IMACF + Zicsr/Zifencei + Zba/Zbb/Zbc/Zbs,
`CONFIG_SYSTEM=y` + `CONFIG_ELF_LOADER=y` (flash-image boot, no DTB),
`INTERPRETER_ONLY`, `MOP_FUSION`, `BLOCK_CHAINING=n`, `LTO`, log color,
`-O2` + debug symbols, ESP32_C3/C6/H2/P4 all `y`. (`BLOCK_CHAINING=n`
is load-bearing: the P4 ROM-slot hooks rely on unchained dispatch.)
