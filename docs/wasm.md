# WebAssembly build (ESP32)

Requires Emscripten (`source ~/emsdk/emsdk_env.sh`, emcc 6.0.6) and a
TCO-capable browser (Chrome 112+, Firefox 121+, Safari 18.2+).

```shell
source ~/emsdk/emsdk_env.sh
rm -rf build/softfloat build/devices         # when switching toolchains
make CC=emcc wasmc6_defconfig
make CC=emcc -j$(nproc)                      # -> build/rv32emu.js + .wasm
```

Headless node runs (the bundle sets `Module["noInitialRun"]=true`, so bare
`node build/rv32emu.js -C ...` does NOT run `main()` — use the harnesses):

```shell
timeout 300 node run_p4.js <merged.bin>      # P4 (run_c3/c6/h2.js likewise)
P4_RX_FILE=<rxfile> node run_p4.js <merged.bin>  # UART RX preload via /uartrx
```

Browser demo: `python3 tools/dev-server.py --directory demo`, open the
system page, click the chip button (firmware + glue under
`demo/system/esp32*/`, `assets/wasm/js/system-pre.js`).
