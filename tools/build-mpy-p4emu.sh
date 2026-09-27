#!/bin/bash
# Build MicroPython for ESP32-P4 (rv32emu ECO5 target, no PSRAM) and
# merge+pad a 16 MB flash image for the emulator.
#
# Outputs:
#   ~/micropython/ports/esp32/build-ESP32_GENERIC_P4-P4EMU/{bootloader/bootloader.bin,
#     partition_table/partition-table.bin,micropython.bin}
#   /tmp/mpy_p4emu_16.bin  (16 MB, 0xFF-padded; NOT committed — rebuild it)
# Run:
#   node run_p4.js /tmp/mpy_p4emu_16.bin "-C esp32p4smp -F /merged.bin"
#
# Requires the mp-y IDF env (ESP_IDF_VERSION=5.5 is load-bearing: without
# it the wifi-remote Kconfig orsource silently drops SLAVE_IDF_TARGET
# and esp_hosted dies with "Unknown Slave Target").
set -e
export IDF_PATH="$HOME/esp-idf-v5.5.4"
export IDF_VERSION=5.5 ESP_IDF_VERSION=5.5
export IDF_PYTHON_ENV_PATH="$HOME/.espressif-mpy/python_env/idf5.5_py3.14_env"
export IDF_TOOLS_PATH="$HOME/.espressif-mpy"
export PATH="$HOME/.espressif-mpy/tools/riscv32-esp-elf/esp-14.2.0_20260121/riscv32-esp-elf/bin:$HOME/.espressif-mpy/python_env/idf5.5_py3.14_env/bin:$HOME/esp-idf-v5.5.4/tools:$PATH"

MPY=~/micropython/ports/esp32
B=$MPY/build-ESP32_GENERIC_P4-P4EMU
make -C "$MPY" BOARD=ESP32_GENERIC_P4 BOARD_VARIANT=P4EMU -j"$(nproc)"
python3 "$IDF_PATH/components/esptool_py/esptool/esptool.py" \
  --chip esp32p4 merge_bin -o /tmp/mpy_p4emu_16.bin \
  --flash_mode dio --flash_size 16MB \
  0x2000 "$B/bootloader/bootloader.bin" \
  0x8000 "$B/partition_table/partition-table.bin" \
  0x10000 "$B/micropython.bin"
python3 -c "img=bytearray(b'\xff'*16777216);raw=open('/tmp/mpy_p4emu_16.bin','rb').read();img[:len(raw)]=raw;open('/tmp/mpy_p4emu_16.bin','r+b').write(img)"
ls -l /tmp/mpy_p4emu_16.bin
