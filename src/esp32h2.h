/*
 * ESP32-H2 SoC model for rv32emu (derived from the ESP32-C6 model; the H2
 * shares the C6-class peripheral IP at the same memory-map offsets, so this
 * reuses the C6 peripheral logic with the H2 interrupt-source numbering and
 * ROM image as a stopgap until an H2 mask ROM is available).
 */

#pragma once

#include "riscv.h"

/* ESP32-H2 memory map (TRM; H2 uses the same peripheral offsets as C6) */
#define C6_ROM_BASE 0x40000000u
#define H2_ROM_SIZE 0x20000u /* 128 KB H2 mask ROM (wokwi/esp32-roms) */
#define C6_SRAM_BASE 0x40800000u
#define C6_SRAM_SIZE 0x50000u /* 320 KB HP-SRAM (I- and D-bus same address) */
#define C6_LP_SRAM_BASE 0x50000000u
#define C6_LP_SRAM_SIZE 0x4000u /* 16 KB */
#define C6_FLASH_I_BASE 0x42000000u /* i/d-cache window (16 MB) */
#define C6_FLASH_WINDOW_SIZE 0x1000000u /* flash cache window (16 MB) */
#define C6_FLASH_SIZE 0x400000u /* 4 MB flash */
#define C6_PERIPH_BASE 0x60000000u
#define C6_PERIPH_SIZE 0x100000u /* 1 MB covers all HP peripherals */
#define C6_PLIC_BASE 0x20000000u /* PLIC_MX/UX + CLINT_M/U */
#define C6_PLIC_SIZE 0x2000u
#define C6_PLIC_CPU_BASE 0x80000000u /* CPU-side PLIC alias */
#define C6_PLIC_CPU_SIZE 0x1000u

typedef struct esp32h2_soc esp32h2_t;

/* Create and initialise the ESP32-H2 SoC (regions, ROM, peripherals). */
esp32h2_t *esp32h2_new(void);
uint8_t *esp32h2_guest_to_host(esp32h2_t *soc, uint32_t addr);

/* Boot the ESP32-H2 machine with the given application ELF path.
 * Returns the entry point (PC) to start at. */
uint32_t esp32h2_boot(esp32h2_t *soc, const char *elf_path);

/* Install the ESP32-H2 memory/io handlers on the core. */
void esp32h2_install_io(riscv_t *rv);

/* Called from rv_step to deliver pending M-mode interrupts. */
void esp32h2_check_interrupt(riscv_t *rv);

/* Called periodically to advance peripheral state (timers). */
void esp32h2_periodic(riscv_t *rv);

/* UART output callback hook (console). Overridable. */
extern void (*esp32h2_uart_output)(char c);

/* GPIO output change callback (LED demo). Overridable. */
extern void (*esp32h2_gpio_output)(int pin, bool level);

/* Optional full flash image (bootloader @ 0x0, partitions @ 0x8000,
 * app @ 0x10000). When set, the machine boots from the ROM reset vector. */
extern const char *esp32h2_flash_image_path;

/* Optional UART RX injection source: a FIFO file (or any readable file)
 * that the host writes command bytes to. Polled non-blockingly and fed
 * into the UART0 RX FIFO, which the guest's uart driver polls. */
extern const char *esp32h2_uart_rx_path;