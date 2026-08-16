/*
 * ESP32-C3 SoC model for rv32emu.
 *
 * Adds an ESP32-C3 machine mode: memory map, UART0, SYSTIMER, INTC, GPIO,
 * eFuse and stub register banks, plus M-mode interrupt delivery through the
 * ESP32 interrupt matrix. Bypasses the Sv32 MMU (bare-metal, identity).
 */

#pragma once

#include "riscv.h"

/* ESP32-C3 memory map (TRM + esp32c3 memory.ld) */
#define C3_DRAM_BASE 0x3FC80000u
#define C3_DRAM_SIZE 0x70000u /* 448 KB SRAM (app 313 KB + ROM data) */
#define C3_ROMDATA_BASE 0x3FF00000u
#define C3_ROMDATA_SIZE 0x20000u /* ROM data bus (.rodata) */
#define C3_IRAM_BASE 0x40380000u
#define C3_IRAM_SIZE 0x60000u /* full IRAM: covers app iram0_0_seg and the
                               * bootloader's data segment at 0x403CE710+ */
#define C3_RTC_FAST_BASE 0x50000000u
#define C3_RTC_FAST_SIZE 0x2000u /* 8 KB */
#define C3_ROM_BASE 0x40000000u
#define C3_ROM_SIZE 0x60000u /* 384 KB */
#define C3_FLASH_D_BASE 0x3C000000u /* d-cache window */
#define C3_FLASH_I_BASE 0x42000000u /* i-cache window */
#define C3_FLASH_SIZE 0x400000u /* 4 MB flash */
#define C3_MMU_TABLE_BASE 0x600C5000u /* flash cache MMU page table */
#define C3_MMU_TABLE_END (C3_MMU_TABLE_BASE + 128 * 4)
#define C3_PERIPH_BASE 0x60000000u
#define C3_PERIPH_SIZE 0x100000u /* 1 MB covers all peripherals incl. INTC */
#define C3_DRAM_TOP (C3_DRAM_BASE + C3_DRAM_SIZE)

typedef struct esp32c3_soc esp32c3_t;

/* Create and initialise the ESP32-C3 SoC (regions, ROM, peripherals). */
esp32c3_t *esp32c3_new(void);

/* Boot the ESP32-C3 machine with the given application ELF path.
 * Returns the entry point (PC) to start at. */
uint32_t esp32c3_boot(esp32c3_t *soc, const char *elf_path);

/* Install the ESP32-C3 memory/io handlers on the core. */
void esp32c3_install_io(riscv_t *rv);

/* Called from rv_step to deliver pending M-mode interrupts. */
void esp32c3_check_interrupt(riscv_t *rv);

/* Called periodically to advance peripheral state (timers). */
void esp32c3_periodic(riscv_t *rv);

/* UART output callback hook (console). Overridable. */
extern void (*esp32c3_uart_output)(char c);

/* GPIO output change callback (LED demo). Overridable. */
extern void (*esp32c3_gpio_output)(int pin, bool level);

/* Optional full flash image (bootloader @ 0x0, partitions @ 0x8000,
 * app @ 0x10000). When set, the machine boots from the ROM reset vector. */
extern const char *esp32c3_flash_image_path;