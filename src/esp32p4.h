/*
 * ESP32-P4 SoC model for rv32emu (derived from the ESP32-C6 model; the P4
 * shares the C6-class peripheral IP at the same memory-map offsets, so this
 * reuses the C6 peripheral logic with the P4 interrupt-source numbering and
 * ROM image as a stopgap until an P4 mask ROM is available).
 */

#pragma once

#include "riscv.h"

/* ESP32-P4 memory map (TRM + ESP-IDF soc headers; IDF 5.5 / Arduino 3.3.x).
 * Unlike C6/H2, the P4 puts SRAM at 0x4FF00000, the flash cache window at
 * 0x40000000 (shared with the mask ROM range until the MMU maps it), LP
 * SRAM at 0x50108000, and HP peripherals at 0x50000000/0x500C0000 with LP
 * peripherals at 0x50110000/0x50120000. */
#define P4_TCM_BASE 0x30100000u
#define P4_TCM_SIZE 0x2000u /* 8 KB TCM */
#define P4_ROM_BASE 0x40000000u
#define P4_ROM_SIZE 0x20000u /* 128 KB HP mask ROM (wokwi/esp32-roms) */
#define P4_SRAM_BASE 0x4FF00000u
#define P4_SRAM_SIZE 0xC0000u /* 768 KB HP SRAM (I- and D-bus same address) */
#define P4_LP_SRAM_BASE 0x50108000u
#define P4_LP_SRAM_SIZE 0x8000u /* 32 KB */
#define P4_FLASH_I_BASE 0x40000000u /* i/d-cache window (64 MB decode) */
#define P4_FLASH_WINDOW_SIZE 0x4000000u /* flash cache window (64 MB) */
#define P4_FLASH_SIZE 0x400000u /* 4 MB flash */
#define P4_MMIO_BASE 0x50000000u
#define P4_MMIO_SIZE 0x130000u /* 0x50000000-0x50130000: HP+LP peripherals */
/* Internal C6-style dispatch base: guest P4 peripheral addresses are
 * translated to this 0x60000000-based layout on entry to the MMIO
 * handlers, so the (C6-class) peripheral logic below is shared. */
#define P4_PERIPH_BASE 0x60000000u
#define P4_PERIPH_SIZE 0x100000u /* 1 MB covers all translated peripherals */
#define P4_PLIC_BASE 0x20000000u /* PLIC_MX/UX + CLINT_M/U */
#define P4_PLIC_SIZE 0x2000u
#define P4_PLIC_CPU_BASE 0x80000000u /* CPU-side PLIC alias */
#define P4_PLIC_CPU_SIZE 0x1000u

typedef struct esp32p4_soc esp32p4_t;

/* Create and initialise the ESP32-P4 SoC (regions, ROM, peripherals). */
esp32p4_t *esp32p4_new(void);
uint8_t *esp32p4_guest_to_host(esp32p4_t *soc, uint32_t addr);

/* Boot the ESP32-P4 machine with the given application ELF path.
 * Returns the entry point (PC) to start at. */
uint32_t esp32p4_boot(esp32p4_t *soc, const char *elf_path);

/* Install the ESP32-P4 memory/io handlers on the core. */
void esp32p4_install_io(riscv_t *rv);

/* Called from rv_step to deliver pending M-mode interrupts. */
void esp32p4_check_interrupt(riscv_t *rv);

/* Called periodically to advance peripheral state (timers). */
void esp32p4_periodic(riscv_t *rv);

/* UART output callback hook (console). Overridable. */
extern void (*esp32p4_uart_output)(char c);

/* GPIO output change callback (LED demo). Overridable. */
extern void (*esp32p4_gpio_output)(int pin, bool level);

/* Optional full flash image (bootloader @ 0x0, partitions @ 0x8000,
 * app @ 0x10000). When set, the machine boots from the ROM reset vector. */
extern const char *esp32p4_flash_image_path;

/* Optional UART RX injection source: a FIFO file (or any readable file)
 * that the host writes command bytes to. Polled non-blockingly and fed
 * into the UART0 RX FIFO, which the guest's uart driver polls. */
extern const char *esp32p4_uart_rx_path;