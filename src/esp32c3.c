/*
 * ESP32-C3 SoC model for rv32emu (MIT license, see LICENSE).
 *
 * Implements the memory map and the minimal peripheral set required to boot
 * ESP-IDF / Arduino firmware on the ESP32-C3:
 *
 *   - RAM regions: DRAM 0x3FC88000, IRAM 0x4037C000, RTC fast 0x50000000
 *   - ROM 0x40000000 (embedded real ROM image)
 *   - Flash cache windows 0x3C000000 / 0x42000000 (shared flash backing)
 *   - Peripherals at 0x60000000+: UART0, SPI0/1, GPIO, RTC_CNTL, eFuse,
 *     TIMG0, SYSTIMER, PMU, LP_CLKRST, INTC
 *
 * M-mode only, no MMU (identity addresses). Interrupts: SYSTIMER compare ->
 * INTC (interrupt matrix) -> mip/mie -> vectored mtvec.
 */

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esp32c3.h"
#include "esp32c3_rom.h"
#include "esp32c3_romdata.h"
#include "esp32c3_romsram.h"
#include "riscv_private.h"
#include "system.h" /* trap_handler */

/* ------------------------------------------------------------------ */
/* ESP32-C3 memory map (TRM)                                          */
/* ------------------------------------------------------------------ */

/* (map constants now live in esp32c3.h) */

/* ------------------------------------------------------------------ */
/* Memory model                                                        */
/* ------------------------------------------------------------------ */

/* Software SHA-256: the ROM reads its digest from the SHA accelerator
 * (0x6003B040-0x6003B05C). Message blocks are written to
 * 0x6003B040-0x6003B0BF: full blocks at 0x6003B080, the final padded
 * block (0x80 + zeros + BE length, built by the ROM itself) at
 * 0x6003B040. SHA_MODE (0x6003B000) is written before every block, so a
 * session is reset only on the first mode write after a digest read. */
static uint8_t sha_msg[0x200000]; /* large enough for full app image hash */
static uint32_t sha_len;
static uint32_t sha_digest[8];
static int sha_computed;
static int sha_reset_pending;
static uint32_t dbg_pc;

static void esp32_sha_reset(void)
{
    sha_len = 0;
    sha_computed = 0;
}

static void esp32_sha_feed_word(uint32_t val)
{
    if (sha_len + 4 <= sizeof(sha_msg)) {
        sha_msg[sha_len++] = val & 0xff;
        sha_msg[sha_len++] = (val >> 8) & 0xff;
        sha_msg[sha_len++] = (val >> 16) & 0xff;
        sha_msg[sha_len++] = (val >> 24) & 0xff;
    }
    sha_computed = 0;
}

static uint32_t esp32_sha_digest_word(unsigned idx)
{
    if (!sha_computed) {
        static const uint32_t k[64] = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
            0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
            0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
            0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
            0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        };
        /* the ROM builds and feeds the final padded block itself
         * (0x80 + zeros + 64-bit BE length); hash the accumulated
         * message as-is */
        size_t total = (sha_len + 63) & ~(size_t) 63;
        uint32_t w[64];
        uint32_t h[8] = {
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        };
        for (size_t block = 0; block < total; block += 64) {
            for (int i = 0; i < 16; i++)
                w[i] = ((uint32_t) sha_msg[block + 4 * i] << 24) |
                       ((uint32_t) sha_msg[block + 4 * i + 1] << 16) |
                       ((uint32_t) sha_msg[block + 4 * i + 2] << 8) |
                       sha_msg[block + 4 * i + 3];
            for (int i = 16; i < 64; i++) {
                uint32_t s0 = ((w[i - 15] >> 7) | (w[i - 15] << 25)) ^
                              ((w[i - 15] >> 18) | (w[i - 15] << 14)) ^
                              (w[i - 15] >> 3);
                uint32_t s1 = ((w[i - 2] >> 17) | (w[i - 2] << 15)) ^
                              ((w[i - 2] >> 19) | (w[i - 2] << 13)) ^
                              (w[i - 2] >> 10);
                w[i] = w[i - 16] + s0 + w[i - 7] + s1;
            }
            uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
            uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];
            for (int i = 0; i < 64; i++) {
                uint32_t S1 = ((e >> 6) | (e << 26)) ^
                              ((e >> 11) | (e << 21)) ^
                              ((e >> 25) | (e << 7));
                uint32_t ch = (e & f) ^ (~e & g);
                uint32_t t1 = hh + S1 + ch + k[i] + w[i];
                uint32_t S0 = ((a >> 2) | (a << 30)) ^
                              ((a >> 13) | (a << 19)) ^
                              ((a >> 22) | (a << 10));
                uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
                uint32_t t2 = S0 + maj;
                hh = g;
                g = f;
                f = e;
                e = d + t1;
                d = c;
                c = b;
                b = a;
                a = t1 + t2;
            }
            h[0] += a;
            h[1] += b;
            h[2] += c;
            h[3] += d;
            h[4] += e;
            h[5] += f;
            h[6] += g;
            h[7] += hh;
        }
        for (int i = 0; i < 8; i++)
            sha_digest[i] = ((h[i] >> 24) & 0xff) | ((h[i] >> 8) & 0xff00) |
                            ((h[i] << 8) & 0xff0000) | (h[i] << 24);
        sha_computed = 1;
    }
    return sha_digest[idx];
}

typedef enum { ESP32_REG_RAM, ESP32_REG_MMIO } esp32_reg_type_t;

typedef struct {
    uint32_t base;
    uint32_t size;
    uint8_t *data; /* NULL for MMIO */
    esp32_reg_type_t type;
} esp32_region_t;

struct esp32c3_soc {
    esp32_region_t regions[12];
    int nregions;

    /* peripheral register backing (MMIO) */
    uint8_t mmio[C3_PERIPH_SIZE];

    /* SYSTIMER */
    uint64_t systimer_counter;
    uint64_t systimer_unit1_counter;
    uint64_t systimer_comp0;
    uint64_t systimer_comp2;
    uint32_t systimer_conf;
    uint32_t systimer_target0_conf;
    uint32_t systimer_target2_conf;
    uint32_t systimer_int_ena;
    uint32_t systimer_int_raw;
    uint64_t systimer_t0_crossed;
    uint64_t systimer_t2_crossed;
    uint64_t systimer_unit0_val; /* latched by UNIT0_OP UPDATE */
    uint64_t systimer_unit1_val; /* latched by UNIT1_OP UPDATE */
    uint64_t rtc_time; /* RTCCNTL_TIME0/1: slow-clock ticks since reset */
    uint64_t rtc_frac;
    uint64_t last_cycle;

    /* SPI flash status registers (SR/SR2 incl. WEL and QE bits) */
    uint32_t flash_sr;
    uint32_t flash_sr2;

    /* INTC (interrupt matrix) */
    uint32_t intc_enable;
    uint32_t intc_type;
    uint64_t intc_status;
    uint32_t intc_eip; /* claimed (exception-in-progress) lines */
    uint32_t intc_intmap[64];

    /* GPIO */
    uint32_t gpio_out;
    uint32_t gpio_enable;

    /* UART output buffering */
    char uart_line[256];
    int uart_line_len;

    /* misc logged-MMIO bookkeeping */
    uint32_t logged_unknown;

    /* TIMG0 WDT_CONFIG0 read counter (stable-read XOR scheme) */
    uint32_t wdt_config0_reads;

    /* flash cache MMU page table (128 x 64KB pages), programmed by the
     * bootloader's esp_rom_spiflash_mmap at 0x18031400 + 4*idx */
    uint32_t mmu[128];
};

void (*esp32c3_uart_output)(char c) = NULL;
void (*esp32c3_gpio_output)(int pin, bool level) = NULL;

/* Optional flash image (bootloader @ 0x0 + partitions @ 0x8000 + app @
 * 0x10000). When set, the machine boots from the ROM reset vector. */
const char *esp32c3_flash_image_path = NULL;

/* ------------------------------------------------------------------ */
/* Region helpers                                                      */
/* ------------------------------------------------------------------ */

static esp32_region_t *esp32_find_region(esp32c3_t *soc, uint32_t addr)
{
    for (int i = 0; i < soc->nregions; i++) {
        esp32_region_t *r = &soc->regions[i];
        if (addr >= r->base && addr < r->base + r->size)
            return r;
    }
    return NULL;
}

static void esp32_add_region(esp32c3_t *soc,
                             uint32_t base,
                             uint32_t size,
                             esp32_reg_type_t type)
{
    esp32_region_t *r = &soc->regions[soc->nregions++];
    r->base = base;
    r->size = size;
    r->type = type;
    r->data = (type == ESP32_REG_RAM) ? calloc(1, size) : NULL;
    assert(r->data || type == ESP32_REG_MMIO);
}

/* ------------------------------------------------------------------ */
/* SoC construction                                                    */
/* ------------------------------------------------------------------ */

esp32c3_t *esp32c3_new(void)
{
    esp32c3_t *soc = calloc(1, sizeof(esp32c3_t));
    assert(soc);
    soc->systimer_conf = 0x40000000u; /* TIMER_UNIT0_WORK_EN default 1 */

    /* flash backing shared by i-cache and d-cache windows */
    uint8_t *flash = calloc(1, C3_FLASH_SIZE);
    assert(flash);

    esp32_add_region(soc, C3_DRAM_BASE, C3_DRAM_SIZE, ESP32_REG_RAM);
    esp32_add_region(soc, C3_IRAM_BASE, C3_IRAM_SIZE, ESP32_REG_RAM);
    esp32_add_region(soc, C3_RTC_FAST_BASE, C3_RTC_FAST_SIZE, ESP32_REG_RAM);
    esp32_add_region(soc, C3_ROM_BASE, C3_ROM_SIZE, ESP32_REG_RAM);
    esp32_add_region(soc, C3_ROMDATA_BASE, C3_ROMDATA_SIZE, ESP32_REG_RAM);

    /* flash cache windows share one backing buffer */
    esp32_region_t *fd = &soc->regions[soc->nregions++];
    fd->base = C3_FLASH_D_BASE;
    fd->size = C3_FLASH_SIZE;
    fd->type = ESP32_REG_RAM;
    fd->data = flash;

    esp32_region_t *fi = &soc->regions[soc->nregions++];
    fi->base = C3_FLASH_I_BASE;
    fi->size = C3_FLASH_SIZE;
    fi->type = ESP32_REG_RAM;
    fi->data = flash;

    /* 64KB linear alias at 0x3C7E0000 (ROM usage): maps flash[0..0x10000) */
    esp32_region_t *fm = &soc->regions[soc->nregions++];
    fm->base = 0x3C7E0000u;
    fm->size = 0x10000u;
    fm->type = ESP32_REG_RAM;
    fm->data = flash;

    /* window page 0x7F at 0x3C7F0000 goes through the flash cache MMU: the
     * bootloader's spiflash reader (0x403cf3e6) re-maps mmu[0x7F] to the
     * current 64K flash page before each read. */
    esp32_region_t *fw = &soc->regions[soc->nregions++];
    fw->base = 0x3C7F0000u;
    fw->size = 0x10000u;
    fw->type = ESP32_REG_RAM;
    fw->data = flash;

    esp32_add_region(soc, C3_PERIPH_BASE, C3_PERIPH_SIZE, ESP32_REG_MMIO);

    /* flash cache MMU defaults to identity mapping (page i -> flash page i) */
    for (int i = 0; i < 128; i++)
        soc->mmu[i] = i;

    /* load the real ROM image */
    esp32_region_t *rom = esp32_find_region(soc, C3_ROM_BASE);
    assert(esp32c3_rom_bin_len <= C3_ROM_SIZE);
    memcpy(rom->data, esp32c3_rom_bin, esp32c3_rom_bin_len);

    /* ROM data (.rodata at 0x3FF19C00, DRAM-resident data at 0x3FCCB000) */
    esp32_region_t *romdata = esp32_find_region(soc, C3_ROMDATA_BASE);
    assert(esp32c3_rom_rodata_bin_len <= C3_ROMDATA_SIZE);
    memcpy(romdata->data, esp32c3_rom_rodata_bin, esp32c3_rom_rodata_bin_len);
    esp32_region_t *dram = esp32_find_region(soc, C3_DRAM_BASE);
    memcpy(dram->data + (0x3FCCB000u - C3_DRAM_BASE), esp32c3_rom_sram_bin,
           esp32c3_rom_sram_bin_len);

    /* INTC default: source s maps to CPU line s */
    for (int i = 0; i < 64; i++)
        soc->intc_intmap[i] = i;

    return soc;
}

/* ------------------------------------------------------------------ */
/* UART0 (0x60000000)                                                  */
/* ------------------------------------------------------------------ */

#define UART_FIFO_REG 0x00u
#define UART_STATUS_REG 0x1Cu

static void esp32_uart_putc(esp32c3_t *soc, char c)
{
    if (esp32c3_uart_output)
        esp32c3_uart_output(c);
    else
        putchar(c);
    if (soc->uart_line_len < (int) sizeof(soc->uart_line) - 1)
        soc->uart_line[soc->uart_line_len++] = c;
    if (c == '\n') {
        fflush(stdout);
        soc->uart_line_len = 0;
    }
}

/* ------------------------------------------------------------------ */
/* GPIO (0x60004000)                                                   */
/* ------------------------------------------------------------------ */

#define GPIO_OUT_REG 0x00u
#define GPIO_OUT_W1TS 0x04u
#define GPIO_OUT_W1TC 0x08u
#define GPIO_ENABLE_REG 0x0Cu
#define GPIO_ENABLE_W1TS 0x10u
#define GPIO_ENABLE_W1TC 0x14u
#define GPIO_IN_REG 0x1Cu
#define GPIO_STRAP_REG 0x38u
#define GPIO_PIN0 0x40u

/* ------------------------------------------------------------------ */
/* SYSTIMER (0x60023000)                                               */
/* ------------------------------------------------------------------ */

#define SYSTIMER_CONF 0x00u
#define SYSTIMER_UNIT0_OP 0x04u
#define SYSTIMER_UNIT1_OP 0x08u
#define SYSTIMER_TARGET0_HI 0x1Cu
#define SYSTIMER_TARGET0_LO 0x20u
#define SYSTIMER_TARGET2_LO 0x30u
#define SYSTIMER_TARGET2_HI 0x2Cu
#define SYSTIMER_TARGET0_CONF 0x34u
#define SYSTIMER_TARGET2_CONF 0x3Cu
#define SYSTIMER_VALUE_HI 0x40u
#define SYSTIMER_VALUE_LO 0x44u
#define SYSTIMER_UNIT1_VALUE_HI 0x48u
#define SYSTIMER_UNIT1_VALUE_LO 0x4Cu
#define SYSTIMER_INT_ENA 0x64u
#define SYSTIMER_INT_RAW 0x68u
#define SYSTIMER_INT_CLR 0x6Cu
/* ESP32-C3 INTC sources: 37 = SYSTIMER_TARGET0 (FreeRTOS tick), 39 =
 * SYSTIMER_TARGET2 (esp_timer). The app's esp_timer_impl_init allocates
 * source 39 and the tick uses the TARGET0 alarm. */
#define SYSTIMER_T0_SOURCE 37u
#define SYSTIMER_T2_SOURCE 39u

/* ------------------------------------------------------------------ */
/* INTC (0x600C2000)                                                   */
/* ------------------------------------------------------------------ */

#define INTC_INTMAP_BASE 0x000u
#define INTC_INTR_STATUS 0x0F8u
#define INTC_INTR_STATUS_1 0x0FCu
#define INTC_INT_ENABLE 0x104u
#define INTC_INT_TYPE 0x108u
#define INTC_INT_CLEAR 0x10Cu

/* ------------------------------------------------------------------ */
/* MMIO dispatch                                                       */
/* ------------------------------------------------------------------ */

static uint32_t esp32_mmio_read(esp32c3_t *soc, uint32_t addr)
{
    static uint32_t seen[512];
    static int n_seen;
    if (addr == 0x60004038u)
        fprintf(stderr, "DBG: strap-read value=0x%08x\n",
                ((1u << 9) | 0x8u));
    if (n_seen < 512) {
        for (int i = 0; i < n_seen; i++)
            if (seen[i] == (addr & ~0xFFu))
                goto have_seen;
        seen[n_seen++] = addr & ~0xFFu;
        fprintf(stderr, "DBG: mmio-read  0x%08x\n", addr);
    }
have_seen:
    if (addr < C3_PERIPH_BASE || addr >= C3_PERIPH_BASE + C3_PERIPH_SIZE)
        return 0; /* unmapped: bus returns zeros */
    uint32_t off = addr - C3_PERIPH_BASE;
    uint32_t *mmio32 = (uint32_t *) soc->mmio;

    /* Flash cache MMU page table (0x600C5000): return programmed pages */
    if (addr >= C3_MMU_TABLE_BASE && addr < C3_MMU_TABLE_END)
        return soc->mmu[(addr - C3_MMU_TABLE_BASE) >> 2];

    /* TIMG1 WDT_CONFIG0 (0x600260B0): the bootloader's stable-read XORs
     * repeated reads of this register; a constant value yields 0 (even
     * read count) and it retries forever. Rotate a single low bit per
     * read so the XOR of any burst is non-zero until SW writes the reg. */
    if (addr == C3_PERIPH_BASE + 0x260B0u) {
        uint32_t v = mmio32[off >> 2];
        if (!v) {
            uint32_t n = soc->wdt_config0_reads++;
            if (n < 8)
                fprintf(stderr, "DBG: wdtcfg0 rd n=%u -> 0x%08x\n", n,
                        0x80000000u | (1u << (n % 31u)));
            return 0x80000000u | (1u << (n % 31u));
        }
        return v;
    }

    /* UART0 */
    if (addr < C3_PERIPH_BASE + 0x1000u) {
        switch (off) {
        case UART_STATUS_REG:
            return 0; /* TX FIFO empty */
        default:
            return mmio32[off >> 2];
        }
    }
    /* SPI0/SPI1 (flash) */
    if (addr < C3_PERIPH_BASE + 0x4000u) {
        if (addr == C3_PERIPH_BASE + 0x2000u)
            return 0; /* SPI_CMD always reads done (self-clears) */
        if (addr == C3_PERIPH_BASE + 0x202Cu)
            return 0x2u; /* SPI0 status: flash ready */
        return mmio32[off >> 2];
    }
    /* GPIO */
    if (addr < C3_PERIPH_BASE + 0x5000u) {
        switch (off - 0x4000u) {
        case GPIO_OUT_REG:
            return soc->gpio_out;
        case GPIO_ENABLE_REG:
            return soc->gpio_enable;
        case GPIO_IN_REG:
            /* strapping: GPIO9 high -> SPI flash boot */
            return 1u << 9;
        case GPIO_STRAP_REG:
            /* GPIO9 strapped high: boot mode 1xxx (SPI flash boot) */
            return (1u << 9) | 0x8u;
        default:
            return mmio32[off >> 2];
        }
    }
    /* RTC_CNTL / IO_MUX / eFuse / RTC_I2C */
    if (addr < C3_PERIPH_BASE + 0xF000u) {
        if (addr == C3_PERIPH_BASE + 0x8010u) {
            return (uint32_t) soc->rtc_time; /* RTCCNTL_TIME0 */
        }
        if (addr == C3_PERIPH_BASE + 0x8014u)
            return (uint32_t) (soc->rtc_time >> 32); /* RTCCNTL_TIME1 */
        if (addr == C3_PERIPH_BASE + 0x8038u)
            return 1; /* RTC_CNTL_RESET_REASON: power-on reset */
        if (addr == C3_PERIPH_BASE + 0x8850u)
            /* EFUSE_RD_MAC_SPI_SYS_0: chip ID 5 in bits [26:24] and [20:18] */
            return (0x5u << 24) | (0x5u << 18);
        return mmio32[off >> 2];
    }
    /* TIMG0/TIMG1/SYSTIMER (0x1F000-0x24000) */
    if (addr >= C3_PERIPH_BASE + 0x1F000u &&
        addr < C3_PERIPH_BASE + 0x24000u) {
        if (addr >= C3_PERIPH_BASE + 0x23000u) { /* SYSTIMER */
            switch (off - 0x23000u) {
            case SYSTIMER_CONF:
                return soc->systimer_conf;
            case SYSTIMER_VALUE_LO:
                return (uint32_t) soc->systimer_counter;
            case SYSTIMER_VALUE_HI:
                return (uint32_t) (soc->systimer_counter >> 32);
            case SYSTIMER_UNIT1_VALUE_LO:
                return (uint32_t) soc->systimer_unit1_counter;
            case SYSTIMER_UNIT1_VALUE_HI:
                return (uint32_t) (soc->systimer_unit1_counter >> 32);
            case SYSTIMER_TARGET0_LO:
                return (uint32_t) soc->systimer_comp0;
            case SYSTIMER_TARGET0_HI:
                return (uint32_t) (soc->systimer_comp0 >> 32);
            case SYSTIMER_TARGET2_LO:
                return (uint32_t) soc->systimer_comp2;
            case SYSTIMER_TARGET2_HI:
                return (uint32_t) (soc->systimer_comp2 >> 32);
            case SYSTIMER_TARGET0_CONF:
                return soc->systimer_target0_conf;
            case SYSTIMER_TARGET2_CONF:
                return soc->systimer_target2_conf;
            case SYSTIMER_INT_ENA:
                return soc->systimer_int_ena;
            case SYSTIMER_INT_RAW:
                return soc->systimer_int_raw;
            default:
                return mmio32[off >> 2];
            }
        }
        return mmio32[off >> 2];
    }
    /* INTC */
    if (addr >= C3_PERIPH_BASE + 0xC2000u &&
        addr < C3_PERIPH_BASE + 0xC3000u) {
        uint32_t o = off - 0xC2000u;
        if (o < 52 * 4u)
            return soc->intc_intmap[o >> 2];
        switch (o) {
        case INTC_INTR_STATUS:
            return (uint32_t) soc->intc_status; /* raw pending sources 0-31 */
        case INTC_INTR_STATUS_1:
            return (uint32_t) (soc->intc_status >> 32); /* sources 32-63 */
        case INTC_INT_ENABLE:
            return soc->intc_enable;
        case INTC_INT_TYPE:
            return soc->intc_type;
        default:
            return mmio32[off >> 2];
        }
    }
    /* SYSCON/APB_CTRL, SPIs, misc (0x24000-0x100000) */
    if (addr < C3_PERIPH_BASE + 0x100000u) {
        /* SHA accelerator (0x6003B000): busy poll + digest reads */
        if (addr == C3_PERIPH_BASE + 0x3B018u)
            return 0; /* SHA_BUSY: instant completion (poll spins while 1) */
        if (addr >= C3_PERIPH_BASE + 0x3B040u &&
            addr < C3_PERIPH_BASE + 0x3B060u) {
            uint32_t w = esp32_sha_digest_word((addr - C3_PERIPH_BASE - 0x3B040u) >> 2);
            {
                static int dumped;
                if (!dumped && sha_len > 1000) {
                    dumped = 1;
                    FILE *f = fopen("/tmp/sha_msg.bin", "wb");
                    fwrite(sha_msg, 1, sha_len, f);
                    fclose(f);
                    fprintf(stderr, "DBG: dumped sha_msg len=%u\n", sha_len);
                }
                if (sha_len > 200000) {
                    FILE *f = fopen("/tmp/sha_msg_app.bin", "wb");
                    fwrite(sha_msg, 1, sha_len, f);
                    fclose(f);
                    fprintf(stderr, "DBG: dumped app sha_msg len=%u\n", sha_len);
                }
            }
            if (0) fprintf(stderr, "DBG: sha-digest addr=0x%08x w[%d]=0x%08x len=%u\n",
                    addr, (addr - C3_PERIPH_BASE - 0x3B040u) >> 2, w,
                    sha_len);
            sha_reset_pending = 1;
            return w;
        }
        /* ROM flash access via APB-aliased SPI0 regs: report commands done */
        if (0 && addr >= C3_PERIPH_BASE + 0xC400u && addr < C3_PERIPH_BASE + 0xC600u)
            fprintf(stderr, "DBG: spi0rd pc=0x%08x addr=0x%08x\n", dbg_pc, addr);
        if (addr == C3_PERIPH_BASE + 0xC401Cu)
            return 0x4; /* SPI0_CMD: done */
        if (addr == C3_PERIPH_BASE + 0xC4028u)
            return 0x3; /* SPI0_CMD2: started + done */
        if (addr == C3_PERIPH_BASE + 0xC4034u)
            return 0x2; /* SPI0 data: ready */
        if (addr == C3_PERIPH_BASE + 0xC4040u)
            return 0x8; /* SPI0_STATUS: ready */
        if (addr == C3_PERIPH_BASE + 0xC40B0u)
            return 0x1; /* SPI0: wait condition met */
        return mmio32[off >> 2];
    }
    return mmio32[off >> 2];
}

static void esp32_mmio_write(riscv_t *rv, uint32_t addr, uint32_t val)
{
    esp32c3_t *soc = PRIV(rv)->esp32c3;
    if (addr < C3_PERIPH_BASE || addr >= C3_PERIPH_BASE + C3_PERIPH_SIZE)
        return; /* unmapped: writes are discarded */
    uint32_t off = addr - C3_PERIPH_BASE;
    uint32_t *mmio32 = (uint32_t *) soc->mmio;

    /* UART0 */
    if (addr < C3_PERIPH_BASE + 0x1000u) {
        if (off == UART_FIFO_REG) {
            fprintf(stderr, "DBG: uart-tx pc=0x%08x c=%02x\n", rv->PC,
                    val & 0xFFu);
            esp32_uart_putc(soc, (char) (val & 0xFFu));
        } else
            mmio32[off >> 2] = val;
        return;
    }
    /* SPI0/SPI1 (flash) */
    if (addr < C3_PERIPH_BASE + 0x4000u) {
        mmio32[off >> 2] = val;
        if (addr == C3_PERIPH_BASE + 0x2000u && (val & 0x40000u)) {
            /* SPI_USR command trigger: service the command into W0.. */
            uint32_t *w = mmio32 + (0x2058u >> 2); /* SPI_MEM_W0 (0x60002058) */
            uint32_t cmd = mmio32[0x2020u >> 2] & 0xFFFFu;
            uint32_t miso = (mmio32[0x2028u >> 2] & 0x3FFu) + 1u;
            uint32_t nbytes = (miso + 7u) / 8u;
            fprintf(stderr,
                    "DBG: spicmd pc=0x%08x cmd=0x%02x misolen=%u addr=0x%08x "
                    "user=0x%08x user1=0x%08x ra=0x%08x sp=0x%08x\n",
                    rv->PC, cmd, miso, mmio32[0x2004u >> 2],
                    mmio32[0x2018u >> 2], mmio32[0x201Cu >> 2], rv->X[1],
                    rv->X[2]);
            if (nbytes > 64u)
                nbytes = 64u;
            esp32_region_t *fi = esp32_find_region(soc, C3_FLASH_D_BASE);
            memset(w, 0, nbytes);
            if (cmd == 0x9Fu) {
                /* RDID: JEDEC ID (Winbond W25Q32: 0xEF 0x40 0x16) */
                w[0] = 0x1640EFu;
            } else if (cmd == 0x05u) {
                w[0] = soc->flash_sr; /* RDSR */
            } else if (cmd == 0x35u) {
                w[0] = soc->flash_sr2; /* RDSR2 */
            } else if (cmd == 0x06u) {
                soc->flash_sr |= 0x02u; /* WREN: set WEL */
            } else if (cmd == 0x04u) {
                soc->flash_sr &= ~0x02u; /* WRDI: clear WEL */
            } else if (cmd == 0x01u) {
                /* WRSR: 2 status bytes in W0 (written by driver as MOSI
                 * data before the command trigger) */
                soc->flash_sr = w[0] & 0xFFu;
                soc->flash_sr2 = (w[0] >> 8) & 0xFFu;
                soc->flash_sr &= ~0x02u; /* WRSR clears WEL */
            } else if (cmd == 0x31u) {
                soc->flash_sr2 = w[0] & 0xFFu; /* WRSR2 */
            } else if (cmd == 0x03u || cmd == 0x0Bu || cmd == 0x3Bu ||
                       cmd == 0x6Bu || cmd == 0xEBu) {
                /* flash read commands: copy from flash image */
                uint32_t faddr = mmio32[0x2004u >> 2];
                if (faddr < C3_FLASH_SIZE)
                    memcpy(w, fi->data + faddr, nbytes);
            }
            if (0) fprintf(stderr, "DBG: spiw0 cmd=0x%02x w0=0x%08x\n", cmd, w[0]);
            mmio32[off >> 2] = 0; /* CMD self-clears when done */
        }
        return;
    }
    /* GPIO */
    if (addr < C3_PERIPH_BASE + 0x5000u) {
        switch (off - 0x4000u) {
        case GPIO_OUT_REG:
            soc->gpio_out = val;
            break;
        case GPIO_OUT_W1TS:
            soc->gpio_out |= val;
            break;
        case GPIO_OUT_W1TC:
            soc->gpio_out &= ~val;
            break;
        case GPIO_ENABLE_REG:
            soc->gpio_enable = val;
            break;
        case GPIO_ENABLE_W1TS:
            soc->gpio_enable |= val;
            break;
        case GPIO_ENABLE_W1TC:
            soc->gpio_enable &= ~val;
            break;
        default:
            mmio32[off >> 2] = val;
            return;
        }
        if (esp32c3_gpio_output) {
            for (int pin = 0; pin < 22; pin++) {
                if (soc->gpio_enable & (1u << pin))
                    esp32c3_gpio_output(pin, !!(soc->gpio_out & (1u << pin)));
            }
        }
        return;
    }
    /* RTC_CNTL / IO_MUX / eFuse / RTC_I2C */
    if (addr < C3_PERIPH_BASE + 0xF000u) {
        mmio32[off >> 2] = val;
        return;
    }
    /* TIMG0/TIMG1/SYSTIMER (0x1F000-0x24000) */
    if (addr >= C3_PERIPH_BASE + 0x1F000u &&
        addr < C3_PERIPH_BASE + 0x24000u) {
        if (addr < C3_PERIPH_BASE + 0x23000u) { /* TIMG0/TIMG1 */
            mmio32[off >> 2] = val;
            /* TIMG0 RTC calibration (0x6001F068 = RTCCALICFG): complete
             * instantly when software raises the START bit. The real
             * hardware counts XTAL (40 MHz) cycles over `slowclk_cycles`
             * cycles of the selected slow clock; rtc_clk_cal_internal then
             * reads CALI_VALUE (0x6001F06C bits [31:7]) and waits on the
             * RDY (bit 15) / bit 19 / RTCCALICFG2 TIMEOUT (bit 0) flags. */
            if (addr == C3_PERIPH_BASE + 0x1F068u && (val & 0x80000000u)) {
                uint32_t max_cycles = (val >> 16) & 0x7FFFu;
                uint32_t clk_sel = (val >> 13) & 0x3u;
                uint64_t slow_freq;
                switch (clk_sel) {
                case 0:  slow_freq = 32768u;    break; /* SLOW_CLK mux (32k here) */
                case 1:  slow_freq = 8500000u;  break; /* RC_FAST (8M) */
                default: slow_freq = 32768u;    break; /* XTAL 32k */
                }
                uint64_t count = (uint64_t) max_cycles * 40000000u / slow_freq;
                if (!count)
                    count = 1;
                mmio32[(off + 4) >> 2] = (uint32_t) (count << 7) | 1u;
                mmio32[off >> 2] |= 0x00080000u | 0x8000u; /* bit19 + RDY */
            }
            return;
        }
        switch (off - 0x23000u) {
        case SYSTIMER_CONF:
            soc->systimer_conf = val;
            return;
        case SYSTIMER_UNIT0_OP:
            mmio32[off >> 2] = val;
            if (val & 0x40000000u) { /* UPDATE: latch counter, set VALUE_VALID */
                soc->systimer_unit0_val = soc->systimer_counter;
                mmio32[off >> 2] |= 0x20000000u; /* bit29 VALUE_VALID */
            }
            return;
        case SYSTIMER_UNIT1_OP:
            mmio32[off >> 2] = val;
            if (val & 0x40000000u) { /* UPDATE: latch counter, set VALUE_VALID */
                soc->systimer_unit1_val = soc->systimer_counter;
                mmio32[off >> 2] |= 0x20000000u; /* bit29 VALUE_VALID */
            }
            return;
        case SYSTIMER_TARGET0_LO:
            soc->systimer_comp0 =
                (soc->systimer_comp0 & ~0xFFFFFFFFull) | val;
            return;
        case SYSTIMER_TARGET0_HI:
            soc->systimer_comp0 =
                (soc->systimer_comp0 & 0xFFFFFFFFull) |
                ((uint64_t) val << 32);
            return;
        case SYSTIMER_TARGET0_CONF:
            soc->systimer_target0_conf = val;
            return;
        case SYSTIMER_TARGET2_LO:
            soc->systimer_comp2 =
                (soc->systimer_comp2 & ~0xFFFFFFFFull) | val;
            return;
        case SYSTIMER_TARGET2_HI:
            soc->systimer_comp2 =
                (soc->systimer_comp2 & 0xFFFFFFFFull) |
                ((uint64_t) val << 32);
            return;
        case SYSTIMER_TARGET2_CONF:
            soc->systimer_target2_conf = val;
            return;
        case SYSTIMER_INT_ENA:
            soc->systimer_int_ena = val;
            return;
        case SYSTIMER_INT_CLR:
            soc->systimer_int_raw &= ~val;
            soc->intc_status &= ~((1ull << SYSTIMER_T0_SOURCE) |
                                  (1ull << SYSTIMER_T2_SOURCE));
            return;
        default:
            mmio32[off >> 2] = val;
            return;
        }
    }
    /* INTC */
    if (addr >= C3_PERIPH_BASE + 0xC2000u &&
        addr < C3_PERIPH_BASE + 0xC3000u) {
        uint32_t o = off - 0xC2000u;
        if (o < 52 * 4u) {
            soc->intc_intmap[o >> 2] = val;
            if ((o >> 2) == 50)
                fprintf(stderr, "DBG: intmap50 pc=0x%08x val=%u\n", rv->PC, val);
            return;
        }
        switch (o) {
        case INTC_INT_ENABLE:
            soc->intc_enable = val;
            fprintf(stderr, "DBG: intc-enable pc=0x%08x val=%08x\n", rv->PC, val);
            return;
        case INTC_INT_TYPE:
            soc->intc_type = val;
            return;
        case INTC_INT_CLEAR:
            soc->intc_eip &= ~val; /* flush claimed state of the line */
            soc->intc_status &= (uint64_t) (~val);
            return;
        default:
            mmio32[off >> 2] = val;
            return;
        }
    }
    if (addr < C3_PERIPH_BASE + 0x100000u) {
        /* SYSTEM_CPU_INTR_FROM_CPU_0 (0x600C0028): crosscore interrupt
         * trigger. Writing 1 raises INTC source 50, writing 0 clears it
         * (the ISR acknowledges by clearing it, see esp_crosscore_isr). */
        if (addr == C3_PERIPH_BASE + 0xC0028u) {
            if (val & 1u)
                soc->intc_status |= 1ULL << 50u;
            else
                soc->intc_status &= ~(1ULL << 50u);
            mmio32[off >> 2] = val;
            {
                static unsigned long cc;
                if ((cc++ & 0xFFFu) == 0)
                    fprintf(stderr, "DBG: crosscore-trigger val=%u pc=0x%08x cycle=%llu\n",
                            val, rv->PC, (unsigned long long) rv->csr_cycle);
            }
            return;
        }
        /* SHA accelerator (0x6003B000) */
        if (addr == C3_PERIPH_BASE + 0x3B000u) { /* SHA_MODE: new session */
            if (sha_reset_pending) {
                esp32_sha_reset();
                sha_reset_pending = 0;
            }
            fprintf(stderr, "DBG: sha-mode val=0x%08x len=%u\n", val, sha_len);
            mmio32[off >> 2] = val;
            return;
        }
        if (addr == C3_PERIPH_BASE + 0x3B010u) { /* SHA_START */
            fprintf(stderr, "DBG: sha-start val=0x%08x len=%u\n", val, sha_len);
            mmio32[off >> 2] = val;
            return;
        }
        if (addr == C3_PERIPH_BASE + 0x3B014u) { /* SHA_CONTINUE */
            fprintf(stderr, "DBG: sha-cont val=0x%08x len=%u\n", val, sha_len);
            mmio32[off >> 2] = val;
            return;
        }
        if (addr >= C3_PERIPH_BASE + 0x3B040u &&
            addr < C3_PERIPH_BASE + 0x3B0C0u) { /* SHA message words */
            esp32_sha_feed_word(val);
            fprintf(stderr, "DBG: sha-feed addr=0x%08x val=0x%08x len=%u\n",
                    addr, val, sha_len);
            mmio32[off >> 2] = val;
            return;
        }
        /* SPI0 flash op state reg: rising edge of start sets done,
         * falling edge of start clears done */
        if (addr == C3_PERIPH_BASE + 0xC40CCu) {
            uint32_t prev = mmio32[off >> 2];
            mmio32[off >> 2] = val & ~4u;
            if ((val & 3u) && !(prev & 3u))
                mmio32[off >> 2] |= 4u;
            else if (!(val & 3u) && (prev & 3u))
                mmio32[off >> 2] &= ~4u;
            return;
        }
        mmio32[off >> 2] = val;
        return;
    }
    mmio32[off >> 2] = val;
}

/* ------------------------------------------------------------------ */
/* Memory accessors (io callbacks)                                     */
/* ------------------------------------------------------------------ */

static inline esp32_region_t *esp32_lookup(riscv_t *rv, uint32_t addr)
{
    return esp32_find_region(PRIV(rv)->esp32c3, addr);
}

/* Flash cache window translation: the d-cache (0x3C000000) and i-cache
 * (0x42000000) windows map through the MMU (64KB pages). The bootloader's
 * spiflash_mmap programs mmu[page] = flash_page, then reads the image via
 * window page 0. The 0x3C7E0000 alias stays linear (ROM usage).
 * Returns the flash buffer index, or ~0u for non-window addresses. */
static inline uint32_t esp32_flash_window_off(esp32c3_t *soc, uint32_t addr)
{
    if ((addr >= C3_FLASH_D_BASE && addr < C3_FLASH_D_BASE + C3_FLASH_SIZE) ||
        (addr >= C3_FLASH_I_BASE && addr < C3_FLASH_I_BASE + C3_FLASH_SIZE) ||
        (addr >= 0x3C7F0000u && addr < 0x3C800000u)) {
        uint32_t off = soc->mmu[(addr >> 16) & 0x7Fu] * 0x10000u + (addr & 0xFFFFu);
        return (off < C3_FLASH_SIZE) ? off : (addr & 0xFFFFu);
    }
    return ~0u;
}

uint32_t esp32_read_w(riscv_t *rv, uint32_t addr)
{
    esp32_region_t *r = esp32_lookup(rv, addr);
    if (!r || r->type != ESP32_REG_RAM) {
        dbg_pc = rv->PC;
        if (addr == 0x60004038u)
            fprintf(stderr, "DBG: strap-val pc=0x%08x -> 0x%08x\n", rv->PC,
                    esp32_mmio_read(PRIV(rv)->esp32c3, addr));
       if (addr == 0x60008010u) {
           static unsigned long n;
           if ((n++ & 0xFFFu) == 0)
               fprintf(stderr,
                       "DBG: rtc-get rtc=%llu cycle=%llu s0=%08x s3=%08x pc=0x%08x\n",
                       (unsigned long long) PRIV(rv)->esp32c3->rtc_time,
                       (unsigned long long) rv->csr_cycle, rv->X[8], rv->X[19],
                       rv->PC);
       }
       if (rv->csr_cycle < 10000000u && (rv->csr_cycle & 0xFFFu) == 0)
           fprintf(stderr, "DBG: mrd-w pc=0x%08x addr=0x%08x\n", rv->PC, addr);
       if (0 && rv->csr_cycle >= 10000000u && (rv->csr_cycle & 0xFFFu) == 0)
           fprintf(stderr, "DBG: mrd-x pc=0x%08x addr=0x%08x\n", rv->PC, addr);
        if (addr >= 0x6003B000u && addr < 0x6003C000u)
            fprintf(stderr, "DBG: sha-rd-in pc=0x%08x addr=0x%08x\n", rv->PC,
                    addr);
        {
            uint32_t v = esp32_mmio_read(PRIV(rv)->esp32c3, addr);
            if (addr >= 0x60008800u && addr < 0x60008880u)
                fprintf(stderr, "DBG: efuse-rd pc=0x%08x addr=0x%08x val=0x%08x\n",
                        rv->PC, addr, v);
            return v;
        }
    }
    if (addr == 0x60004038u)
        fprintf(stderr, "DBG: strap-read pc=0x%08x\n", rv->PC);
    uint32_t val;
    uint32_t off = esp32_flash_window_off(PRIV(rv)->esp32c3, addr);
    if (off == ~0u)
        off = addr - r->base;
    memcpy(&val, r->data + off, 4);
    if (addr >= 0x3C7E0000u && addr < 0x3C800000u && rv->PC == 0x403cf4acu)
        fprintf(stderr, "DBG: alias-rd pc=0x%08x addr=0x%08x val=0x%08x\n",
                rv->PC, addr, val);
    if (addr >= C3_FLASH_I_BASE && addr < C3_FLASH_I_BASE + 0x1000u)
        fprintf(stderr, "DBG: flash-read  pc=0x%08x addr=0x%08x val=0x%08x\n",
                rv->PC, addr, val);
    if (addr >= C3_FLASH_I_BASE + 0x1000u && addr < C3_FLASH_I_BASE + 0x200000u)
        fprintf(stderr, "DBG: flash-read  pc=0x%08x addr=0x%08x val=0x%08x\n",
                rv->PC, addr, val);
    if (addr >= C3_FLASH_D_BASE && addr < C3_FLASH_D_BASE + 0x200000u)
        fprintf(stderr, "DBG: flashd-read pc=0x%08x addr=0x%08x val=0x%08x\n",
                rv->PC, addr, val);
    return val;
}

uint16_t esp32_read_s(riscv_t *rv, uint32_t addr)
{
    esp32_region_t *r = esp32_lookup(rv, addr);
    if (!r || r->type != ESP32_REG_RAM) {
        if (addr == 0x600C4034u)
            fprintf(stderr, "DBG: mrd-h pc=0x%08x addr=0x%08x\n", rv->PC, addr);
        return (uint16_t) esp32_mmio_read(PRIV(rv)->esp32c3, addr);
    }
    if (rv->PC >= 0x403d0000u && rv->PC < 0x403d0560u &&
        addr >= C3_FLASH_D_BASE && addr < C3_FLASH_D_BASE + 0x10000u) {
        uint32_t off = esp32_flash_window_off(PRIV(rv)->esp32c3, addr);
        uint16_t v;
        memcpy(&v, r->data + off, 2);
        fprintf(stderr, "DBG: verify-s pc=0x%08x addr=0x%08x val=0x%04x\n",
                rv->PC, addr, v);
    }
    if (addr == 0x60004038u)
        fprintf(stderr, "DBG: strap-read-s pc=0x%08x\n", rv->PC);
    if (rv->PC >= 0x403cf000u && rv->PC < 0x403d0560u &&
        addr >= 0x3c7e0000u && addr < 0x3c7f0000u) {
        fprintf(stderr, "DBG: verify-l pc=0x%08x addr=0x%08x val=0x%08x\n",
                rv->PC, addr,
                *(uint32_t *)(r->data + (addr - r->base)));
    }
    if (rv->PC >= 0x403cf000u && rv->PC < 0x403d0560u &&
        addr >= 0x3c7f0000u && addr < 0x3c800000u) {
        fprintf(stderr, "DBG: verify-m pc=0x%08x addr=0x%08x val=0x%08x\n",
                rv->PC, addr,
                *(uint32_t *)(r->data + (addr - r->base)));
    }
    uint16_t val;
    uint32_t off = esp32_flash_window_off(PRIV(rv)->esp32c3, addr);
    if (off == ~0u)
        off = addr - r->base;
    memcpy(&val, r->data + off, 2);
    if (addr >= C3_FLASH_I_BASE && addr < C3_FLASH_I_BASE + 0x1000u)
        fprintf(stderr, "DBG: flash-reads pc=0x%08x addr=0x%08x val=0x%04x\n",
                rv->PC, addr, val);
    return val;
}

uint8_t esp32_read_b(riscv_t *rv, uint32_t addr)
{
    esp32_region_t *r = esp32_lookup(rv, addr);
    if (!r || r->type != ESP32_REG_RAM) {
        if (addr == 0x600C4034u)
            fprintf(stderr, "DBG: mrd-b pc=0x%08x addr=0x%08x\n", rv->PC, addr);
        return (uint8_t) esp32_mmio_read(PRIV(rv)->esp32c3, addr);
    }
    if (addr == 0x60004038u)
        fprintf(stderr, "DBG: strap-read-b pc=0x%08x\n", rv->PC);
    if (rv->PC >= 0x403cf180u && rv->PC < 0x403cf200u)
        fprintf(stderr, "DBG: chkrd-b pc=0x%08x addr=0x%08x val=0x%02x\n",
                rv->PC, addr, r->data[addr - r->base]);
    if (addr >= C3_FLASH_I_BASE && addr < C3_FLASH_I_BASE + 0x1000u)
        fprintf(stderr, "DBG: flash-readb pc=0x%08x addr=0x%08x val=0x%02x\n",
                rv->PC, addr, r->data[addr - r->base]);
    if (rv->PC >= 0x403cf000u && rv->PC < 0x403d0560u &&
        addr >= C3_FLASH_D_BASE && addr < C3_FLASH_D_BASE + 0x10000u &&
        addr != 0x3c000020u) {
        uint32_t off = esp32_flash_window_off(PRIV(rv)->esp32c3, addr);
        fprintf(stderr, "DBG: verify-b pc=0x%08x addr=0x%08x val=0x%02x\n",
                rv->PC, addr, r->data[off]);
    }
    uint32_t off = esp32_flash_window_off(PRIV(rv)->esp32c3, addr);
    if (off == ~0u)
        off = addr - r->base;
    return r->data[off];
}

static uint32_t dbg_pc;
static int acc_writes;
static uint32_t last_acc;

static void acc_trace_write(riscv_t *rv, uint32_t addr, uint32_t val)
{
    if (addr == 0x3fcde508u) {
        if (acc_writes < 8 || (val != last_acc && acc_writes < 4000)) {
            fprintf(stderr, "DBG: accw %d pc=0x%08x val=0x%08x\n", acc_writes, rv->PC, val);
        }
        last_acc = val;
        acc_writes++;
    }
}

void esp32_write_w(riscv_t *rv, uint32_t addr, uint32_t val)
{
    esp32c3_t *soc = PRIV(rv)->esp32c3;
    if (addr >= C3_MMU_TABLE_BASE && addr < C3_MMU_TABLE_END) {
        uint32_t idx = (addr - C3_MMU_TABLE_BASE) >> 2;
        soc->mmu[idx] = val;
        if (rv->PC >= 0x403cf000u && rv->PC < 0x403d1000u)
            fprintf(stderr, "DBG: mmu-w idx=%u page=0x%08x pc=0x%08x\n", idx,
                    val, rv->PC);
        return;
    }
    if (addr >= 0x3FCDF100u && addr < 0x3FCDF130u)
        fprintf(stderr, "DBG: write[0x%08x]=0x%08x from pc=0x%08x\n", addr,
                val, rv->PC);
    if (addr >= 0x3FCD5800u && addr < 0x3FCD5820u)
        fprintf(stderr, "DBG: hdr-wr[0x%08x]=0x%08x from pc=0x%08x\n", addr,
                val, rv->PC);
    if (rv->PC >= 0x40057e52u && rv->PC < 0x40057f10u)
        fprintf(stderr, "DBG: mcpy-wr[0x%08x]=0x%08x from pc=0x%08x\n", addr,
                val, rv->PC);
    esp32_region_t *r = esp32_lookup(rv, addr);
    if (!r || r->type != ESP32_REG_RAM) {
        esp32_mmio_write(rv, addr, val);
        return;
    }
    acc_trace_write(rv, addr, val);
    if (addr >= 0x3fcde594u && addr <= 0x3fcde5c0u)
        fprintf(stderr, "DBG: shdr-w pc=0x%08x addr=0x%08x val=0x%08x\n",
                rv->PC, addr, val);
    memcpy(r->data + (addr - r->base), &val, 4);
}

void esp32_write_s(riscv_t *rv, uint32_t addr, uint16_t val)
{
    esp32_region_t *r = esp32_lookup(rv, addr);
    if (!r || r->type != ESP32_REG_RAM) {
        esp32_mmio_write(rv, addr, val);
        return;
    }
    memcpy(r->data + (addr - r->base), &val, 2);
}

void esp32_write_b(riscv_t *rv, uint32_t addr, uint8_t val)
{
    esp32_region_t *r = esp32_lookup(rv, addr);
    if (!r || r->type != ESP32_REG_RAM) {
        esp32_mmio_write(rv, addr, val);
        return;
    }
    r->data[addr - r->base] = val;
}

uint32_t esp32_ifetch(riscv_t *rv, uint32_t addr)
{
    static uint32_t hist[32];
    static int hist_i;
    hist[hist_i++ & 31] = rv->PC;
    if (rv->PC == 0x403d04c0u) {
        fprintf(stderr,
                "DBG: cpyloop s3=0x%08x s10=0x%08x s2=0x%08x s8=0x%08x s6=0x%08x "
                "s5=0x%08x s9=0x%08x s4=0x%08x s11=0x%08x s0=0x%08x\n",
                rv->X[19], rv->X[26], rv->X[18], rv->X[24], rv->X[22], rv->X[21],
                rv->X[25], rv->X[20], rv->X[27], rv->X[8]);
    }
    if (rv->PC == 0x403d07e6u) {
        uint32_t sp = rv->X[2];
        esp32_region_t *rr = esp32_lookup(rv, 0x3fcde508);
        uint32_t acc = 0;
        if (rr && rr->type == ESP32_REG_RAM) {
            memcpy(&acc, rr->data + 0x3fcde508 - rr->base, 4);
            fprintf(stderr,
                    "DBG: err a3=0x%08x a4=0x%08x acc(3fcde508)=0x%08x s2=0x%08x "
                    "s3=0x%08x s9=0x%08x s4=0x%08x s1=0x%08x s8=0x%08x s10=0x%08x "
                    "sp=0x%08x nacc=%d\n",
                    rv->X[13], rv->X[14], acc, rv->X[18], rv->X[19], rv->X[25],
                    rv->X[20], rv->X[9], rv->X[24], rv->X[26], sp, acc_writes);
        }
    }
    {
        static uint32_t lastblk = ~0u;
        static uint32_t bhist[16384];
        static int bn;
        if (rv->PC != lastblk && bn < 16384) {
            uint32_t t = rv->PC;
            for (int i = 0; i < bn; i++)
                if (bhist[i] == t)
                    goto have_b;
            bhist[bn++] = t;
            fprintf(stderr, "DBG: boot-blk %03d 0x%08x\n", bn, t);
        }
        lastblk = rv->PC;
    have_b:
        ;
    }
    if (rv->PC >= 0x4004949au && rv->PC <= 0x40049700u) {
        static uint32_t last_pc;
        if (rv->PC != last_pc) {
            fprintf(stderr, "DBG: load-trace 0x%08x\n", rv->PC);
            last_pc = rv->PC;
        }
    }
    if (addr == 0) {
        fprintf(stderr, "DBG: jump to PC=0 from 0x%08x, history:",
                rv->PC);
        for (int i = 0; i < 32; i++)
            fprintf(stderr, " 0x%08x", hist[(hist_i + i) & 31]);
        fprintf(stderr, "\n");
    }
    esp32_region_t *r = esp32_lookup(rv, addr);
    if (!r || r->type != ESP32_REG_RAM) {
        /* code fetch outside RAM: decode as 0 (illegal) and log once */
        fprintf(stderr,
                "esp32c3: ifetch at non-RAM 0x%08x (guest pc=0x%08x, r=%p)\n",
                addr, rv->PC, (void *) r);
        return 0;
    }
    uint32_t val;
    uint32_t off = esp32_flash_window_off(PRIV(rv)->esp32c3, addr);
    if (off == ~0u)
        off = addr - r->base;
    memcpy(&val, r->data + off, 4);
    return val;
}

static uint32_t esp32_translate(riscv_t *rv, uint32_t vaddr, bool rw)
{
    (void) rv;
    (void) rw;
    return vaddr; /* bare metal: identity */
}

void esp32c3_install_io(riscv_t *rv)
{
    riscv_io_t io = {
        .mem_ifetch = esp32_ifetch,
        .mem_read_w = esp32_read_w,
        .mem_read_s = esp32_read_s,
        .mem_read_b = esp32_read_b,
        .mem_write_w = esp32_write_w,
        .mem_write_s = esp32_write_s,
        .mem_write_b = esp32_write_b,
        .mem_translate = esp32_translate,
        .mmu_read_w = esp32_read_w,
        .mmu_read_s = esp32_read_s,
        .mmu_read_b = esp32_read_b,
        .mmu_write_w = esp32_write_w,
        .mmu_write_s = esp32_write_s,
        .mmu_write_b = esp32_write_b,
        .on_ecall = NULL,
        .on_ebreak = NULL,
        .on_memcpy = NULL,
        .on_memset = NULL,
        .on_trap = trap_handler,
    };
    memcpy(&rv->io, &io, sizeof(riscv_io_t));
}

/* ------------------------------------------------------------------ */
/* ELF loading                                                         */
/* ------------------------------------------------------------------ */

typedef struct {
    uint8_t e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint32_t e_entry;
    uint32_t e_phoff;
    uint32_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} esp32_elf32_hdr_t;

typedef struct {
    uint32_t p_type;
    uint32_t p_offset;
    uint32_t p_vaddr;
    uint32_t p_paddr;
    uint32_t p_filesz;
    uint32_t p_memsz;
    uint32_t p_flags;
    uint32_t p_align;
} esp32_elf32_phdr_t;

uint32_t esp32c3_boot(esp32c3_t *soc, const char *elf_path)
{
    /* Full flash-image boot (ROM reset vector -> bootloader -> app) */
    if (esp32c3_flash_image_path) {
        FILE *f = fopen(esp32c3_flash_image_path, "rb");
        if (!f) {
            fprintf(stderr, "esp32c3: cannot open flash image %s\n",
                    esp32c3_flash_image_path);
            exit(EXIT_FAILURE);
        }
        esp32_region_t *fd = esp32_find_region(soc, C3_FLASH_D_BASE);
        size_t got = fread(fd->data, 1, C3_FLASH_SIZE, f);
        fclose(f);
        fprintf(stderr, "esp32c3: loaded %zu bytes of flash image\n", got);
        /* boot from the ROM reset vector: ROM code initializes the system
         * (timer structs, SYSTIMER, UART, clocks) then loads the 2nd-stage
         * bootloader from flash offset 0 and jumps to the app. */
        return C3_ROM_BASE;
    }

    FILE *f = fopen(elf_path, "rb");
    if (!f) {
        fprintf(stderr, "esp32c3: cannot open %s\n", elf_path);
        exit(EXIT_FAILURE);
    }
    esp32_elf32_hdr_t hdr;
    if (fread(&hdr, 1, sizeof(hdr), f) != sizeof(hdr) ||
        memcmp(hdr.e_ident, "\x7f" "ELF", 4) != 0) {
        fprintf(stderr, "esp32c3: %s is not an ELF32 file\n", elf_path);
        exit(EXIT_FAILURE);
    }
    for (int i = 0; i < hdr.e_phnum; i++) {
        esp32_elf32_phdr_t ph;
        if (fseek(f, hdr.e_phoff + i * hdr.e_phentsize, SEEK_SET) ||
            fread(&ph, 1, sizeof(ph), f) != sizeof(ph))
            break;
        if (ph.p_type != 1) /* PT_LOAD */
            continue;
        uint32_t vaddr = ph.p_vaddr;
        uint32_t sz = ph.p_memsz;
        /* write into regions, allowing segments spanning regions (flash) */
        for (uint32_t pos = 0; pos < sz;) {
            esp32_region_t *r = esp32_find_region(soc, vaddr + pos);
            if (!r || r->type != ESP32_REG_RAM) {
                fprintf(stderr,
                        "esp32c3: ELF segment at 0x%08x outside RAM\n",
                        vaddr + pos);
                exit(EXIT_FAILURE);
            }
            uint32_t chunk = r->base + r->size - (vaddr + pos);
            if (chunk > sz - pos)
                chunk = sz - pos;
            uint32_t in_flash = pos < ph.p_filesz ? ph.p_filesz - pos : 0;
            uint32_t copy = in_flash < chunk ? in_flash : chunk;
            if (copy) {
                if (fseek(f, ph.p_offset + pos, SEEK_SET) ||
                    fread(r->data + (vaddr + pos - r->base), 1, copy, f) !=
                        copy) {
                    fprintf(stderr, "esp32c3: ELF segment read failed\n");
                    exit(EXIT_FAILURE);
                }
            }
            pos += chunk;
        }
    }
    fclose(f);
    return hdr.e_entry;
}

/* ------------------------------------------------------------------ */
/* Interrupt delivery                                                  */
/* ------------------------------------------------------------------ */

/* Route enabled pending INTC sources to CPU interrupt lines (mip). */
static uint32_t esp32_intc_raise(esp32c3_t *soc)
{
    uint64_t pending = soc->intc_status;
    uint32_t lines = 0;
    for (int s = 0; s < 52; s++)
        if (pending & (1ULL << s))
            lines |= 1u << (soc->intc_intmap[s] & 0x1Fu);
    /* Clear EIP for lines that no longer have a pending source. */
    soc->intc_eip &= lines;
    uint32_t raise = 0;
    for (int s = 0; s < 52; s++) {
        if (pending & (1ULL << s)) {
            int line = soc->intc_intmap[s] & 0x1Fu;
            if (line >= 1 && line < 31 && (soc->intc_enable & (1u << line)) &&
                !(soc->intc_eip & (1u << line)))
                raise |= 1u << line;
        }
    }
    return raise;
}

void esp32c3_check_interrupt(riscv_t *rv)
{
    esp32c3_t *soc = PRIV(rv)->esp32c3;
    if (!soc)
        return;
    if (!(rv->csr_mstatus & MSTATUS_MIE))
        return;
    rv->csr_mip = (rv->csr_mip & ~0x7FFFFFFEu) | esp32_intc_raise(soc);
    /* The ESP32-C3 does not use the CSR mie (the app never writes it); the
     * INTC per-line enable (checked in esp32_intc_raise) plus mstatus.MIE
     * are the only gates. */
    uint32_t pending = rv->csr_mip;
    if (!pending)
        return;
    /* lowest set bit = CPU interrupt number */
    int idx = __builtin_ctz(pending);
    soc->intc_eip |= 1u << idx; /* claim the line (blocks re-delivery) */
    static unsigned long itr_count;
    if ((itr_count++ & 0x3FFu) == 0)
        fprintf(stderr, "DBG: int-trap idx=%d mstatus=%08x mie=%08x mip=%08x intc_status=%08llx eip=%08x mepc_target=%08x\n",
                idx, rv->csr_mstatus, rv->csr_mie, rv->csr_mip,
                (unsigned long long) soc->intc_status, soc->intc_eip, rv->PC);
    SET_CAUSE_AND_TVAL_THEN_TRAP(rv, ((1u << 31) | idx), 0);
}

void esp32c3_periodic(riscv_t *rv)
{
    esp32c3_t *soc = PRIV(rv)->esp32c3;
    if (!soc)
        return;

    /* advance SYSTIMER counters (both units free-run on the C3) */
    uint64_t elapsed = rv->csr_cycle - soc->last_cycle;
    soc->last_cycle = rv->csr_cycle;
    soc->systimer_counter += elapsed;
    soc->systimer_unit1_counter += elapsed;
    /* RTCCNTL_TIME counts slow-clock ticks; keep rtc_time_get() timeout loops
     * making progress regardless of emulated speed. Accumulate fractional
     * slow-clock ticks so small per-call elapsed values still count up. */
    uint64_t rtc_total = elapsed + soc->rtc_frac;
    soc->rtc_frac = rtc_total % 64u;
    soc->rtc_time += rtc_total / 64u;
    if (rv->PC == 0x403cf2f6u)
        fprintf(stderr, "DBG: boot-mmap pc=0x403cf2f6 a0(off)=0x%x a1(size)=0x%x\n",
                rv->X[10], rv->X[11]);
    if (rv->PC == 0x403cf0d6u)
        fprintf(stderr, "DBG: efuse-blkrev-check pc=0x403cf0d6 a0(min)=0x%x "
                "a1(max)=0x%x\n", rv->X[10], rv->X[11]);
    if (rv->PC == 0x403d051cu) {
        uint32_t s3 = rv->X[19];
        uint32_t a = s3 + 176;
        esp32_region_t *r = esp32_find_region(soc, a);
        uint32_t v = 0;
        if (r && a + 2 <= r->base + r->size)
            v = *(uint32_t *) (r->data + (a - r->base));
        fprintf(stderr, "DBG: efuse-lhu s3=0x%08x b176=%04x b178=%04x\n", s3,
                v & 0xFFFFu, v >> 16);
    }
    if ((rv->csr_cycle & 0x7FFFFFu) == 0)
        fprintf(stderr, "DBG: pc=0x%08x cycle=%llu rtc=%llu\n", rv->PC,
                (unsigned long long) rv->csr_cycle,
                (unsigned long long) soc->rtc_time);
    if (rv->PC == 0x42009b16u && (rv->csr_cycle & 0xFFFu) == 0)
        fprintf(stderr, "DBG: rtc-loop rtc=%llu cycle=%llu\n",
                (unsigned long long) soc->rtc_time,
                (unsigned long long) rv->csr_cycle);
    if (rv->PC == 0x403836beu)
        fprintf(stderr, "DBG: us2slow us=%08x freq=%08x\n", rv->X[10], rv->X[12]);

/* SYSTIMER alarms. The C3: alarm enables are SYSTIMER_CONF bits
 * (TARGET0_WORK_EN=24, TARGET2_WORK_EN=22); TIMER_UNIT_SEL (bit31 of the
 * per-target CONF) picks the counter unit; bit30 selects period mode
 * (fires every PERIOD ticks, period = CONF bits 25:0). The app's esp_timer
 * uses TARGET2/unit1 (INTC source 39); the FreeRTOS tick uses TARGET0 in
 * period mode with unit1 (source 37). */
    {
        uint64_t cnt0 = (soc->systimer_target0_conf & 0x80000000u)
                            ? soc->systimer_unit1_counter
                            : soc->systimer_counter;
        if (soc->systimer_conf & (1u << 24)) { /* TARGET0_WORK_EN */
            if (soc->systimer_target0_conf & 0x40000000u) {
                /* period mode: pulse once per period crossing */
                uint64_t p = soc->systimer_target0_conf & 0x03FFFFFFu;
                uint64_t crossed = p ? (cnt0 / p) : 0;
                if (crossed > soc->systimer_t0_crossed) {
                    soc->systimer_t0_crossed = crossed;
                    soc->systimer_int_raw |= 1u;
                    soc->intc_status |= 1ull << SYSTIMER_T0_SOURCE;
                }
            } else if (soc->systimer_comp0 && cnt0 >= soc->systimer_comp0) {
                soc->systimer_int_raw |= 1u;
                soc->intc_status |= 1ull << SYSTIMER_T0_SOURCE;
            }
        }
        uint64_t cnt2 = (soc->systimer_target2_conf & 0x80000000u)
                            ? soc->systimer_unit1_counter
                            : soc->systimer_counter;
        if (soc->systimer_conf & (1u << 22)) { /* TARGET2_WORK_EN */
            if (soc->systimer_target2_conf & 0x40000000u) {
                uint64_t p = soc->systimer_target2_conf & 0x03FFFFFFu;
                uint64_t crossed = p ? (cnt2 / p) : 0;
                if (crossed > soc->systimer_t2_crossed) {
                    soc->systimer_t2_crossed = crossed;
                    soc->systimer_int_raw |= 4u;
                    soc->intc_status |= 1ull << SYSTIMER_T2_SOURCE;
                }
            } else if (soc->systimer_comp2 && cnt2 >= soc->systimer_comp2) {
                soc->systimer_int_raw |= 4u;
                soc->intc_status |= 1ull << SYSTIMER_T2_SOURCE;
            }
        }
    }
}