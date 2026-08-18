/*
 * ESP32-C6 SoC model for rv32emu (MIT license, see LICENSE).
 *
 * Implements the memory map and the minimal peripheral set required to boot
 * ESP-IDF / Arduino firmware on the ESP32-C6:
 *
 *   - SRAM 0x40800000 (512 KB, single I/D-bus address)
 *   - LP-SRAM 0x50000000 (16 KB)
 *   - ROM 0x40000000 (embedded real ROM image)
 *   - Flash cache window 0x42000000 (irom+drom, MMU page table via
 *     SPI_MEM_MMU_ITEM_CONTENT/INDEX, page size 2^(16-mode))
 *   - Peripherals at 0x60000000+: UART0, SPI0/1, GPIO, eFuse, LP_CLKRST,
 *     SYSTIMER, SHA, interrupt matrix
 *   - PLIC/CLINT at 0x20001000/0x20001400/0x20001800/0x20001C00 plus the
 *     CPU-side PLIC alias at 0x80000404
 *
 * M-mode only, no MMU (identity addresses). Interrupts: SYSTIMER compare ->
 * interrupt matrix (INTMTX) -> PLIC gate -> mie/mip -> vectored mtvec
 * (all 32 vectors share one handler, so base-only trapping is fine).
 */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "esp32c6.h"
#include "esp32c6_rom.h"
#include "riscv_private.h"
#include "system.h" /* trap_handler */

/* ------------------------------------------------------------------ */
/* Memory model                                                        */
/* ------------------------------------------------------------------ */

/* Software SHA-256: the ROM feeds message blocks to the SHA accelerator
 * (0x60089080-0x600890BF = M_MEM), then reads the digest from H_MEM
 * (0x60089040-0x6008907F). SHA_MODE (0x60089000) is written before every
 * block, so a session is reset only on the first mode write after a digest
 * read. SHA_START (0x60089010) begins a session, SHA_CONTINUE (0x60089014)
 * appends; the final padded block is built and fed by the ROM itself. */
static uint8_t sha_msg[0x200000]; /* large enough for full app image hash */
static uint32_t sha_len;
static uint32_t sha_digest[8];
static int sha_computed;
static int sha_reset_pending;

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

struct esp32c6_soc {
    esp32_region_t regions[12];
    int nregions;

    /* peripheral register backing (MMIO) */
    uint8_t mmio[C6_PERIPH_SIZE];

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
    uint64_t last_cycle;

    /* LP_TIMER (0x600B0C00): RTC slow-clock 64-bit main timer */
    uint64_t lp_timer;

    /* CLINT (0x20001800): free-running MTIME + MSIP/MTIMECMP */
    uint64_t clint_mtime;
    uint64_t clint_mtimcmp;
    uint32_t clint_msip;

    /* SPI flash status registers (SR/SR2 incl. WEL and QE bits) */
    uint32_t flash_sr;
    uint32_t flash_sr2;

    /* interrupt matrix (INTMTX): peripheral source -> CPU line */
    uint32_t intc_intmap[64];
    uint64_t intc_status; /* pending peripheral sources */

    /* PLIC (0x20001000) */
    uint32_t plic_enable;
    uint32_t plic_type;
    uint32_t plic_prio[28];
    uint32_t plic_threshold;

    /* GPIO */
    uint32_t gpio_out;
    uint32_t gpio_enable;

    /* UART output buffering */
    char uart_line[256];
    int uart_line_len;

    /* I2C_EXT (0x60004000): register bank + SCL_RST_SLV_EN auto-clear */
    uint32_t i2c_reg[128]; /* 0x200 bytes, mirrors i2c_dev_t */
    int i2c_scl_rst_cnt;   /* reads left with SCL_RST_SLV_EN asserted */
    int i2c_transfer_pending; /* a trans_start was written; bus has no slave */

    /* SPI2 (GPSPI2, 0x60081000): register bank + transfer completion */
    uint32_t spi2_reg[64]; /* 0x100 bytes, mirrors spi_dev_t */
    int spi2_transfer_pending; /* a cmd.usr was written; bus has no slave */

    /* UART0 RX FIFO (128 bytes, ring) fed from the host injection file */
    uint8_t uart_rx[128];
    unsigned int uart_rx_head;
    unsigned int uart_rx_tail;
    int uart_rx_fd; /* host injection fd, -1 when not open */

    /* flash cache MMU page table: 256 x 64KB pages, programmed through
     * SPI_MEM_MMU_ITEM_CONTENT (0x6000237C) with page size
     * 2^(16-mode) (mode = SPI_MEM_MMU_PAGE_MODE bits[4:3]) */
    uint32_t mmu[256];
    uint32_t mmu_page_mode; /* bits [4:3] of 0x60002384 */
    uint32_t mmu_index;     /* last written MMU_ITEM_INDEX */
};

void (*esp32c6_uart_output)(char c) = NULL;
void (*esp32c6_gpio_output)(int pin, bool level) = NULL;

/* Optional flash image (bootloader @ 0x0 + partitions @ 0x8000 + app @
 * 0x10000). When set, the machine boots from the ROM reset vector. */
const char *esp32c6_flash_image_path = NULL;

/* Optional UART RX injection source (FIFO file the host writes to). */
const char *esp32c6_uart_rx_path = NULL;

/* ------------------------------------------------------------------ */
/* Region helpers                                                      */
/* ------------------------------------------------------------------ */

static esp32_region_t *esp32_find_region(esp32c6_t *soc, uint32_t addr)
{
    for (int i = 0; i < soc->nregions; i++) {
        esp32_region_t *r = &soc->regions[i];
        if (addr >= r->base && addr < r->base + r->size)
            return r;
    }
    return NULL;
}

static void esp32_add_region(esp32c6_t *soc,
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

esp32c6_t *esp32c6_new(void)
{
    esp32c6_t *soc = calloc(1, sizeof(esp32c6_t));
    assert(soc);
    soc->systimer_conf = 0x40000000u; /* TIMER_UNIT0_WORK_EN default 1 */
    soc->uart_rx_fd = -1;

    /* flash backing shared by the i/d-cache window */
    uint8_t *flash = calloc(1, C6_FLASH_SIZE);
    assert(flash);

    esp32_add_region(soc, C6_SRAM_BASE, C6_SRAM_SIZE, ESP32_REG_RAM);
    esp32_add_region(soc, C6_LP_SRAM_BASE, C6_LP_SRAM_SIZE, ESP32_REG_RAM);
    esp32_add_region(soc, C6_ROM_BASE, C6_ROM_SIZE, ESP32_REG_RAM);

    /* flash cache window (irom and drom share one window + backing) */
    esp32_region_t *fw = &soc->regions[soc->nregions++];
    fw->base = C6_FLASH_I_BASE;
    fw->size = C6_FLASH_WINDOW_SIZE;
    fw->type = ESP32_REG_RAM;
    fw->data = flash;

    esp32_add_region(soc, C6_PERIPH_BASE, C6_PERIPH_SIZE, ESP32_REG_MMIO);

    /* PCR SYSCLK_CONF reset: hs_div_num = 2 (SOC_ROOT_CLK/HP_ROOT_CLK div is
     * fixed at 3, never written by software; required for freq round-trip) */
    ((uint32_t *) soc->mmio)[(0x60096110u - C6_PERIPH_BASE) >> 2] = 0x200u;

    /* flash cache MMU defaults to identity mapping (page i -> flash page i) */
    for (int i = 0; i < 256; i++)
        soc->mmu[i] = i;

    /* load the real ROM image */
    esp32_region_t *rom = esp32_find_region(soc, C6_ROM_BASE);
    assert(esp32c6_rom_bin_len <= C6_ROM_SIZE);
    memcpy(rom->data, esp32c6_rom_bin, esp32c6_rom_bin_len);

    /* INTMTX default: source s maps to CPU line s */
    for (int i = 0; i < 64; i++)
        soc->intc_intmap[i] = i;

    return soc;
}

/* ------------------------------------------------------------------ */
/* UART0 (0x60000000)                                                  */
/* ------------------------------------------------------------------ */

#define UART_FIFO_REG 0x00u
#define UART_STATUS_REG 0x1Cu
#define UART_CLKDIV_CONF_REG 0x98u

static void esp32_uart_putc(esp32c6_t *soc, char c)
{
    if (esp32c6_uart_output)
        esp32c6_uart_output(c);
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
/* GPIO (0x60091000)                                                   */
/* ------------------------------------------------------------------ */

#define GPIO_OUT_REG 0x04u
#define GPIO_OUT_W1TS 0x08u
#define GPIO_OUT_W1TC 0x0Cu
#define GPIO_ENABLE_REG 0x20u
#define GPIO_ENABLE_W1TS 0x24u
#define GPIO_ENABLE_W1TC 0x28u
#define GPIO_STRAP_REG 0x38u
#define GPIO_IN_REG 0x3Cu

/* ------------------------------------------------------------------ */
/* SYSTIMER (0x6000A000; offsets identical to ESP32-C3)                */
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

/* ESP32-C6 interrupt sources (soc/interrupts.h): 57 = SYSTIMER_TARGET0
 * (FreeRTOS tick), 59 = SYSTIMER_TARGET2 (esp_timer). */
#define SYSTIMER_T0_SOURCE 57u
#define SYSTIMER_T2_SOURCE 59u

/* ------------------------------------------------------------------ */
/* SHA accelerator (0x60089000)                                        */
/* ------------------------------------------------------------------ */

#define SHA_MODE_REG 0x00u
#define SHA_START_REG 0x10u
#define SHA_CONTINUE_REG 0x14u
#define SHA_BUSY_REG 0x18u
#define SHA_H_MEM_BASE 0x40u
#define SHA_M_MEM_BASE 0x80u

/* ------------------------------------------------------------------ */
/* SPI0/SPI1 (flash; 0x60002000 / 0x60003000)                          */
/* ------------------------------------------------------------------ */

#define SPI_CMD_REG 0x00u
#define SPI_ADDR_REG 0x04u
#define SPI_MISO_DLEN 0x28u
#define SPI_DATA_BUF 0x58u /* spi_mem_w0..w15 */
#define SPI_CMD_USR_BIT 0x40000u /* SPI_MEM_CMD.usr = bit 18 */
#define SPI_AXI_STATUS_REG 0x170u /* SPI_MEM_AXI_ERR_ADDR */

/* MMU item registers (in SPI_MEM0 at 0x60002000) */
#define SPI_MMU_ITEM_CONTENT 0x37Cu
#define SPI_MMU_ITEM_INDEX 0x380u
#define SPI_MMU_PAGE_MODE 0x384u

/* ------------------------------------------------------------------ */
/* MMIO dispatch                                                       */
/* ------------------------------------------------------------------ */

/* page size = 2^(16-mode) with mode = (PAGE_MODE >> 3) & 3 */
static uint32_t esp32_mmu_page_shift(esp32c6_t *soc)
{
    uint32_t mode = (soc->mmu_page_mode >> 3) & 3u;
    return 16u - mode;
}

static uint32_t esp32_mmio_read(esp32c6_t *soc, uint32_t addr)
{
    /* PLIC (0x20001000) / PLIC-U (0x20001400) / CLINT-M (0x20001800) /
     * CLINT-U (0x20001C00) */
    if (addr >= C6_PLIC_BASE && addr < C6_PLIC_BASE + C6_PLIC_SIZE) {
        uint32_t off = addr - C6_PLIC_BASE;
        if (off >= 0x1000u && off < 0x1400u) { /* PLIC_MX */
            switch (off - 0x1000u) {
            case 0x00: return soc->plic_enable;
            case 0x04: return soc->plic_type;
            case 0x08: return 0; /* PLIC clear: write-only */
            case 0x0C: { /* EMIP_STATUS: lines with pending + enabled src */
                uint32_t lines = 0;
                for (int s = 0; s < 64; s++)
                    if (soc->intc_status & (1ULL << s))
                        lines |= 1u << (soc->intc_intmap[s] & 0x1Fu);
                return lines;
            }
            case 0x90: return soc->plic_threshold;
            default:
                if (off >= 0x1010u && off < 0x1010u + 28 * 4u)
                    return soc->plic_prio[(off - 0x1010u) >> 2];
                return 0;
            }
        }
        if (off >= 0x1400u && off < 0x1800u) { /* PLIC_UX: mirror storage */
            if ((off - 0x1400u) == 0x90u)
                return 0;
            if ((off - 0x1400u) >= 0x10u && (off - 0x1400u) < 0x10u + 28 * 4u)
                return 0;
            return 0;
        }
        if (off >= 0x1800u && off < 0x1C00u) { /* CLINT_M */
            switch (off - 0x1800u) {
            case 0x00: return soc->clint_msip;
            case 0x08: return (uint32_t) soc->clint_mtimcmp;
            case 0x0C: return (uint32_t) (soc->clint_mtimcmp >> 32);
            case 0x10: return (uint32_t) soc->clint_mtime;
            case 0x14: return (uint32_t) (soc->clint_mtime >> 32);
            default: return 0;
            }
        }
        return 0; /* CLINT_U: unmapped */
    }
    /* CPU-side PLIC alias (0x80000404 + 4*i): priority[i] */
    if (addr >= C6_PLIC_CPU_BASE && addr < C6_PLIC_CPU_BASE + C6_PLIC_CPU_SIZE) {
        uint32_t off = addr - C6_PLIC_CPU_BASE;
        if (off >= 0x404u && off < 0x404u + 28 * 4u)
            return soc->plic_prio[(off - 0x404u) >> 2];
        return 0;
    }
    if (addr < C6_PERIPH_BASE || addr >= C6_PERIPH_BASE + C6_PERIPH_SIZE)
        return 0; /* unmapped: bus returns zeros */
    uint32_t off = addr - C6_PERIPH_BASE;
    uint32_t *mmio32 = (uint32_t *) soc->mmio;

    /* SPI2 (GPSPI2, 0x60081000-0x60081100) */
    if (addr >= C6_PERIPH_BASE + 0x81000u &&
        addr < C6_PERIPH_BASE + 0x81100u) {
        return soc->spi2_reg[(addr - C6_PERIPH_BASE - 0x81000u) >> 2];
    }

    /* I2C_EXT (0x60004000-0x60004200) */
    if (addr >= C6_PERIPH_BASE + 0x4000u &&
        addr < C6_PERIPH_BASE + 0x4200u) {
        uint32_t *r = soc->i2c_reg + ((addr - C6_PERIPH_BASE - 0x4000u) >> 2);
        if (addr == C6_PERIPH_BASE + 0x4080u && soc->i2c_scl_rst_cnt > 0 &&
            --soc->i2c_scl_rst_cnt == 0)
            *r &= ~1u; /* SCL_RST_SLV_EN self-clears after the pulses */
        if (addr == C6_PERIPH_BASE + 0x402cu) {
            uint32_t v = soc->i2c_reg[0x20 >> 2] & soc->i2c_reg[0x28 >> 2];
            return v;
        }
        return *r;
    }

    /* UART0 */
    if (addr < C6_PERIPH_BASE + 0x1000u) {
        switch (off) {
        case UART_FIFO_REG:
            if (soc->uart_rx_head != soc->uart_rx_tail) {
                uint8_t b = soc->uart_rx[soc->uart_rx_tail];
                soc->uart_rx_tail = (soc->uart_rx_tail + 1) %
                                    sizeof(soc->uart_rx);
                return b;
            }
            return 0; /* empty FIFO reads as zero */
        case UART_STATUS_REG:
            /* RXFIFO_CNT [5:0]; TX side left at 0 (always room) */
            return (soc->uart_rx_head - soc->uart_rx_tail) &
                   (sizeof(soc->uart_rx) - 1u);
        case UART_CLKDIV_CONF_REG:
            /* the divider sync completes instantly in the model */
            return mmio32[off >> 2] & ~0x1u;
        default:
            return mmio32[off >> 2];
        }
    }
    /* SPI0/SPI1 (flash) */
    if (addr < C6_PERIPH_BASE + 0x4000u) {
        if (addr == C6_PERIPH_BASE + 0x2000u ||
            addr == C6_PERIPH_BASE + 0x3000u)
            return 0; /* SPI_CMD always reads done (self-clears) */
        if (addr == C6_PERIPH_BASE + 0x2000u + SPI_AXI_STATUS_REG)
            return mmio32[off >> 2] | 0x80000000u; /* MSPI idle */

        if (addr == C6_PERIPH_BASE + 0x202Cu)
            return 0x2u; /* SPI0 status: flash ready */
        if (addr >= C6_PERIPH_BASE + 0x2000u + SPI_MMU_ITEM_CONTENT &&
            addr < C6_PERIPH_BASE + 0x2000u + SPI_MMU_PAGE_MODE + 4u) {
            /* MMU item registers: read-back of the programmed table */
            switch (addr - C6_PERIPH_BASE - 0x2000u) {
            case SPI_MMU_ITEM_CONTENT:
                return soc->mmu[soc->mmu_index & 0xFFu];
            case SPI_MMU_ITEM_INDEX:
                return soc->mmu_index;
            case SPI_MMU_PAGE_MODE:
                return soc->mmu_page_mode;
            }
        }
        return mmio32[off >> 2];
    }
    /* GPIO */
    if (addr >= C6_PERIPH_BASE + 0x91000u && addr < C6_PERIPH_BASE + 0x92000u) {
        switch (off - 0x91000u) {
        case GPIO_OUT_REG:
            return soc->gpio_out;
        case GPIO_ENABLE_REG:
            return soc->gpio_enable;
        case GPIO_IN_REG:
            return 0; /* all inputs low */
        case GPIO_STRAP_REG:
            /* strapping: GPIO9 high -> SPI flash boot (boot mode 1xxx) */
            return 0x8u;
        default:
            return mmio32[off >> 2];
        }
    }
    /* LP_CLKRST (0x600B0400): reset reason */
    if (addr == C6_PERIPH_BASE + 0xB0410u)
        return 1; /* POWERON_RESET */
    /* RNG (0x600B2808): xorshift PRNG, seeded by the SYSTIMER counter */
    if (addr == C6_PERIPH_BASE + 0xB2808u) {
        uint32_t s = (uint32_t) soc->systimer_counter | 1u;
        s ^= s << 13;
        s ^= s >> 17;
        s ^= s << 5;
        return s;
    }
    /* LP_TIMER (0x600B0C00): RTC main timer, counting slow-clock ticks.
     * The hal reads MAIN_TIMER_LO/HI (0x14/0x18) after setting the
     * MAIN_TIMER_UPDATE bit (0x10). */
    if (addr == C6_PERIPH_BASE + 0xB0C14u)
        return (uint32_t) soc->lp_timer;
    if (addr == C6_PERIPH_BASE + 0xB0C18u)
        return (uint32_t) (soc->lp_timer >> 32);
    /* I2C analog master (0x600AF000): BB-PLL calibration done instantly */
    if (addr == C6_PERIPH_BASE + 0xAF818u)
        return mmio32[off >> 2] | 0x1000000u;
    /* ICache (0x600C8000): operations complete instantly */
    if (addr == C6_PERIPH_BASE + 0xC8134u || addr == C6_PERIPH_BASE + 0xC80D8u)
        return mmio32[off >> 2] | 0x2u;
    if (addr == C6_PERIPH_BASE + 0xC802Cu)
        return mmio32[off >> 2]; /* freeze busy bit stored by write */
    if (addr == C6_PERIPH_BASE + 0xC8088u)
        return mmio32[off >> 2] | 0x4u; /* unlock complete */
    if (addr == C6_PERIPH_BASE + 0xC8098u)
        return mmio32[off >> 2] | 0x10u; /* invalidate complete */
    /* eFuse (0x600B0800): chip ID 6 in the standard fields */
    if (addr == C6_PERIPH_BASE + 0xB0850u)
        return (0x6u << 24) | (0x6u << 18);
    /* SHA accelerator */
    if (addr >= C6_PERIPH_BASE + 0x89000u && addr < C6_PERIPH_BASE + 0x8A000u) {
        if (addr == C6_PERIPH_BASE + 0x89018u)
            return 0; /* SHA_BUSY: instant completion (poll spins while 1) */
        if (addr >= C6_PERIPH_BASE + 0x89040u &&
            addr < C6_PERIPH_BASE + 0x89080u) {
            uint32_t w = esp32_sha_digest_word((addr - C6_PERIPH_BASE -
                                                0x89040u) >>
                                               2);
            sha_reset_pending = 1;
            return w;
        }
        return mmio32[off >> 2];
    }
    /* SYSTIMER (0x6000A000) */
    if (addr >= C6_PERIPH_BASE + 0xA000u &&
        addr < C6_PERIPH_BASE + 0xB000u) {
        switch (off - 0xA000u) {
        case SYSTIMER_CONF:
            return soc->systimer_conf;
        case SYSTIMER_VALUE_LO:
            return (uint32_t) soc->systimer_unit0_val;
        case SYSTIMER_VALUE_HI:
            return (uint32_t) (soc->systimer_unit0_val >> 32);
        case SYSTIMER_UNIT1_VALUE_LO:
            return (uint32_t) soc->systimer_unit1_val;
        case SYSTIMER_UNIT1_VALUE_HI:
            return (uint32_t) (soc->systimer_unit1_val >> 32);
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

static void esp32_mmio_write(riscv_t *rv, uint32_t addr, uint32_t val)
{
    esp32c6_t *soc = PRIV(rv)->esp32c6;
    /* PLIC / CLINT */
    if (addr >= C6_PLIC_BASE && addr < C6_PLIC_BASE + C6_PLIC_SIZE) {
        uint32_t off = addr - C6_PLIC_BASE;
        if (off >= 0x1000u && off < 0x1400u) { /* PLIC_MX */
            switch (off - 0x1000u) {
            case 0x00: soc->plic_enable = val; return;
            case 0x04: soc->plic_type = val; return;
            case 0x08: return; /* clear: the device clears its own status */
            default:
                if (off >= 0x1010u && off < 0x1010u + 28 * 4u) {
                    soc->plic_prio[(off - 0x1010u) >> 2] = val;
                    return;
                }
                if (off == 0x90u) {
                    soc->plic_threshold = val;
                    return;
                }
                return;
            }
        }
        if (off >= 0x1800u && off < 0x1C00u) { /* CLINT_M */
            switch (off - 0x1800u) {
            case 0x00: soc->clint_msip = val & 1u; return;
            case 0x08: soc->clint_mtimcmp =
                (soc->clint_mtimcmp & ~0xFFFFFFFFull) | val; return;
            case 0x0C: soc->clint_mtimcmp =
                (soc->clint_mtimcmp & 0xFFFFFFFFull) |
                ((uint64_t) val << 32); return;
            default: return;
            }
        }
        return;
    }
    /* CPU-side PLIC alias (0x80000404 + 4*i): priority[i] */
    if (addr >= C6_PLIC_CPU_BASE && addr < C6_PLIC_CPU_BASE + C6_PLIC_CPU_SIZE) {
        uint32_t off = addr - C6_PLIC_CPU_BASE;
        if (off >= 0x404u && off < 0x404u + 28 * 4u)
            soc->plic_prio[(off - 0x404u) >> 2] = val;
        return;
    }
    if (addr < C6_PERIPH_BASE || addr >= C6_PERIPH_BASE + C6_PERIPH_SIZE)
        return; /* unmapped: writes are discarded */
    uint32_t off = addr - C6_PERIPH_BASE;
    uint32_t *mmio32 = (uint32_t *) soc->mmio;

    /* I2C_EXT (0x60004000-0x60004200) */
    if (addr >= C6_PERIPH_BASE + 0x4000u &&
        addr < C6_PERIPH_BASE + 0x4200u) {
        uint32_t *r = soc->i2c_reg + ((addr - C6_PERIPH_BASE - 0x4000u) >> 2);
        if (addr == C6_PERIPH_BASE + 0x4024u) { /* int_clr */
            soc->i2c_reg[0x20 >> 2] &= ~val; /* clear raw status bits */
            soc->intc_status &= ~(1ull << 50); /* drop the pending IRQ */
        } else if (addr == C6_PERIPH_BASE + 0x4004u) { /* ctr */
            *r = val;
            if (val & (1u << 5)) /* trans_start (WT): transfer begins */
                soc->i2c_transfer_pending = 1;
        } else {
            *r = val;
        }
        if (addr == C6_PERIPH_BASE + 0x4080u) {
            if (val & 1u) /* SCL_RST_SLV_EN: start the reset pulses */
                soc->i2c_scl_rst_cnt = 64; /* held high ~64 reads */
            else
                soc->i2c_scl_rst_cnt = 0;
        }
        return;
    }

    /* SPI2 (GPSPI2, 0x60081000-0x60081100) */
    if (addr >= C6_PERIPH_BASE + 0x81000u &&
        addr < C6_PERIPH_BASE + 0x81100u) {
        uint32_t *r = soc->spi2_reg + ((addr - C6_PERIPH_BASE - 0x81000u) >> 2);
        if (addr == C6_PERIPH_BASE + 0x81000u) { /* cmd */
            *r = val & ~(1u << 23); /* update self-clears: config applied */
            if (val & (1u << 24))   /* usr: transfer begins */
                soc->spi2_transfer_pending = 1;
        } else if (addr == C6_PERIPH_BASE + 0x81038u) { /* dma_int_clr */
            soc->spi2_reg[0x3c >> 2] &= ~val; /* clear raw interrupt bits */
        } else {
            *r = val;
        }
        return;
    }

    /* UART0 */
    if (addr < C6_PERIPH_BASE + 0x1000u) {
        if (off == UART_FIFO_REG) {
            esp32_uart_putc(soc, (char) (val & 0xFFu));
        } else
            mmio32[off >> 2] = val;
        return;
    }
    /* SPI0/SPI1 (flash) */
    if (addr < C6_PERIPH_BASE + 0x4000u) {
        /* MMU item registers live in SPI_MEM0 */
        if (addr >= C6_PERIPH_BASE + 0x2000u + SPI_MMU_ITEM_CONTENT &&
            addr < C6_PERIPH_BASE + 0x2000u + SPI_MMU_PAGE_MODE + 4u) {
            switch (addr - C6_PERIPH_BASE - 0x2000u) {
            case SPI_MMU_ITEM_CONTENT:
                if (soc->mmu_index < 256)
                    soc->mmu[soc->mmu_index] = val;
                return;
            case SPI_MMU_ITEM_INDEX:
                soc->mmu_index = val & 0xFFu;
                return;
            case SPI_MMU_PAGE_MODE:
                soc->mmu_page_mode = val;
                return;
            }
        }
        mmio32[off >> 2] = val;
        if ((addr == C6_PERIPH_BASE + 0x2000u ||
             addr == C6_PERIPH_BASE + 0x3000u) && (val & SPI_CMD_USR_BIT)) {
            /* SPI_USR command trigger: service the command into W0.. */
            uint32_t base = addr - C6_PERIPH_BASE;
            uint32_t *w = mmio32 + ((base + SPI_DATA_BUF) >> 2);
            uint32_t cmd = mmio32[(base + 0x20u) >> 2] & 0xFFu; /* USER2 */
            uint32_t user = mmio32[(base + 0x18u) >> 2];        /* USER */
            uint32_t miso =
                (mmio32[(base + SPI_MISO_DLEN) >> 2] & 0x3FFu) + 1u;
            uint32_t nbytes = (miso + 7u) / 8u;
            if (nbytes > 64u)
                nbytes = 64u;
            esp32_region_t *fi = esp32_find_region(soc, C6_FLASH_I_BASE);
            memset(w, 0, nbytes);
            uint32_t faddr = mmio32[(base + SPI_ADDR_REG) >> 2];
            if (cmd == 0x9Fu) {
                /* RDID: JEDEC ID (Winbond W25Q32: 0xEF 0x40 0x16) */
                w[0] = 0x1640EFu;
            } else if (cmd == 0x5Au) {
                /* SFDP: 1st 16 bytes = "SFDP" + version + table ptr */
                static const uint8_t sfdp[16] = {
                    'S', 'F', 'D', 'P', 0x00, 0x01, 0xFF, 0x00,
                    0x00, 0x20, 0x00, 0xFF, 0xFF, 0xFF, 0x00, 0xFF
                };
                uint32_t base_addr = mmio32[(base + SPI_ADDR_REG) >> 2];
                for (uint32_t i = 0; i < nbytes && (base_addr + i) < 16u; i++)
                    ((uint8_t *) w)[i] = sfdp[base_addr + i];
            } else if (cmd == 0x7Au) {
                w[0] = 0x00u; /* QPI enable: no-op */
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
            } else if (user & 0x10000000u) {
                /* USR_MISO: read data into W0 (flash bytes in order) */
                if (faddr < C6_FLASH_SIZE)
                    memcpy(w, fi->data + faddr, nbytes);
            } else if (user & 0x08000000u) {
                /* USR_MOSI: write data from W0 */
                if (faddr < C6_FLASH_SIZE)
                    memcpy(fi->data + faddr, w, nbytes);
            } else if (cmd == 0x9Fu) {
                /* RDID: JEDEC ID (Winbond W25Q32: 0xEF 0x40 0x16) */
                w[0] = 0x1640EFu;
            } else if (cmd == 0x03u || cmd == 0x0Bu || cmd == 0x3Bu ||
                       cmd == 0x6Bu || cmd == 0xEBu) {
                /* flash read commands: copy from flash image */
                if (faddr < C6_FLASH_SIZE)
                    memcpy(w, fi->data + faddr, nbytes);
            }
            mmio32[off >> 2] = 0; /* CMD self-clears when done */
        }
        return;
    }
    /* GPIO */
    if (addr >= C6_PERIPH_BASE + 0x91000u && addr < C6_PERIPH_BASE + 0x92000u) {
        switch (off - 0x91000u) {
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
        if (esp32c6_gpio_output) {
            for (int pin = 0; pin < 30; pin++) {
                if (soc->gpio_enable & (1u << pin))
                    esp32c6_gpio_output(pin, !!(soc->gpio_out & (1u << pin)));
            }
        }
        return;
    }
    /* interrupt matrix (0x60010000 + 4*source) */
    if (addr >= C6_PERIPH_BASE + 0x10000u &&
        addr < C6_PERIPH_BASE + 0x10000u + 64 * 4u) {
        uint32_t s = (addr - C6_PERIPH_BASE - 0x10000u) >> 2;
        soc->intc_intmap[s] = val & 0x1Fu;
        return;
    }
    /* SHA accelerator (0x60089000) */
    if (addr >= C6_PERIPH_BASE + 0x89000u && addr < C6_PERIPH_BASE + 0x8A000u) {
        if (addr == C6_PERIPH_BASE + 0x89000u) { /* SHA_MODE: new session */
            if (sha_reset_pending) {
                esp32_sha_reset();
                sha_reset_pending = 0;
            }
            mmio32[off >> 2] = val;
            return;
        }
        if (addr == C6_PERIPH_BASE + 0x89010u) { /* SHA_START */
            mmio32[off >> 2] = val;
            return;
        }
        if (addr == C6_PERIPH_BASE + 0x89014u) { /* SHA_CONTINUE */
            mmio32[off >> 2] = val;
            return;
        }
        if (addr >= C6_PERIPH_BASE + 0x89080u &&
            addr < C6_PERIPH_BASE + 0x890C0u) { /* SHA M_MEM words */
            esp32_sha_feed_word(val);
            mmio32[off >> 2] = val;
            return;
        }
        mmio32[off >> 2] = val;
        return;
    }
    /* SYSTIMER (0x6000A000) */
    if (addr >= C6_PERIPH_BASE + 0xA000u &&
        addr < C6_PERIPH_BASE + 0xB000u) {
        switch (off - 0xA000u) {
        case SYSTIMER_CONF:
            soc->systimer_conf = val;
            return;
        case SYSTIMER_UNIT0_OP:
            mmio32[off >> 2] = val;
            if (val & 0x40000000u) { /* UPDATE: latch counter, set VALID */
                soc->systimer_unit0_val = soc->systimer_counter;
                mmio32[off >> 2] |= 0x20000000u; /* bit29 VALUE_VALID */
            }
            return;
        case SYSTIMER_UNIT1_OP:
            mmio32[off >> 2] = val;
            if (val & 0x40000000u) { /* UPDATE: latch counter, set VALID */
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
    /* ICache freeze (0x600C8000): latch the busy bit18 on freeze request */
    if (addr == C6_PERIPH_BASE + 0xC802Cu) {
        if (val & 0x10000u)
            val |= 0x40000u;
        else
            val &= ~0x40000u;
        mmio32[off >> 2] = val;
        return;
    }
    /* TIMG0 RTCCALICFG (0x60008068): one-off slow-clock calibration.
     * On START the hardware counts XTAL (40 MHz) cycles over RTC_CALI_MAX
     * cycles of the selected calibration clock, then sets RTC_CALI_RDY and
     * latches the count into RTCCALICFG1 (0x6000806C). */
    if (addr == C6_PERIPH_BASE + 0x8068u) {
        mmio32[off >> 2] = val;
        if (val & 0x80000000u) { /* TIMG_RTC_CALI_START */
            uint32_t clk_hz, max = (val >> 16) & 0x7FFFu;
            switch ((val >> 13) & 3u) { /* TIMG_RTC_CALI_CLK_SEL */
            case 0: clk_hz = 150000u; break;    /* RC_SLOW */
            case 1: clk_hz = 20000000u; break;  /* RC_FAST */
            default: clk_hz = 32768u; break;    /* XTAL32K / RC32K / OSC_SLOW */
            }
            mmio32[(0x806Cu) >> 2] =
                (uint32_t) ((uint64_t) max * 40000000u / clk_hz);
            mmio32[off >> 2] |= 0x8000u; /* TIMG_RTC_CALI_RDY */
        }
        return;
    }
    /* Crosscore interrupt flag (0x600C5090): writing 1 raises INTC source 22
     * (ESP_CROSSCPU_INT_SOURCE), writing 0 clears it. The FreeRTOS port's
     * yield (esp_crosscore_int_send / vPortYield / esp_crosscore_isr)
     * depends on this. */
    if (addr == C6_PERIPH_BASE + 0xC5090u) {
        mmio32[off >> 2] = val & 1u;
        if (val & 1u)
            soc->intc_status |= 1ull << 22u;
        else
            soc->intc_status &= ~(1ull << 22u);
        return;
    }
    mmio32[off >> 2] = val;
}

/* ------------------------------------------------------------------ */
/* Memory accessors (io callbacks)                                     */
/* ------------------------------------------------------------------ */

static inline esp32_region_t *esp32_lookup(riscv_t *rv, uint32_t addr)
{
    return esp32_find_region(PRIV(rv)->esp32c6, addr);
}

/* Flash cache window translation: the 0x42000000 window (16 MB) maps
 * through the MMU with 2^(16-mode) byte pages, programmed via
 * SPI_MEM_MMU_ITEM_INDEX/CONTENT. Returns the flash buffer offset, or
 * ~0u for non-window addresses. */
static inline uint32_t esp32_flash_window_off(esp32c6_t *soc, uint32_t addr)
{
    if (addr >= C6_FLASH_I_BASE && addr < C6_FLASH_I_BASE + C6_FLASH_WINDOW_SIZE) {
        uint32_t shift = esp32_mmu_page_shift(soc);
        uint32_t mask = (1u << shift) - 1u;
        uint32_t page = (addr - C6_FLASH_I_BASE) >> shift;
        uint32_t off = ((soc->mmu[page & 0xFFu] & 0x1FFu) << shift) |
                       (addr & mask);
        return (off < C6_FLASH_SIZE) ? off : (addr & mask);
    }
    return ~0u;
}

uint32_t esp32c6_read_w(riscv_t *rv, uint32_t addr)
{
    esp32_region_t *r = esp32_lookup(rv, addr);
    if (!r || r->type != ESP32_REG_RAM)
        return esp32_mmio_read(PRIV(rv)->esp32c6, addr);
    uint32_t val;
    uint32_t off = esp32_flash_window_off(PRIV(rv)->esp32c6, addr);
    if (off == ~0u)
        off = addr - r->base;
    memcpy(&val, r->data + off, 4);
    return val;
}

uint16_t esp32c6_read_s(riscv_t *rv, uint32_t addr)
{
    esp32_region_t *r = esp32_lookup(rv, addr);
    if (!r || r->type != ESP32_REG_RAM)
        return (uint16_t) esp32_mmio_read(PRIV(rv)->esp32c6, addr);
    uint16_t val;
    uint32_t off = esp32_flash_window_off(PRIV(rv)->esp32c6, addr);
    if (off == ~0u)
        off = addr - r->base;
    memcpy(&val, r->data + off, 2);
    return val;
}

uint8_t esp32c6_read_b(riscv_t *rv, uint32_t addr)
{
    esp32_region_t *r = esp32_lookup(rv, addr);
    if (!r || r->type != ESP32_REG_RAM)
        return (uint8_t) esp32_mmio_read(PRIV(rv)->esp32c6, addr);
    uint32_t off = esp32_flash_window_off(PRIV(rv)->esp32c6, addr);
    if (off == ~0u)
        off = addr - r->base;
    return r->data[off];
}

void esp32c6_write_w(riscv_t *rv, uint32_t addr, uint32_t val)
{
    esp32_region_t *r = esp32_lookup(rv, addr);
    if (!r || r->type != ESP32_REG_RAM) {
        esp32_mmio_write(rv, addr, val);
        return;
    }
    memcpy(r->data + (addr - r->base), &val, 4);
}

void esp32c6_write_s(riscv_t *rv, uint32_t addr, uint16_t val)
{
    esp32_region_t *r = esp32_lookup(rv, addr);
    if (!r || r->type != ESP32_REG_RAM) {
        esp32_mmio_write(rv, addr, val);
        return;
    }
    memcpy(r->data + (addr - r->base), &val, 2);
}

void esp32c6_write_b(riscv_t *rv, uint32_t addr, uint8_t val)
{
    esp32_region_t *r = esp32_lookup(rv, addr);
    if (!r || r->type != ESP32_REG_RAM) {
        esp32_mmio_write(rv, addr, val);
        return;
    }
    r->data[addr - r->base] = val;
}

uint32_t esp32c6_ifetch(riscv_t *rv, uint32_t addr)
{
    esp32_region_t *r = esp32_lookup(rv, addr);
    if (!r || r->type != ESP32_REG_RAM) {
        /* code fetch outside RAM: decode as 0 (illegal) and log once */
        fprintf(stderr,
                "esp32c6: ifetch at non-RAM 0x%08x (guest pc=0x%08x, r=%p)\n",
                addr, rv->PC, (void *) r);
        return 0;
    }
    uint32_t val;
    uint32_t off = esp32_flash_window_off(PRIV(rv)->esp32c6, addr);
    if (off == ~0u)
        off = addr - r->base;
    memcpy(&val, r->data + off, 4);
    return val;
}

static uint32_t esp32c6_translate(riscv_t *rv, uint32_t vaddr, bool rw)
{
    (void) rv;
    (void) rw;
    return vaddr; /* bare metal: identity */
}

void esp32c6_install_io(riscv_t *rv)
{
    riscv_io_t io = {
        .mem_ifetch = esp32c6_ifetch,
        .mem_read_w = esp32c6_read_w,
        .mem_read_s = esp32c6_read_s,
        .mem_read_b = esp32c6_read_b,
        .mem_write_w = esp32c6_write_w,
        .mem_write_s = esp32c6_write_s,
        .mem_write_b = esp32c6_write_b,
        .mem_translate = esp32c6_translate,
        .mmu_read_w = esp32c6_read_w,
        .mmu_read_s = esp32c6_read_s,
        .mmu_read_b = esp32c6_read_b,
        .mmu_write_w = esp32c6_write_w,
        .mmu_write_s = esp32c6_write_s,
        .mmu_write_b = esp32c6_write_b,
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

uint32_t esp32c6_boot(esp32c6_t *soc, const char *elf_path)
{
    /* Full flash-image boot (ROM reset vector -> bootloader -> app) */
    if (esp32c6_flash_image_path) {
        FILE *f = fopen(esp32c6_flash_image_path, "rb");
        if (!f) {
            fprintf(stderr, "esp32c6: cannot open flash image %s\n",
                    esp32c6_flash_image_path);
            exit(EXIT_FAILURE);
        }
        esp32_region_t *fd = esp32_find_region(soc, C6_FLASH_I_BASE);
        size_t got = fread(fd->data, 1, C6_FLASH_SIZE, f);
        fclose(f);
        fprintf(stderr, "esp32c6: loaded %zu bytes of flash image\n", got);
        /* boot from the ROM reset vector: ROM code initializes the system
         * (timer structs, SYSTIMER, UART, clocks) then loads the 2nd-stage
         * bootloader from flash offset 0 and jumps to the app. */
        return C6_ROM_BASE;
    }

    FILE *f = fopen(elf_path, "rb");
    if (!f) {
        fprintf(stderr, "esp32c6: cannot open %s\n", elf_path);
        exit(EXIT_FAILURE);
    }
    esp32_elf32_hdr_t hdr;
    if (fread(&hdr, 1, sizeof(hdr), f) != sizeof(hdr) ||
        memcmp(hdr.e_ident, "\x7f" "ELF", 4) != 0) {
        fprintf(stderr, "esp32c6: %s is not an ELF32 file\n", elf_path);
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
                        "esp32c6: ELF segment at 0x%08x outside RAM\n",
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
                    fprintf(stderr, "esp32c6: ELF segment read failed\n");
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

/* Route enabled pending peripheral sources to CPU interrupt lines (mip)
 * through the PLIC gate: line must be PLIC-enabled and have a priority
 * above the threshold. */
static uint32_t esp32_intc_raise(esp32c6_t *soc)
{
    uint32_t lines = 0;
    for (int s = 0; s < 64; s++) {
        if (!(soc->intc_status & (1ULL << s)))
            continue;
        int line = soc->intc_intmap[s] & 0x1Fu;
        if (line >= 1 && line < 28 &&
            (soc->plic_enable & (1u << line)) &&
            soc->plic_prio[line] > soc->plic_threshold)
            lines |= 1u << line;
    }
    /* CLINT: MSIP (line 3) and MTIMECMP (line 7) */
    if (soc->clint_msip && (soc->plic_enable & (1u << 3)))
        lines |= 1u << 3;
    if (soc->clint_mtimcmp && soc->clint_mtime >= soc->clint_mtimcmp &&
        (soc->plic_enable & (1u << 7)))
        lines |= 1u << 7;
    return lines;
}

void esp32c6_check_interrupt(riscv_t *rv)
{
    esp32c6_t *soc = PRIV(rv)->esp32c6;
    if (!soc)
        return;
    if (!(rv->csr_mstatus & MSTATUS_MIE))
        return;
    uint32_t lines = esp32_intc_raise(soc);
    rv->csr_mip = (rv->csr_mip & ~0x0FFFFFFEu) | lines;
    /* the C6 app enables per-line mie bits via esprv_intc_int_enable */
    uint32_t pending = lines & rv->csr_mie;
    if (!pending)
        return;
    /* lowest set bit = CPU interrupt number */
    int idx = __builtin_ctz(pending);
    SET_CAUSE_AND_TVAL_THEN_TRAP(rv, ((1u << 31) | idx), 0);
}

/* Drain host-injected UART RX bytes (FIFO file) into the guest RX FIFO. */
static void esp32c6_uart_rx_poll(esp32c6_t *soc)
{
    if (!esp32c6_uart_rx_path)
        return;
    if (soc->uart_rx_fd < 0) {
        soc->uart_rx_fd =
            open(esp32c6_uart_rx_path, O_RDONLY | O_NONBLOCK);
        if (soc->uart_rx_fd < 0) {
            if (errno != ENOENT && errno != EACCES)
                fprintf(stderr, "esp32c6: uart rx open %s: %s\n",
                        esp32c6_uart_rx_path, strerror(errno));
            return;
        }
    }
    for (;;) {
        unsigned int count = (soc->uart_rx_head - soc->uart_rx_tail) &
                             (sizeof(soc->uart_rx) - 1u);
        unsigned int free_slots = sizeof(soc->uart_rx) - 1u - count;
        unsigned int head = soc->uart_rx_head % sizeof(soc->uart_rx);
        unsigned int chunk = sizeof(soc->uart_rx) - head;
        if (chunk > free_slots)
            chunk = free_slots;
        ssize_t n = read(soc->uart_rx_fd, soc->uart_rx + head, chunk);
        if (n <= 0)
            break; /* EAGAIN/EOF: nothing more right now */
        soc->uart_rx_head =
            (soc->uart_rx_head + n) % sizeof(soc->uart_rx);
    }
}

void esp32c6_periodic(riscv_t *rv)
{
    esp32c6_t *soc = PRIV(rv)->esp32c6;
    if (!soc)
        return;

    /* I2C transfer completion: a trans_start was issued on an empty bus.
     * The address byte is never ACKed -> NACK + trans-complete, which the
     * ISR maps to I2C_INTR_EVENT_NACK (I2C_EXT0 = INTMTX source 50). */
    if (soc->i2c_transfer_pending) {
        soc->i2c_transfer_pending = 0;
        soc->i2c_reg[0x20 >> 2] |= (1u << 10) | (1u << 7); /* nack + complete */
        soc->intc_status |= 1ull << 50;
    }

    /* SPI2 transfer completion: cmd.usr was set on an empty bus. MISO
     * floats high (no slave) so all received words come back 0xFF, and
     * cmd.usr self-clears for the firmware's poll. */
    if (soc->spi2_transfer_pending) {
        soc->spi2_transfer_pending = 0;
        for (int i = 0; i < 16; i++)
            soc->spi2_reg[(0x98u + 4u * i) >> 2] = 0xFFFFFFFFu;
        soc->spi2_reg[0x00 >> 2] &= ~(1u << 24); /* usr cleared */
        soc->spi2_reg[0x3c >> 2] |= 1u << 12;    /* trans_done raw */
    }

    /* feed host-injected bytes into the UART RX FIFO (throttled) */
    if ((rv->csr_cycle & 0x1FFu) == 0)
        esp32c6_uart_rx_poll(soc);

    /* advance SYSTIMER counters (both units free-run on the C6) */
    uint64_t elapsed = rv->csr_cycle - soc->last_cycle;
    soc->last_cycle = rv->csr_cycle;
    soc->systimer_counter += elapsed;
    soc->systimer_unit1_counter += elapsed;
    soc->clint_mtime += elapsed;
    soc->lp_timer = rv->csr_cycle / 1067u; /* RC_SLOW ~150 kHz vs ~160 MHz */

/* SYSTIMER alarms. The C6: alarm enables are SYSTIMER_CONF bits
 * (TARGET0_WORK_EN=24, TARGET2_WORK_EN=22); TIMER_UNIT_SEL (bit31 of the
 * per-target CONF) picks the counter unit; bit30 selects period mode
 * (fires every PERIOD ticks, period = CONF bits 25:0). The app's esp_timer
 * uses TARGET2 (INTC source 59); the FreeRTOS tick uses TARGET0 (57). */
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