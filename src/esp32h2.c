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

#include "esp32h2.h"
#include "esp32h2_rom.h"
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
static unsigned dbg_69_at_check;  /* times bit 69 seen pending at check */
static unsigned dbg_trap_deliv;   /* times a trap was actually delivered */
static unsigned dbg_gdma_intrwr;  /* guest writes to GDMA intr regs */
static unsigned dbg_gdma_intrwr_clear; /* ...that cleared bit 69 */

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

struct esp32h2_soc {
    esp32_region_t regions[12];
    int nregions;

    /* peripheral register backing (MMIO) */
    uint8_t mmio[C6_PERIPH_SIZE];

    /* SYSTIMER */
    uint64_t systimer_counter;
    uint32_t strap_b0410; /* 0x600b0410: strapping (low5=5) + reset reason */
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

    /* LP_TIMER sleep-wait counter: advanced on each MAIN_TIMER_UPDATE pulse
     * so the firmware's timer-wakeup busy-wait (counter >= target) exits. */
    uint64_t lp_counter;
    uint64_t lp_target;   /* armed sleep-timer target (LP_TIMER target[0]) */
    uint8_t  lp_armed;    /* sleep timer enable latched */

    /* PMU_INT_RAW (0x600B015C): SOC_WAKEUP_INT_RAW (bit 31) is set when the
     * sleep timer fires so pmu_sleep_start's wakeup-wait loop exits. */
    uint32_t pmu_int_raw;

    /* CLINT (0x20001800): free-running MTIME + MSIP/MTIMECMP */
    uint64_t clint_mtime;
    uint64_t clint_mtimcmp;
    uint32_t clint_msip;

    /* SPI flash status registers (SR/SR2 incl. WEL and QE bits) */
    uint32_t flash_sr;
    uint32_t flash_sr2;

    /* interrupt matrix (INTMTX): peripheral source -> CPU line */
    uint32_t intc_intmap[96];
    __uint128_t intc_status; /* pending peripheral sources (128-bit: sources 0..127) */

    /* PLIC (0x20001000) */
    uint32_t plic_enable;
    uint32_t plic_type;
    uint32_t plic_prio[32];
    uint32_t plic_threshold;

    /* GPIO */
    uint32_t gpio_out;
    uint32_t gpio_enable;
    uint32_t gpio_in;    /* input pad levels (host-injected) */
    uint32_t gpio_in_prev; /* last live input seen (edge detection) */
    uint32_t gpio_status; /* pending interrupt bits (W1TC) */
    uint32_t gpio_vbtn;  /* virtual button phase (toggles input pin 7) */

    /* UART output buffering */
    char uart_line[256];
    int uart_line_len;

    /* I2C_EXT (0x60004000): register bank + SCL_RST_SLV_EN auto-clear */
    uint32_t i2c_reg[128]; /* 0x200 bytes, mirrors i2c_dev_t */
    int i2c_scl_rst_cnt;   /* reads left with SCL_RST_SLV_EN asserted */
    int i2c_transfer_pending; /* a trans_start was written */
    uint8_t i2c_tx_fifo[32];  /* bytes pushed to I2C_DATA before trans_start */
    int i2c_tx_len;
    uint8_t i2c_rx_fifo[32];  /* bytes the virtual device sent on a read */
    int i2c_rx_len;
    int i2c_rx_pos;
    int i2c_slave_active;     /* transfer targets the virtual device */
    int i2c_slave_rw;         /* 1 = read from the device, 0 = write */
    uint8_t i2c_dev_mem[16];  /* virtual EEPROM contents (address 0x50) */
    int i2c_dev_ptr;          /* current register/memory address pointer */

    /* SPI2 (GPSPI2, 0x60081000): register bank + transfer completion */
    uint32_t spi2_reg[64]; /* 0x100 bytes, mirrors spi_dev_t */
    int spi2_transfer_pending; /* a cmd.usr was written; bus has no slave */
    uint8_t spi2_dev_mem[16];  /* virtual SRAM contents */
    int spi2_jedec;            /* next JEDEC ID byte index (4 == idle) */

    /* TWAI0 (CAN, 0x6000C000): register bank + TX completion */
    uint32_t twai_reg[64]; /* 0x100 bytes, mirrors twai_dev_t */
    uint32_t adc_reg[257]; /* SARADC 0x400 bytes + version reg */
    int twai_tx_pending; /* a cmd.tx_request was written */
    uint64_t twai_tx_done_cycle; /* cycle at which the TX completes */
    uint64_t twai_rx_deliver_cycle; /* cycle at which the virtual node's frame arrives */
    int twai_rx_delivered;          /* RX delivery is one-shot */

    /* AES (0x60088000): register bank; transform done synchronously on
     * trigger so the esp-idf driver (which busy-waits on state) sees the
     * result immediately. */
    uint32_t aes_reg[64]; /* 0x100 bytes, mirrors aes_dev_t */

    /* RMT (0x60007000): TX completion model */
    uint64_t rmt_tx_done_cycle; /* cycle at which the TX completes */
    /* RMT RX (HW channels 2/3, input signals 71/72): pulse-width capture.
     * The channel memory holds symbols {level, duration}; the driver's ISR
     * copies them straight out of the channel memory after RX_END. */
    uint64_t rmt_rx_last_cycle[2]; /* cycle of the last periodic pass */
    uint64_t rmt_rx_trans_cycle[2]; /* cycle of the last input transition */
    uint32_t rmt_rx_wptr[2];     /* symbols written into the channel memory */
    uint32_t rmt_rx_last_level[2]; /* last input level seen */
    int rmt_rx_en[2];            /* rx_en armed by the driver */

    /* LEDC (0x60008000): register bank + running duty + timer anchors */
    uint32_t ledc_reg[128];  /* 0x200 bytes, mirrors ledc_dev_t */
    uint32_t ledc_duty_r[6]; /* running duty per channel (latched on start) */
    uint64_t ledc_timer_anchor[4]; /* cycle anchor per timer (phase origin) */
    uint64_t ledc_timer_frac[4];   /* fractional cycle remainder per timer */

    /* TIMG0/1 (0x60009000/0x6000A000): one timer per group */
    uint32_t timg_reg[2][64]; /* 0x100 bytes, mirrors timer_group_dev_t */
    /* MWDT (Timer Group Watchdog): armed flag, expiry cycle, write-protect
     * unlock. The WDT raises the group's WDT interrupt source on timeout. */
    int wdt_en[2];
    uint64_t wdt_expire[2];
    int wdt_unlock[2];
    uint64_t timg_counter[2]; /* live counter value */
    uint64_t timg_anchor[2];  /* cycle at which the counter base applies */
    uint64_t timg_frac[2];    /* fractional cycle remainder per group */
    uint64_t systimer_frac;   /* fractional cycle remainder (16 MHz sysclk) */

    /* PCNT (0x60012000): 0x100 bytes, mirrors pcnt_dev_t. The virtual
     * button (pin 7) is the pulse source: edges count whenever a channel's
     * input signal is routed to pin 7 via the GPIO matrix. */
    uint32_t pcnt_reg[64];

    /* MCPWM (0x60014000): 0x130 bytes, mirrors mcpwm_dev_t. Timers count
     * 0..period at (timer_prescale+1)*(clk_prescale+1) 40 MHz source
     * cycles; generator events (zero/period/compare A/B) update the
     * levels that drive pads routed to signals 87..92
     * (PWM0_OUT{0,1,2}{A,B}). */
    uint32_t mcpwm_reg[128]; /* 0x200 bytes; covers int_st/ena at 0x194/0x198 */
    uint64_t mcpwm_anchor[3];   /* cycle anchor per timer */
    uint64_t mcpwm_frac[3];     /* fractional cycle remainder per timer */
    uint32_t mcpwm_phase[3];    /* live timer value */
    int mcpwm_dir[3];           /* 0 counting up, 1 counting down */
    int mcpwm_running[3];       /* timer started */
    int mcpwm_stopat[3];        /* one-shot: 0 never, 1 at zero, 2 at peak */
    uint32_t mcpwm_level[3][2]; /* generator output levels */

    /* GDMA (0x60080000): 3 TX channels feeding the I2S0 TX FIFO */
    uint32_t gdma_out_conf0[3];
    uint32_t gdma_out_conf1[3];
    uint32_t gdma_out_link[3];
    uint32_t gdma_out_eof_des_addr[3];
    uint32_t gdma_out_dscr[3];
    uint32_t gdma_out_pri[3];
    uint32_t gdma_out_peri_sel[3];
    uint32_t gdma_out_int_raw[3];
    uint32_t gdma_out_int_ena[3];
    uint32_t gdma_tx_fifo[3][12];  /* 12-word TX FIFO (shared with I2S) */
    uint8_t gdma_tx_fifo_cnt[3];
    uint8_t gdma_tx_run[3];        /* descriptor walker active */
    uint32_t gdma_tx_desc_addr[3]; /* current descriptor address (full) */
    uint32_t gdma_tx_desc_buf[3];  /* current descriptor buffer (full) */
    uint32_t gdma_tx_desc_len[3];  /* current descriptor length (bytes) */
    uint32_t gdma_tx_desc_left[3]; /* bytes still to push */
    uint32_t gdma_tx_next_addr[3]; /* next descriptor address (DW2) */
    uint64_t gdma_tx_drain_cyc[3]; /* next cycle for the paced drain */

    /* GDMA RX (IN) channels: fed from the I2S0 RX FIFO (synthesized
     * samples) and copied into guest RAM descriptors by the walker. */
    uint32_t gdma_in_conf0[3];
    uint32_t gdma_in_conf1[3];
    uint32_t gdma_in_link[3];
    uint32_t gdma_in_eof_des_addr[3];
    uint32_t gdma_in_dscr[3];
    uint32_t gdma_in_pri[3];
    uint32_t gdma_in_peri_sel[3];
    uint32_t gdma_in_int_raw[3];
    uint32_t gdma_in_int_ena[3];
    uint32_t gdma_rx_fifo[3][12];  /* 12-word RX FIFO (shared with I2S) */
    uint8_t gdma_rx_fifo_cnt[3];
    uint8_t gdma_rx_fifo_head[3];  /* index of oldest entry */
    uint8_t gdma_rx_run[3];         /* descriptor walker active */
    uint32_t gdma_rx_desc_addr[3];  /* current descriptor address (full) */
    uint32_t gdma_rx_desc_buf[3];  /* current descriptor buffer (full) */
    uint32_t gdma_rx_desc_len[3];  /* current descriptor length (bytes) */
    uint32_t gdma_rx_desc_left[3]; /* bytes still to pull */
    uint32_t gdma_rx_next_addr[3]; /* next descriptor address (DW2) */
    uint64_t gdma_rx_fill_cyc[3];  /* next cycle for the paced fill */
    uint32_t gdma_rx_sample[3];     /* running synthesized sample counter */

    /* UART0/1 RX FIFOs (128-byte rings). Port 0 is also fed from the
     * host injection file (-U); port 1 gets data via the TX->RX loopback
     * bit (CONF0 bit 12) so a sketch can send and receive on Serial1.
     * (ESP32-C6 has only UART0 and UART1.) */
    uint8_t uart_rx[2][128];
    unsigned int uart_rx_head[2];
    unsigned int uart_rx_tail[2];
    /* TX FIFO occupancy model: the driver's TX ISR only moves bytes from
     * its software ring buffer into the HW FIFO when the TXFIFO_EMPTY
     * interrupt fires. The model reports the TX FIFO as always-empty and
     * paces the TXFIFO_EMPTY interrupt via uart_tx_cnt/uart_tx_idle so the
     * esp-idf uart driver actually drains its ring buffer into the FIFO. */
    unsigned int uart_tx_cnt[2];
    uint8_t uart_tx_idle[2];
    int uart_rx_fd; /* host injection fd for port 0, -1 when not open */

    /* flash cache MMU page table: 256 x 64KB pages, programmed through
     * SPI_MEM_MMU_ITEM_CONTENT (0x6000237C) with page size
     * 2^(16-mode) (mode = SPI_MEM_MMU_PAGE_MODE bits[4:3]) */
    uint32_t mmu[256];
    uint32_t mmu_page_mode; /* bits [4:3] of 0x60002384 */
    uint32_t mmu_index;     /* last written MMU_ITEM_INDEX */
};

void (*esp32h2_uart_output)(char c) = NULL;
void (*esp32h2_gpio_output)(int pin, bool level) = NULL;

/* Optional flash image (bootloader @ 0x0 + partitions @ 0x8000 + app @
 * 0x10000). When set, the machine boots from the ROM reset vector. */
const char *esp32h2_flash_image_path = NULL;

/* Optional UART RX injection source (FIFO file the host writes to). */
const char *esp32h2_uart_rx_path = NULL;

/* ------------------------------------------------------------------ */
/* Region helpers                                                      */
/* ------------------------------------------------------------------ */

static esp32_region_t *esp32_find_region(esp32h2_t *soc, uint32_t addr)
{
    for (int i = 0; i < soc->nregions; i++) {
        esp32_region_t *r = &soc->regions[i];
        if (addr >= r->base && addr < r->base + r->size)
            return r;
    }
    return NULL;
}

/* Host pointer for guest RAM (DMA descriptors and data buffers always live
 * in SRAM/LP-SRAM; flash windows are never DMA targets). */
static uint8_t *esp32h2_dma_ptr(esp32h2_t *soc, uint32_t addr)
{
    esp32_region_t *r = esp32_find_region(soc, addr);
    if (!r || r->type != ESP32_REG_RAM)
        return NULL;
    return r->data + (addr - r->base);
}

/* Guest virtual address -> host pointer for any RAM region (used by the
 * panic-debug dump in emulate.c to read the guest stack / reason string). */
uint8_t *esp32h2_guest_to_host(esp32h2_t *soc, uint32_t addr)
{
    esp32_region_t *r = esp32_find_region(soc, addr);
    if (!r || r->type != ESP32_REG_RAM || !r->data)
        return NULL;
    return r->data + (addr - r->base);
}

/* Load the descriptor at gdma_tx_desc_addr[ch] into the walker state.
 * Descriptor layout (3 words): DW0 = owner(31) | eof(30) | sosf(29) |
 * offset(28:24) | length(23:12) | size(11:0); DW1 = buffer address;
 * DW2 = next descriptor address (0 = last). */
static void esp32h2_gdma_load_desc(esp32h2_t *soc, int ch)
{
    uint8_t *d = esp32h2_dma_ptr(soc, soc->gdma_tx_desc_addr[ch]);
    if (!d) { /* descriptor not in RAM: park the channel */
        soc->gdma_tx_run[ch] = 0;
        return;
    }
    uint32_t dw0, dw1, dw2;
    memcpy(&dw0, d, 4);
    memcpy(&dw1, d + 4, 4);
    memcpy(&dw2, d + 8, 4);
    soc->gdma_tx_next_addr[ch] = dw2;
    soc->gdma_tx_desc_buf[ch] = dw1;
    soc->gdma_tx_desc_len[ch] = (dw0 >> 12) & 0xFFFu;
    soc->gdma_tx_desc_left[ch] = soc->gdma_tx_desc_len[ch] & ~3u;
    soc->gdma_out_dscr[ch] = soc->gdma_tx_desc_addr[ch];
}

/* Load the RX (IN) descriptor at gdma_rx_desc_addr[ch] into the walker. */
static void esp32h2_gdma_load_rx_desc(esp32h2_t *soc, int ch)
{
    uint8_t *d = esp32h2_dma_ptr(soc, soc->gdma_rx_desc_addr[ch]);
    if (!d) { /* descriptor not in RAM: park the channel */
        soc->gdma_rx_run[ch] = 0;
        return;
    }
    uint32_t dw0, dw1, dw2;
    memcpy(&dw0, d, 4);
    memcpy(&dw1, d + 4, 4);
    memcpy(&dw2, d + 8, 4);
    soc->gdma_rx_next_addr[ch] = dw2;
    soc->gdma_rx_desc_buf[ch] = dw1;
    soc->gdma_rx_desc_len[ch] = (dw0 >> 12) & 0xFFFu;
    soc->gdma_rx_desc_left[ch] = soc->gdma_rx_desc_len[ch] & ~3u;
    soc->gdma_in_dscr[ch] = soc->gdma_rx_desc_addr[ch];
}

static void esp32_add_region(esp32h2_t *soc,
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

esp32h2_t *esp32h2_new(void)
{
    esp32h2_t *soc = calloc(1, sizeof(esp32h2_t));
    assert(soc);
    soc->systimer_conf = 0x40000000u; /* TIMER_UNIT0_WORK_EN default 1 */
    soc->strap_b0410 = 1; /* reset cause: POWERON (1); strapping handled via GPIO_STRAP */
    soc->uart_rx_fd = -1;

    /* virtual I2C device: 16-byte EEPROM with a known pattern */
    for (int i = 0; i < 16; i++)
        soc->i2c_dev_mem[i] = 0x40 + i;
    soc->i2c_dev_ptr = 0;
    /* virtual SPI device: 16-byte SRAM with the same known pattern */
    for (int i = 0; i < 16; i++)
        soc->spi2_dev_mem[i] = 0x40 + i;
    soc->spi2_jedec = 4;
    soc->gpio_in_prev = 0;

    /* flash backing shared by the i/d-cache window */
    uint8_t *flash = calloc(1, C6_FLASH_SIZE);
    assert(flash);

    esp32_add_region(soc, C6_SRAM_BASE, H2_SRAM_SIZE, ESP32_REG_RAM);
    esp32_add_region(soc, C6_LP_SRAM_BASE, C6_LP_SRAM_SIZE, ESP32_REG_RAM);
    esp32_add_region(soc, C6_ROM_BASE, H2_ROM_SIZE, ESP32_REG_RAM);

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

    /* GPIO matrix output select resets to 0x80 (SIG_GPIO_OUT): every pad
     * is a plain GPIO output until a peripheral signal is routed to it */
    for (int p = 0; p < 30; p++)
        ((uint32_t *) soc->mmio)[(0x91554u + 4u * p) >> 2] = 0x80u;

    /* flash cache MMU defaults to identity mapping (page i -> flash page i) */
    for (int i = 0; i < 256; i++)
        soc->mmu[i] = i;

    /* load the real ROM image */
    esp32_region_t *rom = esp32_find_region(soc, C6_ROM_BASE);
    assert(esp32h2_rom_bin_len <= H2_ROM_SIZE);
    memcpy(rom->data, esp32h2_rom_bin, esp32h2_rom_bin_len);

    /* H2 boot ROM / 2nd-stage bootloader populate several DRAM-resident
     * trampoline+flag tables (function pointers + status flags) in the
     * unloaded HP-SRAM region. On real silicon the bootloader fills them; the
     * emulator leaves them zeroed, so indirect calls land on null and flag
     * checks spin forever. As a stopgap, fill the whole unloaded region with a
     * tiny "li a0,0; ret" stub: flag slots read non-zero (spin + esp_timer
     * checks pass) and function-pointer slots jump to a stub returning success
     * (a0 = 0). */
    {
        esp32_region_t *sram = esp32_find_region(soc, C6_SRAM_BASE);
        const uint32_t stub = 0x4084FF00u;      /* inside HP-SRAM, un-filled */
        uint8_t *sp = sram->data + (stub - C6_SRAM_BASE);
        uint32_t insn0 = 0x00000513u;           /* li a0, 0 */
        uint32_t insn1 = 0x00008067u;           /* ret (jalr x0,0(ra)) */
        memcpy(sp, &insn0, 4);
        memcpy(sp + 4, &insn1, 4);
        uint32_t *tab =
            (uint32_t *)(sram->data + (0x4080d8b8u - C6_SRAM_BASE));
        /* fill from end of last loaded segment up to (not incl.) the stub */
        for (uint32_t a = 0x4080d8b8u; a < stub; a += 4)
            tab[(a - 0x4080d8b8u) / 4] = stub;
    }

    /* INTMTX default: source s maps to CPU line s */
    for (int i = 0; i < 96; i++)
        soc->intc_intmap[i] = i;

    return soc;
}

/* ------------------------------------------------------------------ */
/* UART0 (0x60000000)                                                  */
/* ------------------------------------------------------------------ */

#define UART_FIFO_REG 0x00u
#define UART_INT_RAW_REG 0x04u
#define UART_INT_ST_REG 0x08u
#define UART_INT_ENA_REG 0x0cu
#define UART_INT_CLR_REG 0x10u
#define UART_STATUS_REG 0x1Cu
/* On ESP32-C6 the loopback/conf0 bits live in `conf0_sync` at offset 0x20
 * (register 0x14 is now clkdiv_sync). Loopback = conf0_sync bit 12. */
#define UART_CONF0_REG 0x20u
#define UART_LOOPBACK_BIT (1u << 12) /* conf0_sync bit 12: TX->RX loopback */
#define UART_CLKDIV_CONF_REG 0x98u
#define UART_RX_FIFO_SZ 128u

/* INTMTX source for UART0 (interrupts.h enum, counted from 0) */
#define C6_UART0_INTR_SOURCE 33u
#define C6_UART1_INTR_SOURCE 34u
#define C6_TWAI0_INTR_SOURCE 36u
#define C6_GPIO_INTR_SOURCE 22u
#define C6_RMT_INTR_SOURCE 38u
/* I2C_EXT0 interrupt source (intmatrix.h enum) */
#define C6_I2C_EXT0_INTR_SOURCE 39u
/* TIMG0/TIMG1 timer interrupt sources (interrupts.h enum) */
#define C6_TG0_T0_INTR_SOURCE 41u
#define C6_TG1_T0_INTR_SOURCE 43u
/* TIMG0/TIMG1 watchdog interrupt sources (interrupts.h enum) */
#define C6_TG0_WDT_INTR_SOURCE 42u
#define C6_TG1_WDT_INTR_SOURCE 44u
/* PCNT interrupt source (interrupts.h enum) */
#define C6_PCNT_INTR_SOURCE 50u
/* MCPWM0 interrupt source (interrupts.h enum) */
#define C6_MCPWM_INTR_SOURCE 49u
/* I2S0 and GDMA interrupt sources (interrupts.h enum) */
#define C6_I2S0_INTR_SOURCE 31u
#define C6_DMA_IN_CH0_INTR_SOURCE 53u
#define C6_DMA_OUT_CH0_INTR_SOURCE 56u

/* Virtual I2C device: a 16-byte EEPROM at 0x50 that ACKs transfers */
#define C6_I2C_DEV_ADDR 0x50u
/* UART_RXFIFO_TOUT_INT_RAW */
#define UART_RXFIFO_TOUT_BIT 0x100u
/* UART_TXFIFO_EMPTY_INT_RAW (bit 1) */
#define UART_TXFIFO_EMPTY_BIT 0x2u

/* AES (0x60088000) register offsets/values — layout matches aes_struct.h:
 * key 0x00, text_in 0x20, text_out 0x30, mode 0x40, endian 0x44,
 * trigger 0x48, state 0x4C, iv 0x50, h/j0/t0 0x60..0x8C, dma_enable 0x90,
 * block_mode 0x94, block_num 0x98, aad_block_num 0xA0, conti 0xA8,
 * int_clear 0xAC, int_ena 0xB0, date 0xB4, dma_exit 0xB8. */
#define AES_BASE        (C6_PERIPH_BASE + 0x88000u)
#define SHA_BASE        (C6_PERIPH_BASE + 0x89000u)
#define AES_KEY_OFF     0x00u
#define AES_TEXT_IN_OFF 0x20u
#define AES_TEXT_OUT_OFF 0x30u
#define AES_MODE_OFF    0x40u   /* 0/1/2 enc 128/192/256; 4/5/6 dec 128/192/256 */
#define AES_TRIG_OFF    0x48u   /* write 1 to start */
#define AES_STATE_OFF   0x4Cu   /* 0 idle, 1 busy */
#define AES_IV_OFF      0x50u
#define AES_DMA_ENABLE_OFF 0x90u /* bit0: DMA mode enable */
#define AES_BLOCKMODE_OFF 0x94u /* 0 ECB, 1 CBC, 2 OFB, 3 CTR, 4 CFB-8, 5 CFB-128 */
#define AES_INT_CLR_OFF 0xACu
#define AES_INT_ENA_OFF 0xB0u   /* bit0: raise AES_INTR_SOURCE on DMA done */
#define ETS_AES_INTR_SOURCE 60u /* from esp32h2 interrupts.h (ESP32-C6) */
#define ETS_SHA_INTR_SOURCE 61u /* from esp32h2 interrupts.h (ESP32-C6) */

/* TWAI0 (CAN) register bits */
#define TWAI0_CMD_TX_REQUEST 0x1u
#define TWAI0_CMD_RELEASE_BUFFER 0x4u
#define TWAI0_CMD_CLEAR_DOVERRUN 0x8u
#define TWAI0_STATUS_RBS 0x1u
#define TWAI0_STATUS_DOS 0x2u
#define TWAI0_STATUS_TBS 0x4u
#define TWAI0_STATUS_TCS 0x8u
#define TWAI0_STATUS_RS 0x10u
#define TWAI0_INTR_TI 0x2u
#define TWAI0_INTR_RI 0x1u

/* ------------------------------------------------------------------ */
/* LEDC (0x60008000): 6 channels x (CONF0/HPOINT/DUTY/CONF1/DUTY_R),  */
/* 4 timers x (CONF/VALUE), INT_RAW/ST/ENA/CLR, CONF.                  */
/* ------------------------------------------------------------------ */

#define LEDC_CH_CONF0(c) (0x14u * (c))
#define LEDC_CH_HPOINT(c) (0x14u * (c) + 0x4u)
#define LEDC_CH_DUTY(c) (0x14u * (c) + 0x8u)
#define LEDC_CH_CONF1(c) (0x14u * (c) + 0xcu)
#define LEDC_CH_DUTY_R(c) (0x14u * (c) + 0x10u)
#define LEDC_TIMER_CONF(t) (0xa0u + 8u * (t))
#define LEDC_TIMER_VALUE(t) (0xa4u + 8u * (t))
#define LEDC_INT_RAW_OFF 0xc0u
#define LEDC_INT_ST_OFF 0xc4u
#define LEDC_INT_ENA_OFF 0xc8u
#define LEDC_INT_CLR_OFF 0xccu
#define LEDC_CONF_OFF 0x1f0u
#define LEDC_SIG_OUT_EN (1u << 2)
#define LEDC_IDLE_LV (1u << 3)
#define LEDC_DUTY_START (1u << 31)
#define LEDC_TIMER_RST (1u << 24)
#define LEDC_TIMER_PAUSE (1u << 23)
#define LEDC_TICK_SEL (1u << 25)

/* ------------------------------------------------------------------ */
/* TIMG0/1 (0x60009000/0x6000A000): one timer + WDT per group.         */
/* ------------------------------------------------------------------ */

#define TIMG_T0CONFIG 0x00u
#define TIMG_T0LO 0x04u
#define TIMG_T0HI 0x08u
#define TIMG_T0UPDATE 0x0cu
#define TIMG_T0ALARMLO 0x10u
#define TIMG_T0ALARMHI 0x14u
#define TIMG_T0LOADLO 0x18u
#define TIMG_T0LOADHI 0x1cu
#define TIMG_T0LOAD 0x20u
#define TIMG_INT_ENA 0x70u
#define TIMG_INT_RAW 0x74u
#define TIMG_INT_ST 0x78u
#define TIMG_INT_CLR 0x7cu
#define TIMG_RTCCALICFG 0x68u
#define TIMG_RTCCALICFG1 0x6cu
#define TIMG_REGCLK 0xfcu
#define TIMG_T0_EN (1u << 31)
#define TIMG_T0_INCREASE (1u << 30)
#define TIMG_T0_AUTORELOAD (1u << 29)
#define TIMG_T0_DIVIDER (0xFFFFu << 13)
#define TIMG_T0_DIVCNT_RST (1u << 12)
#define TIMG_T0_ALARM_EN (1u << 10)
#define TIMG_T0_USE_XTAL (1u << 9)
#define TIMG_INT_T0_ALARM (1u << 0)
#define TIMG_INT_WDT (1u << 1) /* WDT interrupt bit in the combined INT regs */

/* MWDT (within TIMG) register offsets and bits (esp32h2 timer_group) */
#define TIMG_WDT_CONFIG0 0x48u
#define TIMG_WDT_CONFIG1 0x4cu
#define TIMG_WDT_CONFIG2 0x50u
#define TIMG_WDT_FEED 0x60u
#define TIMG_WDT_WPROTECT 0x64u
#define TIMG_WDT_MAGIC 0x50D83AA1u /* unlock key written to WDTWPROTECT */
#define TIMG_WDT_EN (1u << 31)
#define TIMG_WDT_STG0 (3u << 29) /* stage0 action: 0=off,1=int,2=cpu-rst,3=sys-rst */
#define TIMG_WDT_STG0_INT (1u << 29)

/* Number of guest cycles until the MWDT (group g) times out, given the
 * current CONFIG1 (prescale) and CONFIG2 (stage0 hold). The WDT clock is
 * ~40 MHz while the guest cycle clock is ~80 MHz, so we multiply by 2 as
 * an approximation; exact timing is not required for correctness. */
static uint64_t esp32h2_wdt_cycles(esp32h2_t *soc, int g)
{
    uint32_t prescale =
        (soc->timg_reg[g][TIMG_WDT_CONFIG1 >> 2] >> 16) & 0xFFFFu;
    uint32_t hold = soc->timg_reg[g][TIMG_WDT_CONFIG2 >> 2];
    if (!hold)
        hold = 1u;
    return (uint64_t) hold * (uint64_t) (prescale + 1u) * 2u;
}

static void esp32_uart_putc(esp32h2_t *soc, char c)
{
    if (esp32h2_uart_output)
        esp32h2_uart_output(c);
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
#define GPIO_STATUS_REG 0x44u
#define GPIO_STATUS_W1TS_REG 0x48u
#define GPIO_STATUS_W1TC_REG 0x4Cu
#define GPIO_PCPU_INT_REG 0x5Cu

/* ------------------------------------------------------------------ */
/* SYSTIMER (0x6000B000; offsets identical to ESP32-C3                */
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

/* ESP32-H2 interrupt sources (soc/interrupts.h): 45 = SYSTIMER_TARGET0
 * (FreeRTOS tick), 47 = SYSTIMER_TARGET2 (esp_timer). */
#define SYSTIMER_T0_SOURCE 45u
#define SYSTIMER_T2_SOURCE 47u

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
static uint32_t esp32_mmu_page_shift(esp32h2_t *soc)
{
    uint32_t mode = (soc->mmu_page_mode >> 3) & 3u;
    return 16u - mode;
}

/* ---- AES block cipher (FIPS-197), used by the 0x60088000 peripheral ---- */
static const uint8_t aes_sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};
static const uint8_t aes_rsbox[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};
#define AES_ROTL(x,n) (((x)<<(n))|((x)>>(32-(n))))
static uint32_t aes_gmul2(uint32_t x){
    uint32_t r=x<<1; if(x&0x80) r^=0x1b; return r&0xff;
}
static uint32_t aes_subw(uint32_t w){
    return (aes_sbox[(w>>24)&0xff]<<24)|(aes_sbox[(w>>16)&0xff]<<16)|
           (aes_sbox[(w>>8)&0xff]<<8)|aes_sbox[w&0xff];
}
static uint32_t aes_rcon(unsigned i){ uint32_t c=1; while(--i) c=aes_gmul2(c); return c<<24; }

/* Expand key; nk = 4/6/8 (key words), nr = 10/12/14 rounds.
 * out has (nr+1)*4 32-bit words, little-endian byte order within word. */
static void aes_keyexp(const uint8_t *key, int nk, int nr, uint32_t *out)
{
    int i;
    for (i = 0; i < nk; i++)
        out[i] = (key[4*i]<<24)|(key[4*i+1]<<16)|(key[4*i+2]<<8)|key[4*i+3];
    for (i = nk; i < (nr+1)*4; i++) {
        uint32_t t = out[i-1];
        if (i % nk == 0)
            t = aes_subw(AES_ROTL(t,8)) ^ aes_rcon(i/nk);
        else if (nk > 6 && i % nk == 4)
            t = aes_subw(t);
        out[i] = out[i-nk] ^ t;
    }
}
static uint32_t aes_xtime(uint32_t a){ return aes_gmul2(a); }
static void aes_addroundkey(uint32_t *s, const uint32_t *k){ for(int i=0;i<4;i++) s[i]^=k[i]; }
static void aes_subbytes(uint32_t *s){ for(int i=0;i<4;i++){
    uint32_t w=s[i]; w=(aes_sbox[(w>>24)&0xff]<<24)|(aes_sbox[(w>>16)&0xff]<<16)|
            (aes_sbox[(w>>8)&0xff]<<8)|aes_sbox[w&0xff]; s[i]=w; } }
static void aes_invsubbytes(uint32_t *s){ for(int i=0;i<4;i++){
    uint32_t w=s[i]; w=(aes_rsbox[(w>>24)&0xff]<<24)|(aes_rsbox[(w>>16)&0xff]<<16)|
            (aes_rsbox[(w>>8)&0xff]<<8)|aes_rsbox[w&0xff]; s[i]=w; } }
static void aes_shiftrows(uint32_t *s){
    /* words are columns: s[c] = s[0,c]<<24 | s[1,c]<<16 | s[2,c]<<8 | s[3,c].
     * ShiftRows: byte at (row r, col c) moves to (row r, col c+r). */
    uint32_t r[4];
    for (int c = 0; c < 4; c++) {
        uint8_t b0 = (s[c & 3] >> 24) & 0xff;
        uint8_t b1 = (s[(c + 1) & 3] >> 16) & 0xff;
        uint8_t b2 = (s[(c + 2) & 3] >> 8) & 0xff;
        uint8_t b3 = (s[(c + 3) & 3]) & 0xff;
        r[c] = ((uint32_t)b0 << 24) | ((uint32_t)b1 << 16) |
               ((uint32_t)b2 << 8) | b3;
    }
    for (int c = 0; c < 4; c++) s[c] = r[c];
}
static void aes_invshiftrows(uint32_t *s){
    /* InvShiftRows: byte at (row r, col c) moves to (row r, col c-r). */
    uint32_t r[4];
    for (int c = 0; c < 4; c++) {
        uint8_t b0 = (s[(c) & 3] >> 24) & 0xff;
        uint8_t b1 = (s[(c - 1) & 3] >> 16) & 0xff;
        uint8_t b2 = (s[(c - 2) & 3] >> 8) & 0xff;
        uint8_t b3 = (s[(c - 3) & 3]) & 0xff;
        r[c] = ((uint32_t)b0 << 24) | ((uint32_t)b1 << 16) |
               ((uint32_t)b2 << 8) | b3;
    }
    for (int c = 0; c < 4; c++) s[c] = r[c];
}
static void aes_mixcolumns(uint32_t *s){
    for(int c=0;c<4;c++){
        uint8_t a[4],x[4];
        for(int i=0;i<4;i++) a[i]=(s[c]>>(24-8*i))&0xff;
        x[0]=aes_xtime(a[0])^aes_xtime(a[1])^a[1]^a[2]^a[3];
        x[1]=a[0]^aes_xtime(a[1])^aes_xtime(a[2])^a[2]^a[3];
        x[2]=a[0]^a[1]^aes_xtime(a[2])^aes_xtime(a[3])^a[3];
        x[3]=aes_xtime(a[0])^a[0]^a[1]^a[2]^aes_xtime(a[3]);
        s[c]=(x[0]<<24)|(x[1]<<16)|(x[2]<<8)|x[3];
    }
}
static uint32_t aes_mul9(uint32_t a){ return aes_gmul2(aes_gmul2(aes_gmul2(a))) ^ a; }
static uint32_t aes_mul11(uint32_t a){ return aes_gmul2(aes_gmul2(aes_gmul2(a))) ^ aes_gmul2(a) ^ a; }
static uint32_t aes_mul13(uint32_t a){ return aes_gmul2(aes_gmul2(aes_gmul2(a))) ^ aes_gmul2(aes_gmul2(a)) ^ a; }
static uint32_t aes_mul14(uint32_t a){ return aes_gmul2(aes_gmul2(aes_gmul2(a))) ^ aes_gmul2(aes_gmul2(a)) ^ aes_gmul2(a); }
static void aes_invmixcolumns(uint32_t *s){
    for(int c=0;c<4;c++){
        uint8_t a[4];
        for(int i=0;i<4;i++) a[i]=(s[c]>>(24-8*i))&0xff;
        uint8_t x[4];
        x[0]=aes_mul14(a[0])^aes_mul11(a[1])^aes_mul13(a[2])^aes_mul9(a[3]);
        x[1]=aes_mul9(a[0])^aes_mul14(a[1])^aes_mul11(a[2])^aes_mul13(a[3]);
        x[2]=aes_mul13(a[0])^aes_mul9(a[1])^aes_mul14(a[2])^aes_mul11(a[3]);
        x[3]=aes_mul11(a[0])^aes_mul13(a[1])^aes_mul9(a[2])^aes_mul14(a[3]);
        s[c]=(x[0]<<24)|(x[1]<<16)|(x[2]<<8)|x[3];
    }
}
/* Transform one 16-byte block in-place (in/out are 4 LE words). */
static void aes_block(const uint8_t *in, const uint8_t *key, int nk, int nr,
                      int encrypt, uint8_t *out)
{
    uint32_t w[4], rk[(14+1)*4];
    for (int i = 0; i < 4; i++)
        w[i] = (in[4*i]<<24)|(in[4*i+1]<<16)|(in[4*i+2]<<8)|in[4*i+3];
    aes_keyexp(key, nk, nr, rk);
    if (encrypt) {
        aes_addroundkey(w, rk);
        for (int r = 1; r <= nr; r++) {
            aes_subbytes(w);
            aes_shiftrows(w);
            if (r != nr) aes_mixcolumns(w);
            aes_addroundkey(w, rk + r*4);
        }
    } else {
        /* equivalent inverse cipher */
        aes_addroundkey(w, rk + nr*4);
        for (int r = nr-1; r >= 1; r--) {
            aes_invshiftrows(w);
            aes_invsubbytes(w);
            aes_addroundkey(w, rk + r*4);
            aes_invmixcolumns(w);
        }
        aes_invshiftrows(w);
        aes_invsubbytes(w);
        aes_addroundkey(w, rk);
    }
    for (int i = 0; i < 4; i++)
        out[4*i]=(w[i]>>24)&0xff, out[4*i+1]=(w[i]>>16)&0xff,
        out[4*i+2]=(w[i]>>8)&0xff, out[4*i+3]=w[i]&0xff;
}

/* Effective pad output for output-enabled pins: when the GPIO matrix routes a
 * peripheral signal (OUT_SEL set in FUNCn_OUT_SEL_CFG), the level is the one the
 * peripheral model already maintains in gpio_in; otherwise it is the GPIO
 * output register. This lets digitalRead() on a peripheral-driven pin (e.g. an
 * LEDC PWM output) report the live peripheral level instead of the static
 * gpio_out value. */
static uint32_t esp32h2_gpio_eff_out(esp32h2_t *soc, uint32_t *mmio32)
{
    uint32_t out = 0;
    for (int p = 0; p < 30; p++) {
        if (!(soc->gpio_enable & (1u << p)))
            continue;
        uint32_t sel = mmio32[(0x91554u + 4u * p) >> 2];
        if (sel & 0x100u)            /* peripheral signal drives the pad */
            out |= (soc->gpio_in & (1u << p));
        else
            out |= (soc->gpio_out & (1u << p));
    }
    return out;
}



static uint32_t esp32_mmio_read(riscv_t *rv, esp32h2_t *soc, uint32_t addr)
{
    (void) rv;
    /* INTPRI_CPU_INTR_FROM_CPU_0_REG (0x600C5090): the crosscore/yield
     * pending flag. The SDK raises it (write 1) and then busy-waits reading
     * this register for 0; the flag must read back as cleared once the
     * interrupt has been delivered. */
    if (addr == C6_PERIPH_BASE + 0xC5090u) {
        uint32_t v = (uint32_t)((soc->intc_status >> 7) & 1u);
        return v;
    }

    /* LP_TIMER (0x600B0C00): the firmware's light-sleep timer-wakeup path
     * busy-waits on the free-running 64-bit counter (counter[0].lo @0x14,
     * counter[0].hi @0x18). Advance the counter on each update pulse (see the
     * write path) so the wait loop eventually sees counter >= target and
     * exits the sleep. */
    if (addr >= 0x600B0C00u && addr < 0x600B0D00u) {
        uint32_t off = addr - 0x600B0C00u;
        if (off == 0x14u) return (uint32_t)(soc->lp_counter & 0xffffffffu);
        if (off == 0x18u) return (uint32_t)((soc->lp_counter >> 32) & 0xffffu);
        return 0;
    }

    /* PMU_INT_RAW (0x600B015C): bit 31 = SOC_WAKEUP_INT_RAW, set when the
     * sleep timer fires so pmu_sleep_start's wakeup-wait loop exits. The
     * firmware polls this register in a tight loop while the (free-running)
     * LP_TIMER counts up to the armed target; advance the timer on each poll
     * and latch the wakeup bit once it expires. */
    if (addr == 0x600B015Cu) {
        if (soc->lp_armed) {
            soc->lp_counter += 1000ull;
            if (soc->lp_counter >= soc->lp_target)
                soc->pmu_int_raw |= (1u << 31); /* SOC_WAKEUP_INT_RAW */
        }
        return soc->pmu_int_raw;
    }

    /* EFUSE_STATUS_REG (0x600B09D0): EFUSE_STATE (bits[3:0]) == 1 means the
     * eFuse state machine is idle/ready. pmu_sleep_finish busy-waits on this;
     * report ready so the wait completes. */
    if (addr == 0x600B09D0u)
        return 1;

    /* AES (0x60088000): plain storage except trigger/state, which the write
     * path maintains. */
    if (addr >= AES_BASE && addr < AES_BASE + 0x100u)
        return soc->aes_reg[(addr - AES_BASE) >> 2];

    /* Interrupt matrix (INTMTX) read-back: 0x60010000 + 4*source */
    if (addr >= C6_PERIPH_BASE + 0x10000u &&
        addr < C6_PERIPH_BASE + 0x10000u + 96 * 4u) {
        uint32_t s = (addr - C6_PERIPH_BASE - 0x10000u) >> 2;
        return soc->intc_intmap[s] & 0x1Fu;
    }

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
                for (int s = 0; s < 96; s++)
                    if (soc->intc_status & (((__uint128_t)1) << s))
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

    /* PCR (0x60096000..0x60097000): emulated peripherals are always
     * clock-ready. Force the READY status bits (bits 2..5) of every CONF
     * register so the mask ROM's enable-then-await loops (e.g.
     * PCR_UART0_CONF_REG bit2, PCR_MSPI_CONF_REG bit5, timer CONF bits 3/4)
     * complete instead of busy-waiting forever on hardware modelled as present.
     */
    if (addr >= 0x60096000u && addr < 0x60097000u) {
        /* Force the per-CONF READY bits (2..5) so enable-then-await loops
         * complete (see comment above). Additionally, PCR_BUS_CLK_UPDATE_REG
         * (0x60096148) bit 0 is a write-1 / auto-clear "clock update" trigger
         * the SDK pulses then busy-waits to clear; report it as already
         * cleared so all peripheral clock-enable sequences make progress.
         */
        uint32_t v = mmio32[(addr - C6_PERIPH_BASE) >> 2] | 0x3Cu;
        if (addr == 0x60096018u)
            /* PCR_MSPI_CONF_REG: |0x3C forces CLK_SEL[4:3]=11 (32 MHz source),
             * which trips spimem_flash_ll_get_source_freq_mhz -> 32 MHz and the
             * "Target 64MHz higher than src 32MHz" abort in get_flash_clock_divider.
             * Real H2 selects the MSPI PLL (CLK_SEL=2 -> 64 MHz). Clear bit3 so
             * CLK_SEL=0b10=2, matching silicon. */
            v &= ~(1u << 3);
        if (addr == 0x60096148u)
            v &= ~0x1u;
        return v;
    }

    /* I2C_ANA_MST (0x600AD800): the SDK issues analog-I2C commands to the
     * PMU/analog block and busy-waits on the per-CONF STATUS bit (reg bit 24,
     * i.e. I2C_MST_ANA_STATUS[0..2] bit 0). There is no analog-I2C peripheral
     * in this model, so report each command as completed instantly by forcing
     * the STATUS bit on reads of the CONF0/1/2 registers.
     */
    if (addr >= 0x600AD818u && addr <= 0x600AD820u)
        return mmio32[(addr - C6_PERIPH_BASE) >> 2] | 0x01000000u;

    /* SYSTIMER_UNIT0_OP_REG (0x6000b004): the mask ROM / SDK issues a unit
     * update (bit 30) and busy-waits on VALUE_VALID (bit 29). Report it valid
     * so the update completes instantly instead of spinning forever.
     */
    if (addr == 0x6000b004u)
        return mmio32[(addr - C6_PERIPH_BASE) >> 2] | (1u << 29);

    /* SPI2 (GPSPI2, 0x60081000-0x60081100) */
    if (addr >= C6_PERIPH_BASE + 0x81000u &&
        addr < C6_PERIPH_BASE + 0x81100u) {
        return soc->spi2_reg[(addr - C6_PERIPH_BASE - 0x81000u) >> 2];
    }

    /* GDMA (0x60080000-0x600802B0): IN + OUT channels and per-channel
     * interrupts. in_intr[ch] = {raw, st, ena, clr} at 0x00 + 16*ch;
     * out_intr[ch] at 0x30 + 16*ch. channel[ch] at 0x70 + 0xC0*ch; the IN
     * block is at +0x00 and the OUT block at +0x60. */
    if (addr >= C6_PERIPH_BASE + 0x80000u &&
        addr < C6_PERIPH_BASE + 0x802B0u) {
        uint32_t o = addr - C6_PERIPH_BASE - 0x80000u;
        if (o < 0x30u) { /* in_intr[3]: 0x00..0x2F */
            uint32_t ch = o >> 4;
            switch (o & 0xFu) {
            case 0x00: return soc->gdma_in_int_raw[ch];
            case 0x04: return soc->gdma_in_int_raw[ch] &
                              soc->gdma_in_int_ena[ch];
            case 0x08: return soc->gdma_in_int_ena[ch];
            default:   return 0; /* clr: write-only */
            }
        }
        if (o >= 0x30u && o < 0x70u) { /* out_intr[3] */
            uint32_t ch = (o - 0x30u) >> 4;
            switch (o & 0xFu) {
            case 0x00: return soc->gdma_out_int_raw[ch];
            case 0x04: return soc->gdma_out_int_raw[ch] &
                              soc->gdma_out_int_ena[ch];
            case 0x08: return soc->gdma_out_int_ena[ch];
            default:   return 0; /* clr: write-only */
            }
        }
        if (o >= 0x70u && o < 0x2B0u) {
            uint32_t c = (o - 0x70u) / 0xC0u;
            uint32_t r = o - 0x70u - c * 0xC0u;
            if (r < 0x60u) { /* IN block */
                switch (r) {
                case 0x00: return soc->gdma_in_conf0[c];
                case 0x04: return soc->gdma_in_conf1[c];
                case 0x08: /* infifo_status: FULL/EMPTY/CNT */
                    return (uint32_t)(soc->gdma_rx_fifo_cnt[c] << 2) |
                           (soc->gdma_rx_fifo_cnt[c] >= 12u ? 1u : 0u) |
                           (soc->gdma_rx_fifo_cnt[c] == 0u ? 2u : 0u);
                case 0x0C: return 0; /* in_pop: read returns nothing */
                case 0x10: /* in_link: park set when the FSM is idle */
                    return (soc->gdma_in_link[c] & 0xFFFFFu) |
                           (soc->gdma_rx_run[c] ? 0u : (1u << 24));
                case 0x14: return 0; /* in_state: idle */
                case 0x18: return soc->gdma_in_eof_des_addr[c];
                case 0x1C: return 0; /* in_err_eof_des_addr */
                case 0x20: return soc->gdma_in_dscr[c];
                case 0x2C: return soc->gdma_in_pri[c];
                case 0x30: return soc->gdma_in_peri_sel[c];
                default:   return 0;
                }
            }
            switch (r) { /* OUT block */
                case 0x60: return soc->gdma_out_conf0[c];
                case 0x64: return soc->gdma_out_conf1[c];
                case 0x68: /* outfifo_status: FULL/EMPTY/CNT */
                    return (uint32_t)(soc->gdma_tx_fifo_cnt[c] << 2) |
                           (soc->gdma_tx_fifo_cnt[c] >= 12u ? 1u : 0u) |
                           (soc->gdma_tx_fifo_cnt[c] == 0u ? 2u : 0u);
                case 0x70: /* out_link: park set when the FSM is idle */
                    return (soc->gdma_out_link[c] & 0xFFFFFu) |
                           (soc->gdma_tx_run[c] ? 0u : (1u << 23));
                case 0x74: return 0; /* out_state: idle */
                case 0x78: return soc->gdma_out_eof_des_addr[c];
                case 0x80: return soc->gdma_out_dscr[c];
                case 0x8C: return soc->gdma_out_pri[c];
                case 0x90: return soc->gdma_out_peri_sel[c];
            }
        }
        return mmio32[off >> 2];
    }

    /* TWAI0 (CAN, 0x6000C000-0x6000C100) */
    if (addr >= C6_PERIPH_BASE + 0xC000u &&
        addr < C6_PERIPH_BASE + 0xC100u) {
        uint32_t off = addr - C6_PERIPH_BASE - 0xC000u;
        if (off == 0x08u) { /* status: TBS + TCS + RBS + RS(=reset mode) */
            uint32_t v = TWAI0_STATUS_TBS |
                         ((soc->twai_reg[0] & 1u) ? TWAI0_STATUS_RS : 0u);
            v |= soc->twai_reg[0x08 >> 2] &
                 (TWAI0_STATUS_RBS | TWAI0_STATUS_TCS);
            return v;
        }
        if (off == 0x0Cu) { /* interrupt: read-to-clear, RI is a level */
            uint32_t v = soc->twai_reg[0x0c >> 2];
            soc->twai_reg[0x0c >> 2] = 0;
            /* RI re-asserts while the receive buffer is full and the
             * receive interrupt is enabled */
            if ((soc->twai_reg[0x08 >> 2] & TWAI0_STATUS_RBS) &&
                (soc->twai_reg[0x10 >> 2] & TWAI0_INTR_RI))
                soc->twai_reg[0x0c >> 2] = TWAI0_INTR_RI;
            if (!soc->twai_reg[0x0c >> 2])
                soc->intc_status &= ~(((__uint128_t)1) << C6_TWAI0_INTR_SOURCE);
            return v;
        }
        return soc->twai_reg[off >> 2];
    }

    /* SARADC (0x6000E000-0x6000E404): oneshot conversion state */
    if (addr >= C6_PERIPH_BASE + 0xE000u &&
        addr < C6_PERIPH_BASE + 0xE404u) {
        uint32_t o = off - 0xE000u;
        if (o == 0x2Cu) /* sar1data_status: raw result */
            return soc->adc_reg[o >> 2];
        if (o == 0x58u) /* tsens ctrl: the 8-bit sensor output field is RO;
                          raw 120 reads 32 C (0.4386*raw - 20.52) */
            return (soc->adc_reg[o >> 2] & ~0xFFu) | 0x78u;
        if (o == 0x44u) /* int_raw */
            return soc->adc_reg[o >> 2];
        if (o == 0x48u) /* int_st = raw & ena */
            return soc->adc_reg[0x44 >> 2] & soc->adc_reg[0x40 >> 2];
        if (o == 0x400u) /* version */
            return 0x02206840u;
        return soc->adc_reg[o >> 2];
    }

    /* PCNT (0x60012000-0x60012100) */
    if (addr >= C6_PERIPH_BASE + 0x12000u &&
        addr < C6_PERIPH_BASE + 0x12100u) {
        uint32_t o = off - 0x12000u;
        if (o == 0x44u) /* int_st = raw & ena */
            return soc->pcnt_reg[0x40 >> 2] & soc->pcnt_reg[0x48 >> 2];
        return soc->pcnt_reg[o >> 2];
    }

    /* MCPWM (0x60014000-0x60014130) */
    if (addr >= C6_PERIPH_BASE + 0x14000u &&
        addr < C6_PERIPH_BASE + 0x14130u) {
        uint32_t o = off - 0x14000u;
        if ((o & 0xFu) == 0x0u && o >= 0x10u && o <= 0x30u) {
            /* timer_status: live counter value (timer t = offset/16 - 1) */
            int t = (o >> 4) - 1;
            return ((uint32_t) soc->mcpwm_dir[t] << 16) |
                   soc->mcpwm_phase[t];
        }
        if (o == 0x19Cu) /* int_st = raw & ena */
            return soc->mcpwm_reg[0x198u >> 2] & soc->mcpwm_reg[0x194u >> 2];
        return soc->mcpwm_reg[o >> 2];
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
        if (addr == C6_PERIPH_BASE + 0x401cu) { /* data: RX fifo pop */
            if (soc->i2c_rx_pos < soc->i2c_rx_len) {
                uint32_t v = soc->i2c_rx_fifo[soc->i2c_rx_pos++];
                soc->i2c_reg[0x1c >> 2] = v;
            }
        }
        return *r;
    }

    /* UART0/1/2 (0x60000000 / 0x60010000 / 0x60020000) */
    for (int p = 0; p < 2; p++) {
        uint32_t base = C6_PERIPH_BASE + 0x1000u * p;
        if (addr >= base && addr < base + 0x1000u) {
            uint32_t o = addr - base;
            switch (o) {
            case UART_FIFO_REG:
                if (soc->uart_rx_head[p] != soc->uart_rx_tail[p]) {
                    uint8_t b = soc->uart_rx[p][soc->uart_rx_tail[p]];
                    soc->uart_rx_tail[p] =
                        (soc->uart_rx_tail[p] + 1) & (UART_RX_FIFO_SZ - 1u);
                    return b;
                }
                return 0; /* empty FIFO reads as zero */
            case UART_STATUS_REG: {
                /* RXFIFO_CNT [5:0]; TX side left at 0 (always room) */
                return (soc->uart_rx_head[p] - soc->uart_rx_tail[p]) &
                       (UART_RX_FIFO_SZ - 1u);
            }
            case UART_INT_ST_REG:
                return mmio32[(base + UART_INT_RAW_REG - C6_PERIPH_BASE) >> 2] &
                       mmio32[(base + UART_INT_ENA_REG - C6_PERIPH_BASE) >> 2];
            case UART_CLKDIV_CONF_REG:
                /* the divider sync completes instantly in the model */
                return mmio32[off >> 2] & ~0x1u;
            default:
                return mmio32[off >> 2];
            }
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
    /* RMT: INT_ST (0x3C) is the raw status masked by INT_ENA */
    if (addr == C6_PERIPH_BASE + 0x703Cu)
        return mmio32[0x7038u >> 2] & mmio32[0x7040u >> 2];
    /* LEDC (0x60008000-0x60008200) */
    if (addr >= C6_PERIPH_BASE + 0x8000u &&
        addr < C6_PERIPH_BASE + 0x8200u) {
        uint32_t o = addr - C6_PERIPH_BASE - 0x8000u;
        for (int c = 0; c < 6; c++)
            if (o == LEDC_CH_DUTY_R(c))
                return soc->ledc_duty_r[c];
        for (int t = 0; t < 4; t++)
            if (o == LEDC_TIMER_VALUE(t))
                return soc->ledc_reg[o >> 2];
        if (o == LEDC_INT_ST_OFF)
            return soc->ledc_reg[LEDC_INT_RAW_OFF >> 2] &
                   soc->ledc_reg[LEDC_INT_ENA_OFF >> 2];
        if (o == LEDC_INT_RAW_OFF) {
            /* raw reflects the running duty changes (model: always done) */
            return soc->ledc_reg[o >> 2];
        }
        return soc->ledc_reg[o >> 2];
    }
    /* TIMG0/1 (0x60009000-0x60009100, 0x6000A000-0x6000A100) */
    if (addr >= C6_PERIPH_BASE + 0x9000u &&
        addr < C6_PERIPH_BASE + 0x9100u) {
        uint32_t o = addr - C6_PERIPH_BASE - 0x9000u;
        if (o == TIMG_T0LO)
            return (uint32_t) soc->timg_counter[0];
        if (o == TIMG_T0HI)
            return (uint32_t) (soc->timg_counter[0] >> 32);
        if (o == TIMG_INT_ST)
            return soc->timg_reg[0][TIMG_INT_RAW >> 2] &
                   soc->timg_reg[0][TIMG_INT_ENA >> 2];
        return soc->timg_reg[0][o >> 2];
    }
    if (addr >= C6_PERIPH_BASE + 0xA000u &&
        addr < C6_PERIPH_BASE + 0xA100u) {
        uint32_t o = addr - C6_PERIPH_BASE - 0xA000u;
        if (o == TIMG_T0LO)
            return (uint32_t) soc->timg_counter[1];
        if (o == TIMG_T0HI)
            return (uint32_t) (soc->timg_counter[1] >> 32);
        if (o == TIMG_INT_ST)
            return soc->timg_reg[1][TIMG_INT_RAW >> 2] &
                   soc->timg_reg[1][TIMG_INT_ENA >> 2];
        return soc->timg_reg[1][o >> 2];
    }
    /* GPIO */
    if (addr >= C6_PERIPH_BASE + 0x91000u && addr < C6_PERIPH_BASE + 0x92000u) {
        switch (off - 0x91000u) {
        case GPIO_OUT_REG:
            return soc->gpio_out;
        case GPIO_ENABLE_REG:
            return soc->gpio_enable;
        case GPIO_IN_REG:
            return soc->gpio_in | esp32h2_gpio_eff_out(soc, mmio32);
        case GPIO_STATUS_REG:
            return soc->gpio_status;
        case GPIO_PCPU_INT_REG:
            return soc->gpio_status;
        case GPIO_STRAP_REG:
            /* strapping: GPIO9 high -> SPI flash boot (boot mode 1xxx) */
            return 0x8u;
        default:
            return mmio32[off >> 2];
        }
    }
    /* LP_CLKRST (0x600B0400): strapping / reset reason.
     * Low 5 bits are the boot-strapping; firmware requires ==5 for the
     * normal SPI-flash boot path (ROM reset and call_start_cpu0 branch on
     * this). The ROM/bootloader store the reset reason here, so keep it
     * writable (initialized to strapping 5). */
    if (addr == C6_PERIPH_BASE + 0xB0410u)
        return soc->strap_b0410;
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
    /* eFuse (0x600B0800): chip ID 0x0B (ESP32-H2) in the standard fields */
    if (addr == C6_PERIPH_BASE + 0xB0850u)
        return (0x0Bu << 24) | (0x0Bu << 18);
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
    /* SYSTIMER (0x6000B000) */
    if (addr >= C6_PERIPH_BASE + 0xB000u &&
        addr < C6_PERIPH_BASE + 0xC000u) {
        switch (off - 0xB000u) {
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

static void esp32h2_aes_run_dma(riscv_t *rv, int ch_out)
{
    esp32h2_t *soc = PRIV(rv)->esp32h2;
    int ch_in = -1;
    for (int ch = 0; ch < 3; ch++)
        if (soc->gdma_in_peri_sel[ch] == 6)
            ch_in = ch;

    int mode = soc->aes_reg[AES_MODE_OFF >> 2] & 0x7u;
    int bm = soc->aes_reg[AES_BLOCKMODE_OFF >> 2] & 0x7u;
    int nk = 0, nr = 0, encrypt = 0, ok = 1;
    switch (mode) {
    case 0: nk = 4; nr = 10; encrypt = 1; break;
    case 1: nk = 6; nr = 12; encrypt = 1; break;
    case 2: nk = 8; nr = 14; encrypt = 1; break;
    case 4: nk = 4; nr = 10; encrypt = 0; break;
    case 5: nk = 6; nr = 12; encrypt = 0; break;
    case 6: nk = 8; nr = 14; encrypt = 0; break;
    default: ok = 0;
    }
    if (!ok)
        return;

    uint8_t key[32], iv[16], final_out[16] = {0};
    for (int i = 0; i < nk * 4; i++)
        key[i] = (soc->aes_reg[(AES_KEY_OFF >> 2) + (i >> 2)] >> (8 * (i & 3))) & 0xff;
    for (int i = 0; i < 16; i++)
        iv[i] = (soc->aes_reg[(AES_IV_OFF >> 2) + (i >> 2)] >> (8 * (i & 3))) & 0xff;

    uint32_t in_cur = C6_SRAM_BASE + (soc->gdma_out_link[ch_out] & 0xFFFFFu);
    uint32_t out_cur = ch_in >= 0 ? C6_SRAM_BASE + (soc->gdma_in_link[ch_in] & 0xFFFFFu) : 0;
    uint32_t out_desc0 = in_cur;   /* first OUT descriptor (s_stream_out_desc) */
    uint32_t in_desc0 = out_cur;   /* first IN descriptor (s_stream_in_desc) */
    uint32_t in_buf = 0, in_off = 0, in_len = 0;
    uint32_t out_buf = 0, out_off = 0, out_len = 0;

    for (;;) {
        if (in_len == 0) {
            if (!in_cur) break;
            uint8_t *d = esp32h2_dma_ptr(soc, in_cur);
            if (!d) break;
            uint32_t dw0, dw1, dw2;
            memcpy(&dw0, d, 4); memcpy(&dw1, d + 4, 4); memcpy(&dw2, d + 8, 4);
            if (!(dw0 & 0x80000000u)) break; /* owner = software */
            in_buf = dw1; in_len = (dw0 >> 12) & 0xFFFu; in_off = 0;
            in_cur = dw2;
        }
        if (in_len < 16) break;
        uint8_t in[16], out[16], blk[16];
        for (int i = 0; i < 16; i++) {
            uint8_t *p = esp32h2_dma_ptr(soc, in_buf + in_off);
            if (!p) { in_len = 0; goto done; }
            in[i] = *p; in_off++; in_len--;
        }
        if (bm == 1) {
            for (int i = 0; i < 16; i++) blk[i] = in[i] ^ iv[i];
            aes_block(blk, key, nk, nr, encrypt, out);
            if (encrypt)
                for (int i = 0; i < 16; i++) iv[i] = out[i];
            else
                for (int i = 0; i < 16; i++) iv[i] = in[i];
        } else {
            aes_block(in, key, nk, nr, encrypt, out);
        }
        memcpy(final_out, out, 16);
        for (int i = 0; i < 16; i++) {
            if (out_len == 0) {
                if (!out_cur) break;
                uint8_t *d = esp32h2_dma_ptr(soc, out_cur);
                if (!d) break;
                uint32_t dw0, dw1, dw2;
                memcpy(&dw0, d, 4); memcpy(&dw1, d + 4, 4); memcpy(&dw2, d + 8, 4);
                out_buf = dw1; out_len = (dw0 >> 12) & 0xFFFu; out_off = 0;
                out_cur = dw2;
            }
            uint8_t *p = esp32h2_dma_ptr(soc, out_buf + out_off);
            if (p) *p = out[i];
            out_off++; out_len--;
        }
    }
done:
    /* Descriptor write-back: real GDMA hardware clears the descriptor owner
     * bit (dw0[31]) and sets the EOF/SUC_EOF bit when a transfer completes.
     * The esp_aes driver polls s_stream_out_desc[0].owner (bit31) to detect
     * DMA completion (esp_aes_dma_done returns (~(*s3))>>31), so we must
     * update the descriptors in guest RAM or the driver spins forever. */
    for (uint32_t w = out_desc0; w;) {
        uint8_t *d = esp32h2_dma_ptr(soc, w);
        if (!d) break;
        uint32_t dw0, dw1, dw2;
        memcpy(&dw0, d, 4); memcpy(&dw1, d + 4, 4); memcpy(&dw2, d + 8, 4);
        dw0 &= ~0x80000000u; /* owner = software */
        dw0 |= (1u << 0);    /* OUT EOF */
        memcpy(d, &dw0, 4);
        w = dw2;
    }
    if (ch_in >= 0) {
        for (uint32_t w = in_desc0; w;) {
            uint8_t *d = esp32h2_dma_ptr(soc, w);
            if (!d) break;
            uint32_t dw0, dw1, dw2;
            memcpy(&dw0, d, 4); memcpy(&dw1, d + 4, 4); memcpy(&dw2, d + 8, 4);
            dw0 &= ~0x80000000u; /* owner = software */
            dw0 |= (1u << 1);    /* IN_SUC_EOF */
            memcpy(d, &dw0, 4);
            w = dw2;
        }
    }
    if (bm == 1)
        for (int i = 0; i < 16; i++)
            soc->aes_reg[(AES_IV_OFF >> 2) + (i >> 2)] =
                (soc->aes_reg[(AES_IV_OFF >> 2) + (i >> 2)] & ~(0xffu << (8 * (i & 3)))) |
                ((uint32_t) iv[i] << (8 * (i & 3)));

    /* Completion. The esp_aes driver busy-waits on the AES state register
     * (0x4C); set it to calculation_done (2) so its poll releases. The GDMA
     * EOF/SUC_EOF raw status bits and the AES accelerator interrupt
     * (ETS_AES_INTR_SOURCE=73) are latched so the esp_aes_complete_isr
     * (registered by esp_aes_intr_alloc) fires, clears the in-progress flag
     * (*s3) and gives op_complete_sem. */
    soc->intc_status |= ((__uint128_t)1) << ETS_AES_INTR_SOURCE;
    if (ch_out >= 0) {
        soc->gdma_out_int_raw[ch_out] |= (1u << 1) | (1u << 3); /* EOF + TOTAL_EOF */
        soc->gdma_out_int_ena[ch_out] |= (1u << 1) | (1u << 3); /* let ISR see+clear it */
        if (soc->gdma_out_int_ena[ch_out] & ((1u << 1) | (1u << 3)))
            soc->intc_status |= ((__uint128_t)1) << (C6_DMA_OUT_CH0_INTR_SOURCE + ch_out);
        soc->gdma_tx_run[ch_out] = 0;
    }
    if (ch_in >= 0) {
        soc->gdma_in_int_raw[ch_in] |= 1u << 1; /* IN_SUC_EOF */
        soc->gdma_in_int_ena[ch_in] |= 1u << 1;
        if (soc->gdma_in_int_ena[ch_in] & (1u << 1))
            soc->intc_status |= ((__uint128_t)1) << (C6_DMA_IN_CH0_INTR_SOURCE + ch_in);
        soc->gdma_rx_run[ch_in] = 0;
    }
    /* DMA-AES: state transitions busy(1) -> calculation_done(2). The esp_aes
     * driver busy-waits on this register, so set it to "done" (bit0=0 not
     * busy, bit1=1 done) to release the poll. */
    soc->aes_reg[AES_STATE_OFF >> 2] = 2;
}

static void esp32h2_gpio_edge_check(esp32h2_t *soc, uint32_t *mmio32,
                                    uint32_t new_live);

static void esp32_mmio_write(riscv_t *rv, uint32_t addr, uint32_t val)
{
    esp32h2_t *soc = PRIV(rv)->esp32h2;

    /* 0x600B0410: strapping / reset-reason store register. The ROM writes
     * the resolved reset reason here; keep it writable so the bootloader's
     * later read reflects the real cause (not the hardcoded strapping). */
    if (addr == C6_PERIPH_BASE + 0xB0410u) {
        soc->strap_b0410 = val;
        return;
    }

    /* SHA (0x60089000): advance the digest synchronously on SHA_START /
     * SHA_CONTINUE so the mask ROM / SDK SHA routines (image hashing, secure
     * boot) complete instead of busy-waiting on the done bit. */
    /* SHA accelerator: the mask ROM / esp-idf feed the message one 32-bit
     * word at a time into SHA_M_MEM (0x80..0xBF); the running digest is read
     * from SHA_H_MEM (0x40..0x7F) which triggers the synchronous compute.
     * SHA_MODE (0x00) starts a new session. Mirror the C6 wiring. */
    if (addr >= C6_PERIPH_BASE + 0x89000u && addr < C6_PERIPH_BASE + 0x8A000u) {
        uint32_t *mmio32 = (uint32_t *) soc->mmio;
        if (addr == C6_PERIPH_BASE + 0x89000u) {        /* SHA_MODE: new session */
            if (sha_reset_pending) {
                esp32_sha_reset();
                sha_reset_pending = 0;
            }
            mmio32[(addr - C6_PERIPH_BASE) >> 2] = val;
            return;
        }
        if (addr == C6_PERIPH_BASE + 0x89010u) {        /* SHA_START */
            mmio32[(addr - C6_PERIPH_BASE) >> 2] = val;
            return;
        }
        if (addr == C6_PERIPH_BASE + 0x89014u) {        /* SHA_CONTINUE */
            mmio32[(addr - C6_PERIPH_BASE) >> 2] = val;
            return;
        }
        if (addr >= C6_PERIPH_BASE + 0x89080u &&
            addr < C6_PERIPH_BASE + 0x890C0u) {          /* SHA M_MEM words */
            esp32_sha_feed_word(val);
            mmio32[(addr - C6_PERIPH_BASE) >> 2] = val;
            return;
        }
        mmio32[(addr - C6_PERIPH_BASE) >> 2] = val;
        return;
    }

    /* LP_TIMER (0x600B0C00): the firmware arms a sleep timer by writing the
     * target (target[0].lo @0x00, target[0].hi @0x04, enable in bit 31 of hi)
     * and then busy-waits on the free-running counter (counter[0].lo @0x14,
     * counter[0].hi @0x18). On each MAIN_TIMER_UPDATE pulse (bit 28) we
     * advance the counter; once it reaches the target we latch the PMU
     * SOC_WAKEUP_INT_RAW bit so pmu_sleep_start's wakeup-wait loop exits. */
    if (addr >= 0x600B0C00u && addr < 0x600B0D00u) {
        uint32_t off = addr - 0x600B0C00u;
        if (off == 0x00u) {
            soc->lp_target = (soc->lp_target & ~0xffffffffull) | (uint64_t)val;
            return;
        }
        if (off == 0x04u) {
            soc->lp_target = (soc->lp_target & 0xffffffffull) |
                             (((uint64_t)(val & 0xffffu)) << 32);
            if (val & (1u << 31)) {
                soc->lp_armed = 1;
                soc->lp_counter = 0; /* start a fresh countdown each arm */
            }
            return;
        }
        if (off == 0x10u) {
            if (val & (1u << 28))
                soc->lp_counter += 1000000ull;
            return;
        }
        return;
    }

    /* PMU_INT_RAW (0x600B015C): R/WTC — writing 1 clears the corresponding
     * raw bit (the firmware clears SOC_WAKEUP_INT_RAW after waking). */
    if (addr == 0x600B015Cu) {
        soc->pmu_int_raw &= ~val;
        return;
    }

    /* AES (0x60088000): most registers are plain storage; the trigger writes
     * the transform synchronously so the esp-idf driver (which busy-waits on
     * the state register) gets the result immediately on the next read. */
    if (addr >= AES_BASE && addr < AES_BASE + 0x100u) {
        uint32_t o = addr - AES_BASE;
        soc->aes_reg[o >> 2] = val;
        if (o == 0xB8u) /* AES_INT_CLR: firmware acknowledges the AES IRQ */
            soc->intc_status &= ~(((__uint128_t)1) << ETS_AES_INTR_SOURCE);
        if (o == AES_TRIG_OFF && (val & 1u)) {
            /* DMA mode (esp_aes / mbedtls): the input arrives via the GDMA
             * OUT channel (peri_sel == AES0 = 6) descriptor buffer and the
             * result is written back through the GDMA IN channel; the
             * text_in register is never written. Detect it by a started AES
             * GDMA channel. */
            int dma_ch = -1;
            for (int ch = 0; ch < 3; ch++)
                if (soc->gdma_out_peri_sel[ch] == 6 && soc->gdma_tx_run[ch])
                    dma_ch = ch;
            if (dma_ch >= 0) {
                esp32h2_aes_run_dma(rv, dma_ch);
            } else {
                int mode = soc->aes_reg[AES_MODE_OFF >> 2] & 0x7u;
                int bm = soc->aes_reg[AES_BLOCKMODE_OFF >> 2] & 0x7u;
                int nk = 0, nr = 0, encrypt = 0, ok = 1;
                switch (mode) {
                case 0: nk = 4; nr = 10; encrypt = 1; break;
                case 1: nk = 6; nr = 12; encrypt = 1; break;
                case 2: nk = 8; nr = 14; encrypt = 1; break;
                case 4: nk = 4; nr = 10; encrypt = 0; break;
                case 5: nk = 6; nr = 12; encrypt = 0; break;
                case 6: nk = 8; nr = 14; encrypt = 0; break;
                default: ok = 0;
                }
                if (ok) {
                    uint8_t key[32], in[16], out[16], iv[16];
                    /* The driver writes each 32-bit word via memcpy as
                     * b0|b1<<8|b2<<16|b3<<24, so byte i of the stream is at
                     * bit position 8*(i & 3) (LSB-first within the word). */
                    for (int i = 0; i < nk * 4; i++)
                        key[i] = (soc->aes_reg[(AES_KEY_OFF >> 2) + (i >> 2)] >>
                                  (8 * (i & 3))) & 0xff;
                    for (int i = 0; i < 16; i++)
                        in[i] = (soc->aes_reg[(AES_TEXT_IN_OFF >> 2) + (i >> 2)] >>
                                 (8 * (i & 3))) & 0xff;
                    for (int i = 0; i < 16; i++)
                        iv[i] = (soc->aes_reg[(AES_IV_OFF >> 2) + (i >> 2)] >>
                                 (8 * (i & 3))) & 0xff;
                    uint8_t blk[16];
                    if (bm == 1) { /* CBC */
                        for (int i = 0; i < 16; i++)
                            blk[i] = in[i] ^ iv[i];
                        aes_block(blk, key, nk, nr, encrypt, out);
                        if (encrypt)
                            for (int i = 0; i < 16; i++)
                                iv[i] = out[i];
                        else
                            for (int i = 0; i < 16; i++)
                                iv[i] = in[i];
                    } else { /* ECB (and fallback for other chaining modes) */
                        aes_block(in, key, nk, nr, encrypt, out);
                    }
                    for (int i = 0; i < 16; i++) {
                        int w = i >> 2, b = i & 3;
                        soc->aes_reg[(AES_TEXT_OUT_OFF >> 2) + w] &=
                            ~(0xffu << (8 * b));
                        soc->aes_reg[(AES_TEXT_OUT_OFF >> 2) + w] |=
                            (uint32_t) out[i] << (8 * b);
                    }
                    if (bm == 1)
                        for (int i = 0; i < 16; i++) {
                            int w = i >> 2, b = i & 3;
                            soc->aes_reg[(AES_IV_OFF >> 2) + w] &=
                                ~(0xffu << (8 * b));
                            soc->aes_reg[(AES_IV_OFF >> 2) + w] |=
                                (uint32_t) iv[i] << (8 * b);
                        }
                }
            }
            soc->aes_reg[AES_TRIG_OFF >> 2] = 0; /* WT: self-clears */
            /* DMA path keeps state=2 (calculation_done) so the driver's
             * busy-wait releases; register path returns to idle (0). */
            soc->aes_reg[AES_STATE_OFF >> 2] = (dma_ch >= 0) ? 2u : 0u;
        }
        return;
    }

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
            soc->intc_status &= ~(((__uint128_t)1) << C6_I2C_EXT0_INTR_SOURCE); /* drop the pending IRQ */
        } else if (addr == C6_PERIPH_BASE + 0x4018u) { /* fifo_conf */
            soc->i2c_reg[0x18 >> 2] = val;
            if (val & (1u << 13)) { /* tx_fifo_rst */
                soc->i2c_tx_len = 0;
            }
            if (val & (1u << 12)) { /* rx_fifo_rst */
                soc->i2c_rx_len = 0;
                soc->i2c_rx_pos = 0;
            }
        } else if (addr == C6_PERIPH_BASE + 0x401cu) { /* data: TX fifo push */
            soc->i2c_reg[0x1c >> 2] = val;
            if (soc->i2c_tx_len < 32)
                soc->i2c_tx_fifo[soc->i2c_tx_len++] = val & 0xFFu;
        } else if (addr == C6_PERIPH_BASE + 0x4004u) { /* ctr */
            *r = val;
            if (val & (1u << 5)) { /* trans_start (WT): transfer begins */
                uint32_t addr_byte = soc->i2c_tx_len > 0 ?
                                     soc->i2c_tx_fifo[0] : 0xFFu;
                soc->i2c_transfer_pending = 1;
                if ((addr_byte >> 1) == C6_I2C_DEV_ADDR) {
                    soc->i2c_slave_active = 1;
                    soc->i2c_slave_rw = addr_byte & 1u;
                } else {
                    soc->i2c_slave_active = 0;
                }
            }
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

    /* RMT (0x60007000-0x60007B00): registers + 4x48-word channel memory
     * at 0x400. TX completes (TX_DONE interrupt, source 38) a while after
     * conf0.tx_start is written; the driver's ISR clears INT_CLR. */
    if (addr >= C6_PERIPH_BASE + 0x7000u &&
        addr < C6_PERIPH_BASE + 0x7B00u) {
        uint32_t roff = addr - C6_PERIPH_BASE - 0x7000u;
        mmio32[off >> 2] = val;
        if (roff == 0x10u || roff == 0x14u) { /* CH0/CH1 CONF0 */
            uint32_t ch = (roff - 0x10u) >> 2;
            if (val & 0x1u) { /* tx_start */
                uint32_t div = (val >> 8) & 0xFFu;
                uint32_t mem_words =
                    (((val >> 16) & 0x7u) ?: 1u) * 48u;
                uint32_t *mem = mmio32 + (0x7400u >> 2) + ch * 48u;
                uint64_t ticks = 0;
                for (uint32_t i = 0; i < mem_words; i++) {
                    uint32_t w = mem[i];
                    if ((w & 0x7FFFu) == 0u) /* end marker */
                        break;
                    ticks += (w & 0x7FFFu) + ((w >> 16) & 0x7FFFu);
                }
                soc->rmt_tx_done_cycle =
                    rv->csr_cycle + (ticks * (div ? div : 1u)) / 8u + 1024u;
            }
            if (val & 0x80u) /* tx_stop */
                soc->rmt_tx_done_cycle = 0;
        }
        if (roff == 0x1cu || roff == 0x24u) { /* CH0/CH1 RX CONF1 */
            uint32_t ch = (roff - 0x1cu) >> 2;
            /* WT bits (mem_wr_rst bit1, apb_mem_rst bit2) self-clear and
             * reset the channel memory write pointer */
            if (val & 0x6u) {
                soc->rmt_rx_wptr[ch] = 0;
                mmio32[((0x7030u + 4u * ch) >> 2)] = (ch + 2u) * 48u;
                uint32_t *mem = mmio32 + (0x7400u >> 2) + (ch + 2u) * 48u;
                for (int i = 0; i < 48; i++)
                    mem[i] = 0;
            }
            mmio32[off >> 2] = val & ~0x6u;
            soc->rmt_rx_en[ch] = (val & 0x1u) ? 1 : 0;
            if (soc->rmt_rx_en[ch]) {
                /* arm at the current input level so the first duration is
                 * measured from the next transition */
                uint32_t insel = mmio32[(0x91270u + 4u * ch) >> 2] & 0x3Fu;
                soc->rmt_rx_last_level[ch] =
                    (soc->gpio_in >> insel) & 1u;
                soc->rmt_rx_trans_cycle[ch] = rv->csr_cycle;
                soc->rmt_rx_last_cycle[ch] = rv->csr_cycle;
            }
        } else if (roff == 0x44u) { /* INT_CLR: clear raw status */
            mmio32[0x7038u >> 2] &= ~val;
            soc->intc_status &= ~(((__uint128_t)1) << C6_RMT_INTR_SOURCE);
            if (mmio32[0x7038u >> 2] & mmio32[0x7040u >> 2])
                soc->intc_status |= ((__uint128_t)1) << C6_RMT_INTR_SOURCE;
        } else {
            mmio32[off >> 2] = val;
        }
        return;
    }

    /* LEDC (0x60008000-0x60008200) */
    if (addr >= C6_PERIPH_BASE + 0x8000u &&
        addr < C6_PERIPH_BASE + 0x8200u) {
        uint32_t o = addr - C6_PERIPH_BASE - 0x8000u;
        for (int c = 0; c < 6; c++) {
            if (o == LEDC_CH_CONF1(c)) {
                soc->ledc_reg[o >> 2] = val;
                if (val & LEDC_DUTY_START) {
                    /* duty update starts: the running duty becomes DUTY */
                    soc->ledc_duty_r[c] = soc->ledc_reg[LEDC_CH_DUTY(c) >> 2];
                    soc->ledc_reg[LEDC_CH_CONF1(c) >> 2] &= ~LEDC_DUTY_START;
                }
                return;
            }
        }
        for (int t = 0; t < 4; t++) {
            if (o == LEDC_TIMER_CONF(t)) {
                if (val & LEDC_TIMER_RST) {
                    soc->ledc_timer_anchor[t] = rv->csr_cycle;
                    soc->ledc_timer_frac[t] = 0;
                }
                soc->ledc_reg[o >> 2] = val & ~(LEDC_TIMER_RST);
                return;
            }
        }
        if (o == LEDC_INT_CLR_OFF) {
            soc->ledc_reg[LEDC_INT_RAW_OFF >> 2] &= ~val;
            return;
        }
        soc->ledc_reg[o >> 2] = val;
        return;
    }

    /* TIMG0/1 (0x60009000-0x60009100, 0x6000A000-0x6000A100) */
    if (addr >= C6_PERIPH_BASE + 0x9000u &&
        addr < C6_PERIPH_BASE + 0x9100u) {
        uint32_t o = addr - C6_PERIPH_BASE - 0x9000u;
        uint32_t *r = soc->timg_reg[0];
        if (o == TIMG_T0CONFIG) {
            /* counter (re)anchors on enable/divider/clock changes */
            soc->timg_anchor[0] = rv->csr_cycle;
            soc->timg_frac[0] = 0;
            r[o >> 2] = val & ~TIMG_T0_DIVCNT_RST;
        } else if (o == TIMG_T0LOAD) {
            soc->timg_counter[0] = ((uint64_t) r[TIMG_T0LOADHI >> 2] << 32) |
                                   r[TIMG_T0LOADLO >> 2];
            soc->timg_anchor[0] = rv->csr_cycle;
            soc->timg_frac[0] = 0;
            r[o >> 2] = 0;
        } else if (o == TIMG_T0UPDATE) {
            r[o >> 2] = 0; /* reads use the live counter; nothing to latch */
        } else if (o == TIMG_INT_CLR) {
            r[TIMG_INT_RAW >> 2] &= ~val;
            if (!(r[TIMG_INT_RAW >> 2] & r[TIMG_INT_ENA >> 2]))
                soc->intc_status &= ~(((__uint128_t)1) << C6_TG0_T0_INTR_SOURCE);
            r[o >> 2] = 0;
        } else if (o == TIMG_RTCCALICFG) {
            /* RTC slow-clock calibration: on START the hardware counts the
             * number of slow-clock cycles in a window of RTC_CALI_MAX periods
             * of a reference clock (XTAL/128). It latches the count into the
             * RTCCALI_VALUE field (bits[31:7]) of RTCCALICFG1 and sets
             * RTC_CALI_RDY. The firmware reads the value back as (RTCCALICFG1
             * >> 7). */
            r[o >> 2] = val;
            if (val & 0x80000000u) { /* TIMG_RTC_CALI_START */
                uint32_t clk_hz, max = (val >> 16) & 0x7FFFu;
                switch ((val >> 13) & 3u) { /* TIMG_RTC_CALI_CLK_SEL */
                case 0: clk_hz = 150000u; break;    /* RC_SLOW */
                case 1: clk_hz = 20000000u; break;  /* RC_FAST */
                default: clk_hz = 32768u; break;    /* XTAL32K/RC32K/OSC_SLOW */
                }
                /* count = max * slow_freq / (XTAL/128) */
                uint32_t count = (uint32_t) ((uint64_t) max * clk_hz
                                             * 128u / 40000000u);
                r[TIMG_RTCCALICFG1 >> 2] = count << 7;
                r[o >> 2] |= 0x8000u; /* TIMG_RTC_CALI_RDY */
            }
        } else if (o == TIMG_WDT_WPROTECT) {
            soc->wdt_unlock[0] = (val == TIMG_WDT_MAGIC);
            r[o >> 2] = val;
        } else if (o == TIMG_WDT_CONFIG0) {
            r[o >> 2] = val;
            if (!soc->wdt_unlock[0])
                ; /* writes are ignored while the WDT is write-protected */
            else if (val & TIMG_WDT_EN) {
                soc->wdt_en[0] = 1;
                soc->wdt_expire[0] = rv->csr_cycle + esp32h2_wdt_cycles(soc, 0);
            } else {
                soc->wdt_en[0] = 0;
                r[TIMG_INT_RAW >> 2] &= ~TIMG_INT_WDT;
                soc->intc_status &=
                    ~(((__uint128_t)1) << C6_TG0_WDT_INTR_SOURCE);
            }
        } else if (o == TIMG_WDT_CONFIG1 || o == TIMG_WDT_CONFIG2) {
            r[o >> 2] = val;
            if (soc->wdt_en[0])
                soc->wdt_expire[0] = rv->csr_cycle + esp32h2_wdt_cycles(soc, 0);
        } else if (o == TIMG_WDT_FEED) {
            if (soc->wdt_unlock[0]) {
                r[TIMG_INT_RAW >> 2] &= ~TIMG_INT_WDT;
                if (!(r[TIMG_INT_RAW >> 2] & r[TIMG_INT_ENA >> 2]))
                    soc->intc_status &=
                        ~(((__uint128_t)1) << C6_TG0_WDT_INTR_SOURCE);
                soc->wdt_expire[0] = rv->csr_cycle + esp32h2_wdt_cycles(soc, 0);
            }
            r[o >> 2] = val;
        } else {
            r[o >> 2] = val;
        }
        return;
    }
    if (addr >= C6_PERIPH_BASE + 0xA000u &&
        addr < C6_PERIPH_BASE + 0xA100u) {
        uint32_t o = addr - C6_PERIPH_BASE - 0xA000u;
        uint32_t *r = soc->timg_reg[1];
        if (o == TIMG_T0CONFIG) {
            soc->timg_anchor[1] = rv->csr_cycle;
            soc->timg_frac[1] = 0;
            r[o >> 2] = val & ~TIMG_T0_DIVCNT_RST;
        } else if (o == TIMG_T0LOAD) {
            soc->timg_counter[1] = ((uint64_t) r[TIMG_T0LOADHI >> 2] << 32) |
                                   r[TIMG_T0LOADLO >> 2];
            soc->timg_anchor[1] = rv->csr_cycle;
            soc->timg_frac[1] = 0;
            r[o >> 2] = 0;
        } else if (o == TIMG_T0UPDATE) {
            r[o >> 2] = 0;
        } else if (o == TIMG_INT_CLR) {
            r[TIMG_INT_RAW >> 2] &= ~val;
            if (!(r[TIMG_INT_RAW >> 2] & r[TIMG_INT_ENA >> 2]))
                soc->intc_status &= ~(((__uint128_t)1) << C6_TG1_T0_INTR_SOURCE);
            r[o >> 2] = 0;
        } else if (o == TIMG_RTCCALICFG) {
            r[o >> 2] = val;
            if (val & 0x80000000u) {
                uint32_t clk_hz, max = (val >> 16) & 0x7FFFu;
                switch ((val >> 13) & 3u) {
                case 0: clk_hz = 150000u; break;
                case 1: clk_hz = 20000000u; break;
                default: clk_hz = 32768u; break;
                }
                r[TIMG_RTCCALICFG1 >> 2] =
                    (uint32_t) ((uint64_t) max * 40000000u / clk_hz);
                r[o >> 2] |= 0x8000u;
            }
        } else if (o == TIMG_WDT_WPROTECT) {
            soc->wdt_unlock[1] = (val == TIMG_WDT_MAGIC);
            r[o >> 2] = val;
        } else if (o == TIMG_WDT_CONFIG0) {
            r[o >> 2] = val;
            if (!soc->wdt_unlock[1])
                ; /* writes are ignored while the WDT is write-protected */
            else if (val & TIMG_WDT_EN) {
                soc->wdt_en[1] = 1;
                soc->wdt_expire[1] = rv->csr_cycle + esp32h2_wdt_cycles(soc, 1);
            } else {
                soc->wdt_en[1] = 0;
                r[TIMG_INT_RAW >> 2] &= ~TIMG_INT_WDT;
                soc->intc_status &=
                    ~(((__uint128_t)1) << C6_TG1_WDT_INTR_SOURCE);
            }
        } else if (o == TIMG_WDT_CONFIG1 || o == TIMG_WDT_CONFIG2) {
            r[o >> 2] = val;
            if (soc->wdt_en[1])
                soc->wdt_expire[1] = rv->csr_cycle + esp32h2_wdt_cycles(soc, 1);
        } else if (o == TIMG_WDT_FEED) {
            if (soc->wdt_unlock[1]) {
                r[TIMG_INT_RAW >> 2] &= ~TIMG_INT_WDT;
                if (!(r[TIMG_INT_RAW >> 2] & r[TIMG_INT_ENA >> 2]))
                    soc->intc_status &=
                        ~(((__uint128_t)1) << C6_TG1_WDT_INTR_SOURCE);
                soc->wdt_expire[1] = rv->csr_cycle + esp32h2_wdt_cycles(soc, 1);
            }
            r[o >> 2] = val;
        } else {
            r[o >> 2] = val;
        }
        return;
    }

    /* TWAI0 (CAN, 0x6000C000-0x6000C100) */
    if (addr >= C6_PERIPH_BASE + 0xC000u &&
        addr < C6_PERIPH_BASE + 0xC100u) {
        uint32_t off = addr - C6_PERIPH_BASE - 0xC000u;
        uint32_t *r = soc->twai_reg + (off >> 2);
        if (off == 0x00u) { /* mode: leaving reset mode starts the bus */
            *r = val;
            if (!(val & 1u) && !soc->twai_rx_delivered)
                soc->twai_rx_deliver_cycle =
                    rv->csr_cycle + 150000; /* ~1.5ms @ 100MHz host clock */
        } else if (off == 0x04u) { /* cmd: commands are latched and self-clear */
            *r = val;
            if (val & TWAI0_CMD_TX_REQUEST) {
                soc->twai_tx_pending = 1;
                soc->twai_tx_done_cycle =
                    rv->csr_cycle + 20000; /* ~200us @ 100MHz host clock */
            }
            if (val & TWAI0_CMD_RELEASE_BUFFER) {
                soc->twai_reg[0x08 >> 2] &= ~TWAI0_STATUS_RBS;
                if (soc->twai_reg[0x74 >> 2])
                    soc->twai_reg[0x74 >> 2]--;
            }
            if (val & TWAI0_CMD_CLEAR_DOVERRUN)
                soc->twai_reg[0x08 >> 2] &= ~TWAI0_STATUS_DOS;
        } else {
            *r = val;
        }
        return;
    }

    /* GDMA (0x60080000-0x600802B0): IN + OUT channel control. in_intr[ch]
     * at 0x00 + 16*ch; out_intr[ch] at 0x30 + 16*ch. channel[ch] at
     * 0x70 + 0xC0*ch with the IN block at +0x00 and OUT block at +0x60.
     * IN_LINK.start (bit 22) / OUT_LINK.start (bit 21) arm the descriptor
     * walker; *_conf0.*_rst (bit 0) is write-only and resets FIFO+walker. */
    if (addr >= C6_PERIPH_BASE + 0x80000u &&
        addr < C6_PERIPH_BASE + 0x802B0u) {
        uint32_t o = addr - C6_PERIPH_BASE - 0x80000u;
        if (o < 0x30u) { /* in_intr[3]: 0x00..0x2F */
            uint32_t ch = o >> 4;
            switch (o & 0xFu) {
            case 0x08: /* ena */
                soc->gdma_in_int_ena[ch] = val;
                break;
            case 0x0C: /* clr: W1C */
                soc->gdma_in_int_raw[ch] &= ~val;
                break;
            default:
                return; /* raw/st: read-only */
            }
            if (!(soc->gdma_in_int_raw[ch] & soc->gdma_in_int_ena[ch])) {
                soc->intc_status &=
                    ~(((__uint128_t)1) << (C6_DMA_IN_CH0_INTR_SOURCE + ch));
            }
            return;
        }
        if (o >= 0x30u && o < 0x70u) { /* out_intr[3] */
            uint32_t ch = (o - 0x30u) >> 4;
            switch (o & 0xFu) {
            case 0x08: /* ena */
                soc->gdma_out_int_ena[ch] = val;
                break;
            case 0x0C: /* clr: W1C */
                soc->gdma_out_int_raw[ch] &= ~val;
                break;
            default:
                return; /* raw/st: read-only */
            }
            dbg_gdma_intrwr++;
            if (!(soc->gdma_out_int_raw[ch] & soc->gdma_out_int_ena[ch])) {
                dbg_gdma_intrwr_clear++;
                soc->intc_status &=
                    ~(((__uint128_t)1) << (C6_DMA_OUT_CH0_INTR_SOURCE + ch));
            }
            return;
        }
        if (o >= 0x70u && o < 0x2B0u) {
            uint32_t c = (o - 0x70u) / 0xC0u;
            uint32_t r = o - 0x70u - c * 0xC0u;
            if (r < 0x60u) { /* IN block */
                switch (r) {
                case 0x00: /* in_conf0 */
                    soc->gdma_in_conf0[c] = val & ~1u; /* in_rst is WT */
                    if (val & 1u) { /* reset the FIFO and the walker */
                        soc->gdma_rx_fifo_cnt[c] = 0;
                        soc->gdma_rx_fifo_head[c] = 0;
                        soc->gdma_rx_run[c] = 0;
                        soc->gdma_rx_desc_left[c] = 0;
                        soc->gdma_in_dscr[c] = 0;
                    }
                    return;
                case 0x04: /* in_conf1 */
                    soc->gdma_in_conf1[c] = val;
                    return;
                case 0x10: /* in_link */
                    soc->gdma_in_link[c] =
                        val & ~0xF00000u; /* start/stop/restart/park WT */
                    if (val & (1u << 22)) { /* start */
                        soc->gdma_rx_desc_addr[c] = C6_SRAM_BASE +
                            (soc->gdma_in_link[c] & 0xFFFFFu);
                        soc->gdma_rx_sample[c] = 0;
                        esp32h2_gdma_load_rx_desc(soc, c);
                        soc->gdma_rx_run[c] = 1;
                        soc->gdma_rx_fill_cyc[c] = rv->csr_cycle + 256u;
                    } else if (val & (1u << 21)) { /* stop */
                        soc->gdma_rx_run[c] = 0;
                    } else if (val & (1u << 23)) { /* restart */
                        soc->gdma_rx_run[c] = 1;
                        soc->gdma_rx_fill_cyc[c] = rv->csr_cycle + 256u;
                    }
                    return;
                case 0x2C: /* in_pri */
                    soc->gdma_in_pri[c] = val;
                    return;
                case 0x30: /* in_peri_sel */
                    soc->gdma_in_peri_sel[c] = val;
                    return;
                default:
                    return; /* stored nowhere (never read back) */
                }
            }
            switch (r) { /* OUT block */
            case 0x60: /* out_conf0 */
                soc->gdma_out_conf0[c] = val & ~1u; /* out_rst is WT */
                if (val & 1u) { /* reset the FIFO and the walker */
                    soc->gdma_tx_fifo_cnt[c] = 0;
                    soc->gdma_tx_run[c] = 0;
                    soc->gdma_tx_desc_left[c] = 0;
                    soc->gdma_out_dscr[c] = 0;
                }
                return;
            case 0x64: /* out_conf1 */
                soc->gdma_out_conf1[c] = val;
                return;
            case 0x70: /* out_link */
                soc->gdma_out_link[c] =
                    val & ~0x700000u; /* start/stop/restart are WT */
                if (val & (1u << 21)) { /* start */
                    soc->gdma_tx_desc_addr[c] = C6_SRAM_BASE +
                        (soc->gdma_out_link[c] & 0xFFFFFu);
                    esp32h2_gdma_load_desc(soc, c);
                    soc->gdma_tx_run[c] = 1;
                    soc->gdma_tx_drain_cyc[c] = rv->csr_cycle + 256u;
                } else if (val & (1u << 20)) { /* stop */
                    soc->gdma_tx_run[c] = 0;
                } else if (val & (1u << 22)) { /* restart */
                    soc->gdma_tx_run[c] = 1;
                    soc->gdma_tx_drain_cyc[c] = rv->csr_cycle + 256u;
                }
                return;
            case 0x8C: /* out_pri */
                soc->gdma_out_pri[c] = val;
                return;
            case 0x90: /* out_peri_sel */
                soc->gdma_out_peri_sel[c] = val;
                return;
            default:
                return; /* the rest is stored nowhere (never read back) */
            }
        }
        return;
    }

    /* I2S (0x6000D000-0x6000D100): TX_CONF/RX_CONF self-clearing bits. The
     * reset bits (0,1) are write-only and *_update (8) clears itself once
     * the configuration has been applied (the driver polls it). rx_start /
     * tx_start (bit 2) are kept set so the engine knows the stream runs. */
    if (addr >= C6_PERIPH_BASE + 0xD000u &&
        addr < C6_PERIPH_BASE + 0xD100u) {
        uint32_t o = addr - C6_PERIPH_BASE - 0xD000u;
        if (o == 0x24u) {
            mmio32[off >> 2] = val & ~0x103u;
        } else if (o == 0x20u) { /* RX_CONF */
            mmio32[off >> 2] = val & ~0x103u;
        } else if (o == 0x18u) { /* INT_CLR: W1C */
            mmio32[(0xD00Cu) >> 2] &= ~val;
        } else {
            mmio32[off >> 2] = val;
        }
        return;
    }

    /* SARADC (0x6000E000-0x6000E404) */
    if (addr >= C6_PERIPH_BASE + 0xE000u &&
        addr < C6_PERIPH_BASE + 0xE404u) {
        uint32_t o = off - 0xE000u;
        if (o == 0x4Cu) { /* int_clr: write-to-clear */
            soc->adc_reg[0x44 >> 2] &= ~val;
        } else {
            soc->adc_reg[o >> 2] = val;
            if (o == 0x20u && (val & (1u << 29))) {
                /* onetime start: the conversion completes instantly. The
                 * selected converter (bit31=ADC1, bit30=ADC2) produces a
                 * done event; pin channels 0-7 read 1024 + ch*128, the
                 * internal-reference channels read mid-scale. */
                uint32_t ch = (val >> 25) & 0xFu;
                if (val & (1u << 31)) { /* sar1 sample */
                    soc->adc_reg[0x2c >> 2] =
                        (ch < 8) ? 1024u + ch * 128u : 2048u;
                    soc->adc_reg[0x44 >> 2] |= 1u << 31; /* ADC1 done */
                }
                if (val & (1u << 30)) { /* sar2 sample */
                    soc->adc_reg[0x30 >> 2] =
                        (ch < 8) ? 1024u + ch * 128u : 2048u;
                    soc->adc_reg[0x44 >> 2] |= 1u << 30; /* ADC2 done */
                }
            }
        }
        return;
    }

    /* PCNT (0x60012000-0x60012100) */
    if (addr >= C6_PERIPH_BASE + 0x12000u &&
        addr < C6_PERIPH_BASE + 0x12100u) {
        uint32_t o = off - 0x12000u;
        if (o == 0x4cu) { /* int_clr: W1C */
            soc->pcnt_reg[0x40 >> 2] &= ~val;
            if (!(soc->pcnt_reg[0x40 >> 2] & soc->pcnt_reg[0x48 >> 2]))
                soc->intc_status &= ~(((__uint128_t)1) << C6_PCNT_INTR_SOURCE);
            return;
        }
        if (o == 0x60u) { /* ctrl: pulse_cnt_rst_uN clears the counter */
            for (int u = 0; u < 4; u++)
                if (val & (1u << (2 * u)))
                    soc->pcnt_reg[(0x30u + 4u * u) >> 2] = 0;
            soc->pcnt_reg[o >> 2] = val;
            return;
        }
        soc->pcnt_reg[o >> 2] = val;
        return;
    }

    /* MCPWM (0x60014000-0x60014130) */
    if (addr >= C6_PERIPH_BASE + 0x14000u &&
        addr < C6_PERIPH_BASE + 0x14130u) {
        uint32_t o = off - 0x14000u;
        if (o == 0x1A0u) { /* int_clr: W1C */
            soc->mcpwm_reg[0x198u >> 2] &= ~val;
            if (!(soc->mcpwm_reg[0x198u >> 2] & soc->mcpwm_reg[0x194u >> 2]))
                soc->intc_status &= ~(((__uint128_t)1) << C6_MCPWM_INTR_SOURCE);
            return;
        }
        if ((o & 0xFu) == 0x08u && o <= 0x28u) { /* timer_cfg1 */
            int t = o >> 4;
            uint32_t cmd = val & 0x7u;
            /* start/stop field is self-clearing on write */
            soc->mcpwm_reg[o >> 2] = val & ~0x7u;
            if (cmd <= 1u) { /* STOP_EMPTY / STOP_FULL */
                soc->mcpwm_running[t] = 0;
                soc->mcpwm_stopat[t] = 0;
            } else if (cmd <= 4u) { /* START_NO_STOP / _STOP_EMPTY / _STOP_FULL */
                soc->mcpwm_running[t] = 1;
                soc->mcpwm_stopat[t] = (cmd == 3u) ? 1 : (cmd == 4u) ? 2 : 0;
                /* start the counter cleanly from the configured phase */
                soc->mcpwm_anchor[t] = rv->csr_cycle;
                soc->mcpwm_frac[t] = 0;
                soc->mcpwm_phase[t] = 0;
            }
            return;
        }
        /* timer_status registers (0x10/0x20/0x30) are read-only */
        if ((o & 0xFu) == 0x0u && o >= 0x10u && o <= 0x30u)
            return;
        soc->mcpwm_reg[o >> 2] = val;
        return;
    }

    /* UART0/1/2 (0x60000000 / 0x60010000 / 0x60020000) */
    for (int p = 0; p < 2; p++) {
        uint32_t base = C6_PERIPH_BASE + 0x1000u * p;
        if (addr >= base && addr < base + 0x1000u) {
            uint32_t o = addr - base;
            if (o == UART_FIFO_REG) {
                uint8_t b = (uint8_t) (val & 0xFFu);
                if (p == 0)
                    esp32_uart_putc(soc, (char) b);
                /* model the byte leaving the TX FIFO (instant transmit) */
                if (soc->uart_tx_cnt[p] < UART_RX_FIFO_SZ)
                    soc->uart_tx_cnt[p]++;
                soc->uart_tx_idle[p] = 0;
                /* TX->RX loopback (CONF0 bit 12) feeds this port's RX FIFO */
                if (mmio32[(base + UART_CONF0_REG - C6_PERIPH_BASE) >> 2] &
                    UART_LOOPBACK_BIT) {
                    unsigned cnt = (soc->uart_rx_head[p] -
                                    soc->uart_rx_tail[p]) &
                                   (UART_RX_FIFO_SZ - 1u);
                    if (cnt < UART_RX_FIFO_SZ - 1u) {
                        soc->uart_rx[p][soc->uart_rx_head[p]] = b;
                        soc->uart_rx_head[p] =
                            (soc->uart_rx_head[p] + 1) &
                            (UART_RX_FIFO_SZ - 1u);
                        /* raise the RX interrupt so the driver ISR drains
                         * the FIFO (esp-idf uart_read_bytes needs it) */
                        uint32_t *raw =
                            &mmio32[(base + UART_INT_RAW_REG -
                                     C6_PERIPH_BASE) >> 2];
                        uint32_t *ena =
                            &mmio32[(base + UART_INT_ENA_REG -
                                     C6_PERIPH_BASE) >> 2];
                        if (!(*raw & (UART_RXFIFO_TOUT_BIT | 0x1u))) {
                            *raw |= (UART_RXFIFO_TOUT_BIT | 0x1u);
                            if (*ena & (UART_RXFIFO_TOUT_BIT | 0x1u)) {
                                int src = (p == 0) ? C6_UART0_INTR_SOURCE
                                                   : C6_UART1_INTR_SOURCE;
                                soc->intc_status |=
                                    ((__uint128_t)1) << src;
                            }
                        }
                    }
                }
            } else if (o == UART_INT_CLR_REG) { /* W1C */
                uint32_t *raw =
                    &mmio32[(base + UART_INT_RAW_REG - C6_PERIPH_BASE) >> 2];
                *raw &= ~val;
                if (!(*raw & (UART_RXFIFO_TOUT_BIT | 0x1u |
                              UART_TXFIFO_EMPTY_BIT))) {
                    int src = (p == 0) ? C6_UART0_INTR_SOURCE
                                       : C6_UART1_INTR_SOURCE;
                    soc->intc_status &= ~(((__uint128_t)1) << src);
                }
            } else if (o == UART_INT_ENA_REG) {
                /* The esp-idf uart TX driver drains its software ring buffer
                 * into the HW FIFO from inside the TXFIFO_EMPTY (and TX_DONE)
                 * ISR. The H2 Arduino core does not always arm these bits in
                 * INT_ENA, so the model forces them on: this both lets the
                 * periodic TXFIFO_EMPTY logic raise the interrupt and lets the
                 * SDK's ISR see it and move bytes to the FIFO. */
                mmio32[off >> 2] = val | UART_TXFIFO_EMPTY_BIT | 0x4000u;
            } else
                mmio32[off >> 2] = val;
            return;
        }
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
        case GPIO_STATUS_W1TS_REG:
            soc->gpio_status |= val;
            soc->intc_status |= ((__uint128_t)1) << C6_GPIO_INTR_SOURCE;
            return;
        case GPIO_STATUS_W1TC_REG:
            soc->gpio_status &= ~val;
            if (!soc->gpio_status)
                soc->intc_status &= ~(((__uint128_t)1) << C6_GPIO_INTR_SOURCE);
            return;
        default:
            mmio32[off >> 2] = val;
            return;
        }
        /* a firmware GPIO write may toggle an output pin; its own pad input
         * tracks the output, so detect edges on the live input here. */
        esp32h2_gpio_edge_check(soc, mmio32,
            soc->gpio_in | esp32h2_gpio_eff_out(soc, mmio32));
        if (esp32h2_gpio_output) {
            for (int pin = 0; pin < 30; pin++) {
                if (soc->gpio_enable & (1u << pin))
                    esp32h2_gpio_output(pin, !!(soc->gpio_out & (1u << pin)));
            }
        }
        return;
    }
    /* interrupt matrix (0x60010000 + 4*source, 72 sources incl. the DMA
     * channels at 0x108-0x11C) */
    if (addr >= C6_PERIPH_BASE + 0x10000u &&
        addr < C6_PERIPH_BASE + 0x10000u + 96 * 4u) {
        uint32_t s = (addr - C6_PERIPH_BASE - 0x10000u) >> 2;
        soc->intc_intmap[s] = val & 0x1Fu;
        return;
    }
    /* SYSTIMER (0x6000B000) */
    if (addr >= C6_PERIPH_BASE + 0xB000u &&
        addr < C6_PERIPH_BASE + 0xC000u) {
        switch (off - 0xB000u) {
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
            soc->intc_status &= ~((((__uint128_t)1) << SYSTIMER_T0_SOURCE) |
                                  (((__uint128_t)1) << SYSTIMER_T2_SOURCE));
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
    /* TIMG0 RTCCALICFG (0x60009068): one-off slow-clock calibration.
     * On START the hardware counts XTAL (40 MHz) cycles over RTC_CALI_MAX
     * cycles of the selected calibration clock, then sets RTC_CALI_RDY and
     * latches the count into RTCCALICFG1 (0x6000906C). */
    if (addr == C6_PERIPH_BASE + 0x9068u) {
        mmio32[off >> 2] = val;
        if (val & 0x80000000u) { /* TIMG_RTC_CALI_START */
            uint32_t clk_hz, max = (val >> 16) & 0x7FFFu;
            switch ((val >> 13) & 3u) { /* TIMG_RTC_CALI_CLK_SEL */
            case 0: clk_hz = 150000u; break;    /* RC_SLOW */
            case 1: clk_hz = 20000000u; break;  /* RC_FAST */
            default: clk_hz = 32768u; break;    /* XTAL32K / RC32K / OSC_SLOW */
            }
            mmio32[(0x906Cu) >> 2] =
                (uint32_t) ((uint64_t) max * 40000000u / clk_hz);
            mmio32[off >> 2] |= 0x8000u; /* TIMG_RTC_CALI_RDY */
        }
        return;
    }
    /* Crosscore interrupt flag (0x600C5090 = INTPRI_CPU_INTR_FROM_CPU_0_REG):
     * writing 1 raises INTC source 7 (ETS_FROM_CPU_INTR0_SOURCE, the FreeRTOS
     * yield line on H2), writing 0 clears it. The FreeRTOS port's yield
     * (esp_crosscore_int_send / vPortYield / esp_crosscore_isr) depends on
     * this. (C6 numbers this source 22; H2 numbers it 7.) */
    if (addr == C6_PERIPH_BASE + 0xC5090u) {
        mmio32[off >> 2] = val & 1u;
        if (val & 1u)
            soc->intc_status |= ((__uint128_t)1) << 7u;
        else
            soc->intc_status &= ~(((__uint128_t)1) << 7u);
        return;
    }
    mmio32[off >> 2] = val;
}

/* ------------------------------------------------------------------ */
/* Memory accessors (io callbacks)                                     */
/* ------------------------------------------------------------------ */

static inline esp32_region_t *esp32_lookup(riscv_t *rv, uint32_t addr)
{
    return esp32_find_region(PRIV(rv)->esp32h2, addr);
}

/* Flash cache window translation: the 0x42000000 window (16 MB) maps
 * through the MMU with 2^(16-mode) byte pages, programmed via
 * SPI_MEM_MMU_ITEM_INDEX/CONTENT. Returns the flash buffer offset, or
 * ~0u for non-window addresses. */
static inline uint32_t esp32_flash_window_off(esp32h2_t *soc, uint32_t addr)
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

uint32_t esp32h2_read_w(riscv_t *rv, uint32_t addr)
{
    esp32_region_t *r = esp32_lookup(rv, addr);
    if (!r || r->type != ESP32_REG_RAM)
        return esp32_mmio_read(rv, PRIV(rv)->esp32h2, addr);
    uint32_t val;
    uint32_t off = esp32_flash_window_off(PRIV(rv)->esp32h2, addr);
    if (off == ~0u)
        off = addr - r->base;
    memcpy(&val, r->data + off, 4);
    return val;
}

uint16_t esp32h2_read_s(riscv_t *rv, uint32_t addr)
{
    esp32_region_t *r = esp32_lookup(rv, addr);
    if (!r || r->type != ESP32_REG_RAM)
        return (uint16_t) esp32_mmio_read(rv, PRIV(rv)->esp32h2, addr);
    uint16_t val;
    uint32_t off = esp32_flash_window_off(PRIV(rv)->esp32h2, addr);
    if (off == ~0u)
        off = addr - r->base;
    memcpy(&val, r->data + off, 2);
    return val;
}

uint8_t esp32h2_read_b(riscv_t *rv, uint32_t addr)
{
    esp32_region_t *r = esp32_lookup(rv, addr);
    if (!r || r->type != ESP32_REG_RAM)
        return (uint8_t) esp32_mmio_read(rv, PRIV(rv)->esp32h2, addr);
    uint32_t off = esp32_flash_window_off(PRIV(rv)->esp32h2, addr);
    if (off == ~0u)
        off = addr - r->base;
    return r->data[off];
}

void esp32h2_write_w(riscv_t *rv, uint32_t addr, uint32_t val)
{
    esp32_region_t *r = esp32_lookup(rv, addr);
    if (!r || r->type != ESP32_REG_RAM) {
        esp32_mmio_write(rv, addr, val);
        return;
    }
    memcpy(r->data + (addr - r->base), &val, 4);
}

void esp32h2_write_s(riscv_t *rv, uint32_t addr, uint16_t val)
{
    esp32_region_t *r = esp32_lookup(rv, addr);
    if (!r || r->type != ESP32_REG_RAM) {
        esp32_mmio_write(rv, addr, val);
        return;
    }
    memcpy(r->data + (addr - r->base), &val, 2);
}

void esp32h2_write_b(riscv_t *rv, uint32_t addr, uint8_t val)
{
    esp32_region_t *r = esp32_lookup(rv, addr);
    if (!r || r->type != ESP32_REG_RAM) {
        esp32_mmio_write(rv, addr, val);
        return;
    }
    /* UART0/1 TX FIFO byte stores (sb) must be echoed just like word
     * stores; otherwise per-byte SDK writes never reach esp32_uart_putc. */
    for (int p = 0; p < 2; p++) {
        uint32_t base = C6_PERIPH_BASE + 0x1000u * p;
        if (addr == base + UART_FIFO_REG) {
            esp32_uart_putc(PRIV(rv)->esp32h2, (char) val);
            return;
        }
    }
    r->data[addr - r->base] = val;
}

uint32_t esp32h2_ifetch(riscv_t *rv, uint32_t addr)
{
    esp32_region_t *r = esp32_lookup(rv, addr);
    if (!r || r->type != ESP32_REG_RAM) {
        /* code fetch outside RAM: decode as 0 (illegal) and log once */
        fprintf(stderr,
                "esp32h2: ifetch at non-RAM 0x%08x (guest pc=0x%08x, r=%p)\n",
                addr, rv->PC, (void *) r);
        return 0;
    }
    uint32_t val;
    uint32_t off = esp32_flash_window_off(PRIV(rv)->esp32h2, addr);
    if (off == ~0u)
        off = addr - r->base;
    memcpy(&val, r->data + off, 4);
    return val;
}

static uint32_t esp32h2_translate(riscv_t *rv, uint32_t vaddr, bool rw)
{
    (void) rv;
    (void) rw;
    return vaddr; /* bare metal: identity */
}

void esp32h2_install_io(riscv_t *rv)
{
    riscv_io_t io = {
        .mem_ifetch = esp32h2_ifetch,
        .mem_read_w = esp32h2_read_w,
        .mem_read_s = esp32h2_read_s,
        .mem_read_b = esp32h2_read_b,
        .mem_write_w = esp32h2_write_w,
        .mem_write_s = esp32h2_write_s,
        .mem_write_b = esp32h2_write_b,
        .mem_translate = esp32h2_translate,
        .mmu_read_w = esp32h2_read_w,
        .mmu_read_s = esp32h2_read_s,
        .mmu_read_b = esp32h2_read_b,
        .mmu_write_w = esp32h2_write_w,
        .mmu_write_s = esp32h2_write_s,
        .mmu_write_b = esp32h2_write_b,
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

uint32_t esp32h2_boot(esp32h2_t *soc, const char *elf_path)
{
    /* Full flash-image boot (ROM reset vector -> bootloader -> app) */
    if (esp32h2_flash_image_path) {
        FILE *f = fopen(esp32h2_flash_image_path, "rb");
        if (!f) {
            fprintf(stderr, "esp32h2: cannot open flash image %s\n",
                    esp32h2_flash_image_path);
            exit(EXIT_FAILURE);
        }
        esp32_region_t *fd = esp32_find_region(soc, C6_FLASH_I_BASE);
        size_t got = fread(fd->data, 1, C6_FLASH_SIZE, f);
        fclose(f);
        fprintf(stderr, "esp32h2: loaded %zu bytes of flash image\n", got);
        /* boot from the ROM reset vector: ROM code initializes the system
         * (timer structs, SYSTIMER, UART, clocks) then loads the 2nd-stage
         * bootloader from flash offset 0 and jumps to the app. */
        return C6_ROM_BASE;
    }

    FILE *f = fopen(elf_path, "rb");
    if (!f) {
        fprintf(stderr, "esp32h2: cannot open %s\n", elf_path);
        exit(EXIT_FAILURE);
    }
    esp32_elf32_hdr_t hdr;
    if (fread(&hdr, 1, sizeof(hdr), f) != sizeof(hdr) ||
        memcmp(hdr.e_ident, "\x7f" "ELF", 4) != 0) {
        fprintf(stderr, "esp32h2: %s is not an ELF32 file\n", elf_path);
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
                        "esp32h2: ELF segment at 0x%08x outside RAM\n",
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
                    fprintf(stderr, "esp32h2: ELF segment read failed\n");
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
static uint32_t esp32_intc_raise(esp32h2_t *soc)
{
    uint32_t lines = 0;
    for (int s = 0; s < 96; s++) {
        if (!(soc->intc_status & (((__uint128_t)1) << s)))
            continue;
        int line = soc->intc_intmap[s] & 0x1Fu;
        if (line >= 1 && line < 32)
            lines |= 1u << line;
    }
    /* CLINT: MSIP (line 3) and MTIMECMP (line 7) */
    if (soc->clint_msip)
        lines |= 1u << 3;
    if (soc->clint_mtimcmp && soc->clint_mtime >= soc->clint_mtimcmp)
        lines |= 1u << 7;
    return lines;
}

void esp32h2_check_interrupt(riscv_t *rv)
{
    esp32h2_t *soc = PRIV(rv)->esp32h2;
    if (!soc)
        return;
    if (!(rv->csr_mstatus & MSTATUS_MIE))
        return;
    uint32_t lines = esp32_intc_raise(soc);
    rv->csr_mip = (rv->csr_mip & ~0x0FFFFFFEu) | lines;
    /* the C6 app enables per-line mie bits via esprv_intc_int_enable */
    uint32_t pending = lines & rv->csr_mie;
    /* dbg_trap_deliv is a global counter declared at the top of the file */
    if ((soc->intc_status >> 69) & 1ull)
        dbg_69_at_check++;
    if (pending) {
        dbg_trap_deliv++;
    }
    if (!pending) {
        return;
    }
    /* lowest set bit = CPU interrupt number */
    int idx = __builtin_ctz(pending);
    /* The crosscore/yield source (INTC source 7) is edge-triggered and has
     * no explicit clear write from the SDK; clear its pending flag once the
     * interrupt is delivered so the SDK's busy-wait on
     * INTPRI_CPU_INTR_FROM_CPU_0_REG (0x600C5090) reads back as cleared. */
    if (pending & (1u << 5))
        soc->intc_status &= ~(((__uint128_t)1) << 7u);
    SET_CAUSE_AND_TVAL_THEN_TRAP(rv, ((1u << 31) | idx), 0);
}

/* Drain host-injected UART RX bytes (FIFO file) into the guest RX FIFO. */
static void esp32h2_uart_rx_poll(esp32h2_t *soc)
{
    if (!esp32h2_uart_rx_path)
        return;
    if (soc->uart_rx_fd < 0) {
        soc->uart_rx_fd =
            open(esp32h2_uart_rx_path, O_RDONLY | O_NONBLOCK);
        if (soc->uart_rx_fd < 0) {
            if (errno != ENOENT && errno != EACCES)
                fprintf(stderr, "esp32h2: uart rx open %s: %s\n",
                        esp32h2_uart_rx_path, strerror(errno));
            return;
        }
    }
    for (;;) {
        unsigned int count = (soc->uart_rx_head[0] - soc->uart_rx_tail[0]) &
                             (UART_RX_FIFO_SZ - 1u);
        unsigned int free_slots = UART_RX_FIFO_SZ - 1u - count;
        unsigned int head = soc->uart_rx_head[0] % UART_RX_FIFO_SZ;
        unsigned int chunk = UART_RX_FIFO_SZ - head;
        if (chunk > free_slots)
            chunk = free_slots;
        ssize_t n = read(soc->uart_rx_fd, soc->uart_rx[0] + head, chunk);
        if (n <= 0)
            break; /* EAGAIN/EOF: nothing more right now */
        soc->uart_rx_head[0] =
            (soc->uart_rx_head[0] + n) % UART_RX_FIFO_SZ;
    }
}

/* Apply the MCPWM generator events that coincide with the timer reaching
 * `phase`: for each operator connected to timer t, the compare values and
 * the action fields of both generators decide the new output levels.
 * Event codes: 0 utez, 1 utep, 2 ucmp0, 3 ucmp1, 4 dtep, 5 dtez,
 * 6 dcmp1, 7 dcmp0; action fields are 2 bits, up events in [0:8),
 * down events in [12:20). */
static void esp32h2_mcpwm_fire(esp32h2_t *soc, int t, int dir,
                               uint32_t phase, uint32_t period)
{
    for (int op = 0; op < 3; op++) {
        uint32_t os = soc->mcpwm_reg[0x38u >> 2];
        if (((os >> (2 * op)) & 0x3u) != (uint32_t) t)
            continue;
        uint32_t gb = 0x3cu + 0x38u * op;
        uint32_t c0 = soc->mcpwm_reg[(gb + 0x04u) >> 2] & 0xFFFFu;
        uint32_t c1 = soc->mcpwm_reg[(gb + 0x08u) >> 2] & 0xFFFFu;
        int ev;
        if (dir == 0) {
            if (phase == 0) ev = 0;
            else if (phase == period) ev = 1;
            else if (phase == c0) ev = 2;
            else if (phase == c1) ev = 3;
            else continue;
        } else {
            if (phase == period) ev = 4;
            else if (phase == 0) ev = 5;
            else if (phase == c1) ev = 6;
            else if (phase == c0) ev = 7;
            else continue;
        }
        for (int g = 0; g < 2; g++) {
            uint32_t gr = soc->mcpwm_reg[(gb + 0x14u + 4u * g) >> 2];
            static const uint8_t ev_shift[8] = { 0, 2, 4, 6, 14, 12, 18, 16 };
            uint32_t act = (gr >> ev_shift[ev]) & 0x3u;
            if (act == 1u)
                soc->mcpwm_level[op][g] = 0;
            else if (act == 2u)
                soc->mcpwm_level[op][g] = 1;
            else if (act == 3u)
                soc->mcpwm_level[op][g] ^= 1;
        }
        /* one-shot (non-continue) force is consumed by the next event */
        uint32_t *gf = &soc->mcpwm_reg[(gb + 0x10u) >> 2];
        if ((*gf >> 10) & 1u) {
            *gf &= ~(1u << 10);
            *gf &= ~(0x3u << 11);
        }
        if ((*gf >> 13) & 1u) {
            *gf &= ~(1u << 13);
            *gf &= ~(0x3u << 14);
        }
    }
}

/* Detect edges on the live GPIO input (host-injected gpio_in ORed with the
 * output levels of enabled output pins) and raise the GPIO interrupt
 * (INTMTX source 30) for pins whose PIN register interrupt type/enable match.
 * Called whenever the live input may have changed (firmware GPIO writes and
 * the periodic virtual-button/pulse injection). */
static void esp32h2_gpio_edge_check(esp32h2_t *soc, uint32_t *mmio32,
                                    uint32_t new_live)
{
    uint32_t changed = new_live ^ soc->gpio_in_prev;
    if (!changed)
        return;
    for (int pin = 0; pin < 31; pin++) {
        if (!(changed & (1u << pin)))
            continue;
        uint32_t pr = mmio32[(0x91074u + 4u * pin) >> 2];
        int type = (pr >> 7) & 0x7u;
        int ena = (pr >> 13) & 0x1Fu;
        int level = (new_live >> pin) & 1;
        int prev = (soc->gpio_in_prev >> pin) & 1;
        int fire = 0;
        switch (type) {
        case 1: fire = level && !prev; break; /* posedge */
        case 2: fire = !level && prev; break; /* negedge */
        case 3: fire = level != prev; break;  /* any edge */
        case 4: fire = !level; break;         /* low level */
        case 5: fire = level; break;          /* high level */
        default: break;
        }
        if (fire && ena) {
            soc->gpio_status |= 1u << pin;
            soc->intc_status |= ((__uint128_t)1) << C6_GPIO_INTR_SOURCE;
        }
        /* PCNT: any edge on a pin that the GPIO matrix routes to a PCNT
         * unit/channel is counted here. Matrix input select for signal s
         * lives at 0x60091000 + 0x154 + 4*s; its low 6 bits are the source
         * GPIO. ESP32-C6 PCNT signal indices are unit u channel ch ->
         * 101 + 4*ch + u (CH0_IN0=101, CH0_IN1=105, CH1_IN0=102, ...). */
        if (level != prev) {
            for (int u = 0; u < 4; u++) {
                if (soc->pcnt_reg[0x60 >> 2] & (1u << (2 * u + 1)))
                    continue; /* counter paused */
                uint32_t conf0 = soc->pcnt_reg[(0x0c * u) >> 2];
                uint32_t conf1 = soc->pcnt_reg[(0x04 + 0x0c * u) >> 2];
                uint32_t conf2 = soc->pcnt_reg[(0x08 + 0x0c * u) >> 2];
                for (int ch = 0; ch < 2; ch++) {
                    uint32_t sig = 101u + 4u * ch + u;
                    uint32_t insel =
                        mmio32[(0x91000u + 0x154u + 4u * sig) >> 2];
                    if ((insel & 0x3Fu) != (uint32_t) pin)
                        continue;
                    int act = level
                        ? (ch ? (conf0 >> 26) & 0x3u : (conf0 >> 18) & 0x3u)
                        : (ch ? (conf0 >> 24) & 0x3u : (conf0 >> 16) & 0x3u);
                    int16_t cnt = (int16_t) soc->pcnt_reg[(0x30u + 4u * u) >> 2];
                    if (act == 1u)
                        cnt++;
                    else if (act == 2u)
                        cnt--;
                    soc->pcnt_reg[(0x30u + 4u * u) >> 2] = (uint16_t) cnt;
                    uint32_t status = 0;
                    if ((conf0 >> 15) & 1u && /* thr_thres1_en */
                        cnt == (int16_t) (conf1 >> 16))
                        status |= 1u << 2;
                    if ((conf0 >> 14) & 1u && /* thr_thres0_en */
                        cnt == (int16_t) (conf1 & 0xFFFFu))
                        status |= 1u << 3;
                    if ((conf0 >> 13) & 1u && /* thr_l_lim_en */
                        cnt == (int16_t) (conf2 >> 16))
                        status |= 1u << 4;
                    if ((conf0 >> 12) & 1u && /* thr_h_lim_en */
                        cnt == (int16_t) (conf2 & 0xFFFFu))
                        status |= 1u << 5;
                    if ((conf0 >> 11) & 1u && cnt == 0) /* thr_zero_en */
                        status |= 1u << 6;
                    soc->pcnt_reg[(0x50 + 4 * u) >> 2] = status;
                    if (status) {
                        soc->pcnt_reg[0x40 >> 2] |= 1u << u;
                        if (soc->pcnt_reg[0x40 >> 2] &
                            soc->pcnt_reg[0x48 >> 2])
                            soc->intc_status |= ((__uint128_t)1) << C6_PCNT_INTR_SOURCE;
                    }
                }
            }
        }
    }
    soc->gpio_in_prev = new_live;
}

void esp32h2_periodic(riscv_t *rv)
{
    esp32h2_t *soc = PRIV(rv)->esp32h2;
    if (!soc)
        return;
    uint32_t *mmio32 = (uint32_t *) soc->mmio;
    /* Virtual button: input pin 7 toggles every ~2^18 cycles. The change
     * is fed into the pad state, and pins with a matching interrupt type
     * raise the GPIO interrupt (INTMTX source 30). */
    {
        uint32_t phase = (rv->csr_cycle >> 18) & 1u;
        if (phase != soc->gpio_vbtn) {
            soc->gpio_vbtn = phase;
            uint32_t mask = 1u << 7;
            uint32_t changed = (soc->gpio_in ^ ((phase ? mask : 0))) & mask;
            if (changed) {
                uint32_t new_levels =
                    (soc->gpio_in & ~mask) | (phase ? mask : 0);
                soc->gpio_in = new_levels;
                esp32h2_gpio_edge_check(soc, mmio32,
                    new_levels | (soc->gpio_out & soc->gpio_enable));
            }
        }
        /* level-triggered pins: re-assert while the level matches */
        for (int pin = 0; pin < 31; pin++) {
            uint32_t pr = mmio32[(0x91074u + 4u * pin) >> 2];
            int type = (pr >> 7) & 0x7u;
            int ena = (pr >> 13) & 0x1Fu;
            int level = (soc->gpio_in >> pin) & 1;
            if (ena && ((type == 4 && !level) || (type == 5 && level))) {
                soc->gpio_status |= 1u << pin;
                soc->intc_status |= ((__uint128_t)1) << C6_GPIO_INTR_SOURCE;
            }
        }
    }

    /* Virtual pulse source: input pin 6 goes high for 2^17 cycles then low
     * for the rest of a 3*2^20-cycle period (a ~1.3ms pulse every ~30ms at
     * 40 MHz). The RMT RX test measures the pulse; the long low gap lets
     * the RX channel idle out (RX_END) between pulses. */
    {
        uint32_t level = ((rv->csr_cycle % (3u << 20)) < (1u << 17)) ? 1u : 0u;
        uint32_t cur = (soc->gpio_in >> 6) & 1u;
        if (level != cur) {
            if (level)
                soc->gpio_in |= 1u << 6;
            else
                soc->gpio_in &= ~(1u << 6);
        }
    }

    /* I2C transfer completion: a trans_start was issued. Without a slave
     * the address byte is never ACKed -> NACK + trans-complete, which the
     * ISR maps to I2C_INTR_EVENT_NACK (I2C_EXT0 = INTMTX source 50). With
     * the virtual device (0x50) the transfer is ACKed: writes are stored
     * into its memory, reads return the memory contents via the RX fifo. */
    if (soc->i2c_transfer_pending) {
        soc->i2c_transfer_pending = 0;
        if (soc->i2c_slave_active) {
            uint8_t *t = soc->i2c_tx_fifo;
            int tl = soc->i2c_tx_len;
            /* Combined write-register-address + read (repeated start), as the
             * Arduino Wire library emits for endTransmission(false)+requestFrom:
             * tx_fifo = [WADDR, REG, RADDR]. Set the pointer from REG, then
             * return dev_mem from there (the read phase of the same op). */
            if (!soc->i2c_slave_rw && tl >= 3 &&
                (t[0] & 1u) == 0u && (t[2] & 1u) == 1u &&
                (t[0] >> 1) == (t[2] >> 1)) {
                int p = t[1];
                soc->i2c_dev_ptr = p;
                soc->i2c_rx_len = 0;
                soc->i2c_rx_pos = 0;
                for (int i = 0; i < 8; i++) {
                    soc->i2c_rx_fifo[i] = soc->i2c_dev_mem[(p++) & 15];
                    soc->i2c_rx_len = 8;
                }
                soc->i2c_dev_ptr = p & 15;
            } else if (soc->i2c_slave_rw) {
                /* READ: return dev_mem from the current pointer, then
                 * auto-increment (standard EEPROM sequential read). */
                soc->i2c_rx_len = 0;
                soc->i2c_rx_pos = 0;
                int p = soc->i2c_dev_ptr;
                for (int i = 0; i < 8; i++) {
                    soc->i2c_rx_fifo[i] = soc->i2c_dev_mem[(p++) & 15];
                    soc->i2c_rx_len = 8;
                }
                soc->i2c_dev_ptr = p & 15;
            } else {
                /* WRITE: tx_fifo[1] is the register/memory address; the
                 * following bytes are stored there and auto-increment. */
                int p = soc->i2c_dev_ptr;
                for (int i = 1; i < soc->i2c_tx_len; i++) {
                    if (i == 1) {
                        soc->i2c_dev_ptr = soc->i2c_tx_fifo[i];
                        p = soc->i2c_dev_ptr;
                    } else {
                        soc->i2c_dev_mem[(p++) & 15] = soc->i2c_tx_fifo[i];
                    }
                }
                soc->i2c_dev_ptr = p & 15;
            }
            soc->i2c_reg[0x20 >> 2] |= 1u << 7; /* trans complete, no nack */
        } else {
            soc->i2c_reg[0x20 >> 2] |= (1u << 10) | (1u << 7); /* nack */
        }
        soc->i2c_reg[0x4 >> 2] &= ~(1u << 5); /* trans_start self-clears */
        soc->i2c_tx_len = 0;
        if (soc->i2c_reg[0x20 >> 2] & soc->i2c_reg[0x28 >> 2])
            soc->intc_status |= ((__uint128_t)1) << C6_I2C_EXT0_INTR_SOURCE;
    }

    /* SPI2 transfer completion: cmd.usr was set. The virtual device (a
     * 16-byte SRAM, JEDEC ID 0xEF4015, echo fallback) decodes the TX bytes
     * from the data buffer (little-endian byte order as the HAL packs it)
     * and shifts its response back MSB-first; with no device selected the
     * MISO line floats high so every received byte is 0xFF. */
    if (soc->spi2_transfer_pending) {
        soc->spi2_transfer_pending = 0;
        uint32_t dlen = soc->spi2_reg[0x1c >> 2] & 0x3Fu; /* usr_mosi_dbitlen */
        int n = (dlen + 8) / 8; /* transferred bytes, byte-aligned */
        if (n > 16)
            n = 16;
        uint8_t tx[16], rx[16];
        for (int i = 0; i < n; i++) {
            int w = i >> 2;
            int sh = 8 * (i & 3); /* HAL packs/reads buffer bytes LE */
            tx[i] = (soc->spi2_reg[(0x98u + 4u * w) >> 2] >> sh) & 0xFFu;
        }
        if (soc->spi2_jedec < 4) { /* mid JEDEC read: clock out next ID bytes */
            static const uint8_t jedec_id[4] = { 0xEFu, 0x40u, 0x15u, 0xFFu };
            int idx = soc->spi2_jedec;
            for (int i = 0; i < n; i++) {
                rx[i] = (idx < 4) ? jedec_id[idx] : 0xFFu;
                idx++;
            }
            soc->spi2_jedec = (idx >= 4) ? 4 : idx;
        } else if (n >= 1 && tx[0] == 0x9Fu) { /* READ JEDEC ID */
            static const uint8_t jedec_id[4] = { 0xEFu, 0x40u, 0x15u, 0xFFu };
            /* the first ID byte (0xEF) clocks out during the 0x9F command */
            for (int i = 0; i < n; i++)
                rx[i] = (i < 4) ? jedec_id[i] : 0xFFu;
            soc->spi2_jedec = (n >= 4) ? 4 : n;
        } else if (n >= 3 && tx[0] == 0x03u) { /* READ SRAM */
            int addr = (tx[1] << 8) | tx[2];
            for (int i = 0; i < n; i++)
                rx[i] = soc->spi2_dev_mem[(addr + i) & 15];
        } else if (n >= 3 && tx[0] == 0x02u) { /* WRITE SRAM */
            int addr = (tx[1] << 8) | tx[2];
            for (int i = 3; i < n; i++)
                soc->spi2_dev_mem[(addr + i - 3) & 15] = tx[i];
            for (int i = 0; i < n; i++)
                rx[i] = tx[i];
        } else { /* loopback echo */
            for (int i = 0; i < n; i++)
                rx[i] = tx[i];
        }
        for (int i = 0; i < 4; i++) /* MISO floats high for unused bits */
            soc->spi2_reg[(0x98u + 4u * i) >> 2] = 0xFFFFFFFFu;
        for (int i = 0; i < n; i++) { /* response packed LE like the HAL reads */
            int w = i >> 2;
            int sh = 8 * (i & 3);
            uint32_t *reg = &soc->spi2_reg[(0x98u + 4u * w) >> 2];
            *reg = (*reg & ~(0xFFu << sh)) | ((uint32_t)rx[i] << sh);
        }
        soc->spi2_reg[0x00 >> 2] &= ~(1u << 24); /* usr cleared */
        soc->spi2_reg[0x3c >> 2] |= 1u << 12;    /* trans_done raw */
    }

    /* TWAI0 TX completion: a tx_request was issued. No other node on the
     * bus, but the frame goes out and the controller reports TCS + TI
     * (transmit interrupt), which the ISR maps to TX_BUFF_FREE|TX_SUCCESS.
     * The completion is delayed to a later cycle so the interrupt is not
     * delivered while the firmware is still inside twai_transmit_v2 (real
     * hardware takes ~200us for a frame); delivering it instantly made the
     * ISR run before the driver's own tx_msg_count++ and assert on it. */
    if (soc->twai_tx_pending &&
        rv->csr_cycle >= soc->twai_tx_done_cycle) {
        soc->twai_tx_pending = 0;
        soc->twai_reg[0x04 >> 2] &= ~TWAI0_CMD_TX_REQUEST;
        soc->twai_reg[0x08 >> 2] |= TWAI0_STATUS_TCS;
        soc->twai_reg[0x0c >> 2] |= TWAI0_INTR_TI;
        soc->intc_status |= ((__uint128_t)1) << C6_TWAI0_INTR_SOURCE;
    }

    /* TWAI0 RX delivery: a virtual node on the bus sends one frame
     * (~1.5ms after the controller left reset mode): std ID 0x123, DLC 2,
     * data DE AD. The frame buffer words hold one byte each (bits 7-0);
     * bytes 1-2 are the ID left-aligned big-endian ((id << 5) >> 8,
     * (id << 5) & 0xFF). RX delivery sets RBS + rx_message_counter and
     * raises RI, gated on the receive interrupt being enabled, so the
     * driver ISR sees RX_BUFF_FRAME and drains one frame. */
    if (!soc->twai_rx_delivered && soc->twai_rx_deliver_cycle &&
        rv->csr_cycle >= soc->twai_rx_deliver_cycle) {
        soc->twai_rx_delivered = 1;
        soc->twai_reg[0x40 >> 2] = 0x02u; /* dlc=2, standard format */
        soc->twai_reg[0x44 >> 2] = 0x24u; /* id 0x123, high byte */
        soc->twai_reg[0x48 >> 2] = 0x60u; /* id 0x123, low byte */
        soc->twai_reg[0x4c >> 2] = 0xDEu; /* data[0] */
        soc->twai_reg[0x50 >> 2] = 0xADu; /* data[1] */
        for (int i = 5; i < 13; i++)
            soc->twai_reg[(0x40u + 4u * i) >> 2] = 0;
        soc->twai_reg[0x08 >> 2] |= TWAI0_STATUS_RBS;
        soc->twai_reg[0x74 >> 2]++;
        if (soc->twai_reg[0x10 >> 2] & TWAI0_INTR_RI) {
            soc->twai_reg[0x0c >> 2] |= TWAI0_INTR_RI;
            soc->intc_status |= ((__uint128_t)1) << C6_TWAI0_INTR_SOURCE;
        }
    }

    /* RMT TX completion: set TX_DONE (raw bit 0) and raise the source
     * (INTMTX source 38); the driver ISR clears it via INT_CLR. */
    if (soc->rmt_tx_done_cycle &&
        rv->csr_cycle >= soc->rmt_tx_done_cycle) {
        soc->rmt_tx_done_cycle = 0;
        mmio32[0x7038u >> 2] |= 0x1u;
        if (mmio32[0x7038u >> 2] & mmio32[0x7040u >> 2])
            soc->intc_status |= ((__uint128_t)1) << C6_RMT_INTR_SOURCE;
    }

    /* RMT RX: pulse capture on the channel input (GPIO matrix FUNC71/72_
     * IN_SEL routes a pin to the RMT input signals). Each input transition
     * writes a symbol {level, duration} into the channel memory at 0x6400 +
     * (ch+2)*48 words and advances the chmstatus writer offset; when the
     * signal stays constant for idle_thres RMT ticks after the first
     * transition, RX_END (raw bit 2+c) frames the message and the channel
     * stops itself until the driver re-arms it. */
    for (int c = 0; c < 2; c++) {
        if (!soc->rmt_rx_en[c])
            continue;
        uint32_t conf0 = mmio32[(0x7018u + 8u * c) >> 2];
        uint32_t div = (conf0 & 0xFFu) ? (conf0 & 0xFFu) : 256u;
        uint32_t idle = (conf0 >> 8) & 0x7FFFu;
        uint32_t insel = mmio32[(0x91270u + 4u * c) >> 2] & 0x3Fu;
        uint32_t level = (insel < 31u) ? ((soc->gpio_in >> insel) & 1u) : 0u;
        uint64_t now = rv->csr_cycle;
        soc->rmt_rx_last_cycle[c] = now;
        if (level != soc->rmt_rx_last_level[c]) {
            /* one RMT tick = div source cycles = 2*div emulated cycles */
            uint32_t dur = (uint32_t) ((now - soc->rmt_rx_trans_cycle[c]) /
                                       (2ull * div));
            if (soc->rmt_rx_wptr[c] < 48u) {
                uint32_t *mem =
                    mmio32 + (0x7400u >> 2) + (c + 2u) * 48u;
                mem[soc->rmt_rx_wptr[c]++] =
                    (soc->rmt_rx_last_level[c] << 15) | (dur & 0x7FFFu);
                mmio32[((0x7030u + 4u * c) >> 2)] =
                    (c + 2u) * 48u + soc->rmt_rx_wptr[c];
            } else { /* channel memory exhausted: raise the error bit */
                mmio32[0x7038u >> 2] |= 1u << (6 + c);
                soc->rmt_rx_en[c] = 0;
            }
            soc->rmt_rx_last_level[c] = level;
            soc->rmt_rx_trans_cycle[c] = now;
        } else {
            /* the idle time since the last transition grows monotonically;
             * when it exceeds idle_thres the message is complete */
            if ((now - soc->rmt_rx_trans_cycle[c]) / (2ull * div) >
                    (uint64_t) idle &&
                soc->rmt_rx_wptr[c] > 0) {
                mmio32[0x7038u >> 2] |= 1u << (2 + c); /* rx end raw */
                if (mmio32[0x7038u >> 2] & mmio32[0x7040u >> 2])
                    soc->intc_status |= ((__uint128_t)1) << C6_RMT_INTR_SOURCE;
                soc->rmt_rx_en[c] = 0; /* HW stops itself after idle */
            }
        }
    }

    /* GDMA TX -> I2S0: the I2S engine drains one 32-bit word from the
     * channel FIFO every 256 cycles (paced, well below the real 44.1 kHz
     * stereo word rate, so descriptors complete quickly without flooding
     * the guest with EOF interrupts). The DMA walker refills the FIFO
     * from the current descriptor and raises OUT_EOF (INTMTX source
     * 56+ch) once it has pushed the descriptor's full length. */
    for (int ch = 0; ch < 3; ch++) {
        if (!soc->gdma_tx_run[ch])
            continue;
        if (soc->gdma_out_peri_sel[ch] == 6)
            continue; /* AES0: data is consumed by the AES trigger, not I2S */
        if (!(mmio32[0xD024u >> 2] & (1u << 2))) /* I2S TX not started */
            continue;
        if (rv->csr_cycle < soc->gdma_tx_drain_cyc[ch])
            continue;
        soc->gdma_tx_drain_cyc[ch] = rv->csr_cycle + 256u;
        if (soc->gdma_tx_fifo_cnt[ch] > 0)
            soc->gdma_tx_fifo_cnt[ch]--;
        while (soc->gdma_tx_fifo_cnt[ch] < 12u &&
               soc->gdma_tx_desc_left[ch] > 0) {
            uint8_t *buf = esp32h2_dma_ptr(
                soc, soc->gdma_tx_desc_buf[ch] +
                         (soc->gdma_tx_desc_len[ch] -
                          soc->gdma_tx_desc_left[ch]));
            if (!buf) { /* buffer outside RAM: park the channel */
                soc->gdma_tx_run[ch] = 0;
                break;
            }
            uint32_t w;
            memcpy(&w, buf, 4);
            soc->gdma_tx_fifo[ch][soc->gdma_tx_fifo_cnt[ch]++] = w;
            soc->gdma_tx_desc_left[ch] -= 4;
        }
        if (soc->gdma_tx_desc_left[ch] > 0)
            continue;
        /* descriptor complete: record the EOF and advance in the ring */
        soc->gdma_out_eof_des_addr[ch] = soc->gdma_tx_desc_addr[ch];
        if (soc->gdma_out_conf0[ch] & (1u << 2)) { /* auto write-back */
            uint8_t *d = esp32h2_dma_ptr(soc, soc->gdma_tx_desc_addr[ch]);
            if (d) {
                uint32_t dw0;
                memcpy(&dw0, d, 4);
                dw0 &= ~0x80000000u; /* owner = software */
                memcpy(d, &dw0, 4);
            }
        }
        soc->gdma_out_int_raw[ch] |= 1u << 1; /* TX_EOF */
        if (soc->gdma_out_int_raw[ch] & soc->gdma_out_int_ena[ch]) {
            soc->intc_status |= ((__uint128_t)1) << (C6_DMA_OUT_CH0_INTR_SOURCE + ch);
        }
        if (!soc->gdma_tx_next_addr[ch]) {
            soc->gdma_tx_run[ch] = 0; /* park after the last descriptor */
        } else {
            soc->gdma_tx_desc_addr[ch] = soc->gdma_tx_next_addr[ch];
            esp32h2_gdma_load_desc(soc, ch);
        }
    }

    /* GDMA RX <- I2S0: the I2S RX engine synthesizes one 32-bit sample word
     * per 256 cycles into the channel RX FIFO; the DMA walker copies FIFO
     * words into the current descriptor buffer and raises IN_SUC_EOF
     * (INTMTX source 66+ch) once the descriptor is full. The synthesized
     * stream is a monotonic 32-bit counter so a guest read can verify it
     * (left channel = word, right channel = word>>16). */
    for (int ch = 0; ch < 3; ch++) {
        if (!soc->gdma_rx_run[ch])
            continue;
        if (soc->gdma_in_peri_sel[ch] == 6)
            continue; /* AES0: data is produced by the AES trigger, not I2S */
        if (!(mmio32[0xD020u >> 2] & (1u << 2))) /* I2S RX not started */
            continue;
        if (rv->csr_cycle < soc->gdma_rx_fill_cyc[ch])
            continue;
        soc->gdma_rx_fill_cyc[ch] = rv->csr_cycle + 256u;
        /* produce one sample into the RX FIFO if there is room */
        if (soc->gdma_rx_fifo_cnt[ch] < 12u) {
            uint8_t t = (soc->gdma_rx_fifo_head[ch] +
                         soc->gdma_rx_fifo_cnt[ch]) % 12u;
            soc->gdma_rx_fifo[ch][t] = soc->gdma_rx_sample[ch]++;
            soc->gdma_rx_fifo_cnt[ch]++;
        }
        /* walker copies one FIFO word into the guest buffer */
        if (soc->gdma_rx_fifo_cnt[ch] > 0 &&
            soc->gdma_rx_desc_left[ch] > 0) {
            uint8_t h = soc->gdma_rx_fifo_head[ch];
            uint32_t w = soc->gdma_rx_fifo[ch][h];
            soc->gdma_rx_fifo_head[ch] = (h + 1u) % 12u;
            soc->gdma_rx_fifo_cnt[ch]--;
            uint8_t *buf = esp32h2_dma_ptr(
                soc, soc->gdma_rx_desc_buf[ch] +
                         (soc->gdma_rx_desc_len[ch] -
                          soc->gdma_rx_desc_left[ch]));
            if (!buf) { /* buffer outside RAM: park the channel */
                soc->gdma_rx_run[ch] = 0;
                break;
            }
            memcpy(buf, &w, 4);
            soc->gdma_rx_desc_left[ch] -= 4;
        }
        if (soc->gdma_rx_desc_left[ch] > 0)
            continue;
        /* descriptor complete: record the EOF and advance in the ring */
        soc->gdma_in_eof_des_addr[ch] = soc->gdma_rx_desc_addr[ch];
        soc->gdma_in_int_raw[ch] |= 1u << 1; /* IN_SUC_EOF */
        if (soc->gdma_in_int_raw[ch] & soc->gdma_in_int_ena[ch]) {
            soc->intc_status |= ((__uint128_t)1) << (C6_DMA_IN_CH0_INTR_SOURCE + ch);
        }
        if (!soc->gdma_rx_next_addr[ch]) {
            soc->gdma_rx_run[ch] = 0; /* park after the last descriptor */
        } else {
            soc->gdma_rx_desc_addr[ch] = soc->gdma_rx_next_addr[ch];
            esp32h2_gdma_load_rx_desc(soc, ch);
        }
    }

    /* feed host-injected bytes into the UART RX FIFO (throttled) */
    if ((rv->csr_cycle & 0x1FFu) == 0)
        esp32h2_uart_rx_poll(soc);

    /* UART RX interrupt: bytes are waiting and the driver armed
     * RXFIFO_TOUT (real HW fires it after rx_tout_thrhd idle bit times;
     * the model fires it immediately, the ISR then drains the FIFO). */
    if (soc->uart_rx_head[0] != soc->uart_rx_tail[0]) {
        uint32_t *raw = &mmio32[UART_INT_RAW_REG >> 2];
        if ((mmio32[UART_INT_ENA_REG >> 2] & UART_RXFIFO_TOUT_BIT) &&
            !(*raw & UART_RXFIFO_TOUT_BIT)) {
            *raw |= UART_RXFIFO_TOUT_BIT;
            soc->intc_status |= ((__uint128_t)1) << C6_UART0_INTR_SOURCE;
        }
    }

    /* UART TXFIFO_EMPTY interrupt: the esp-idf uart driver only moves bytes
     * from its software ring buffer into the HW FIFO inside the TX ISR, which
     * fires on TXFIFO_EMPTY. The model transmits instantly, so the HW FIFO is
     * always empty; we therefore raise TXFIFO_EMPTY periodically (throttled
     * to avoid a storm) whenever the source is enabled and not already
     * pending, so the SDK ISR can drain whatever the app has queued. */
    /* TXFIFO_EMPTY raise DISABLED: continuous re-arm starves the main task
     * (interrupt storm). Re-enable only when the app has data to drain.
    for (int p = 0; p < 2; p++) {
        uint32_t base = C6_PERIPH_BASE + 0x1000u * p;
        if (soc->uart_tx_cnt[p])
            soc->uart_tx_cnt[p]--;
        uint32_t *raw =
            &mmio32[(base + UART_INT_RAW_REG - C6_PERIPH_BASE) >> 2];
        uint32_t *ena =
            &mmio32[(base + UART_INT_ENA_REG - C6_PERIPH_BASE) >> 2];
        if ((soc->uart_tx_cnt[p] & 0x1FFu) == 0 &&
            (*ena & UART_TXFIFO_EMPTY_BIT) &&
            !(*raw & UART_TXFIFO_EMPTY_BIT)) {
            *raw |= UART_TXFIFO_EMPTY_BIT;
            int src = (p == 0) ? C6_UART0_INTR_SOURCE : C6_UART1_INTR_SOURCE;
            soc->intc_status |= ((__uint128_t)1) << src;
        }
    }
    */

    /* LEDC output drive: enabled channels drive their routed pads. The
     * GPIO matrix FUNCx_OUT_SEL (0x60091554 + 4*pin) picks the signal
     * index; LEDC channels 0-5 are signals 0-5. The pad level follows
     * the PWM phase (high for DUTY_R ticks starting at HPOINT within
     * the 2^DUTY_RES period). */
    for (int c = 0; c < 6; c++) {
        uint32_t conf0 = soc->ledc_reg[LEDC_CH_CONF0(c) >> 2];
        int level;
        if (conf0 & LEDC_SIG_OUT_EN) {
            uint32_t t = conf0 & 0x3u;
            uint32_t conf = soc->ledc_reg[LEDC_TIMER_CONF(t) >> 2];
            uint32_t res = conf & 0x1Fu;
            /* CLK_DIV holds the divider in units of 1/256 source clock
             * cycles; the C6 feeds the LEDC timers from the 40MHz XTAL,
             * i.e. one source cycle per two emulated cycles. */
            uint32_t f = (conf >> 5) & 0x3FFFFu;
            uint32_t ratio = (conf & LEDC_TICK_SEL) ? 10u : 1u;
            uint32_t period = 1u << (res < 25 ? res : 25);
            if (f == 0) {
                level = (conf0 & LEDC_IDLE_LV) ? 1 : 0;
            } else {
                /* accumulate the elapsed time in source-cycle/256 units
                 * (one emulated cycle = two source cycles) so the phase
                 * advances exactly one tick per f/256 source cycles,
                 * wrapping at the full PWM period */
                uint64_t span = (uint64_t) f * (uint64_t) period * ratio;
                soc->ledc_timer_frac[t] +=
                    (rv->csr_cycle - soc->ledc_timer_anchor[t]) * 512ull;
                soc->ledc_timer_anchor[t] = rv->csr_cycle;
                soc->ledc_timer_frac[t] %= span;
                uint64_t ticks = soc->ledc_timer_frac[t] / f;
                uint32_t pos = (uint32_t)(ticks % period);
                uint32_t hpoint = soc->ledc_reg[LEDC_CH_HPOINT(c) >> 2] &
                                   0xFFFFFu;
                uint32_t duty = (soc->ledc_duty_r[c] & 0x1FFFFFFu) >> 4u;
                level = ((pos + period - hpoint) % period) < duty;
            }
        } else {
            level = (conf0 & LEDC_IDLE_LV) ? 1 : 0;
        }
        for (int p = 0; p < 30; p++) {
            uint32_t sel = mmio32[(0x91554u + 4u * p) >> 2] & 0xFFu;
            if (sel == (uint32_t) c) {
                if (level)
                    soc->gpio_in |= 1u << p;
                else
                    soc->gpio_in &= ~(1u << p);

            }
        }
    }

    /* MCPWM (0x60014000): timers count 0..period, one tick per
     * (timer_prescale+1)*(clk_prescale+1) source cycles (40 MHz, i.e. two
     * emulated cycles each). timer_mod: 0 paused, 1 up (register period is
     * peak-1), 2 down, 3 up/down (register period is the peak). Generator
     * events (zero, period, compare A/B) apply the action fields; the
     * resulting level drives any pad whose matrix output select is the
     * MCPWM signal (87..92 = PWM0_OUT{0,1,2}{A,B}). */
    {
        uint32_t clkps = (soc->mcpwm_reg[0x00 >> 2] & 0xFFu) + 1u;
        for (int t = 0; t < 3; t++) {
            if (!soc->mcpwm_running[t])
                continue;
            uint32_t base = 0x04u + 0x10u * t;
            uint32_t cfg0 = soc->mcpwm_reg[base >> 2];
            uint32_t mod = (soc->mcpwm_reg[(base + 0x04u) >> 2] >> 3) & 0x3u;
            uint32_t period = (cfg0 >> 8) & 0xFFFFu;
            if (mod == 0u || period == 0)
                continue;
            uint64_t step = (uint64_t) ((cfg0 & 0xFFu) + 1u) * clkps * 2ull;
            soc->mcpwm_frac[t] += rv->csr_cycle - soc->mcpwm_anchor[t];
            soc->mcpwm_anchor[t] = rv->csr_cycle;
            uint64_t elapsed = soc->mcpwm_frac[t] / step;
            soc->mcpwm_frac[t] %= step;
            uint32_t phase = soc->mcpwm_phase[t];
            for (uint64_t i = 0; i < elapsed; i++) {
                /* one-shot stop commands take effect on reaching the value */
                if ((soc->mcpwm_stopat[t] == 1 && phase == 0) ||
                    (soc->mcpwm_stopat[t] == 2 && phase == period)) {
                    soc->mcpwm_running[t] = 0;
                    soc->mcpwm_stopat[t] = 0;
                    break;
                }
                esp32h2_mcpwm_fire(soc, t, soc->mcpwm_dir[t], phase, period);
                if (mod == 1u) { /* up */
                    soc->mcpwm_dir[t] = 0;
                    phase = (phase == period) ? 0 : phase + 1;
                } else if (mod == 2u) { /* down */
                    soc->mcpwm_dir[t] = 1;
                    phase = (phase == 0) ? period : phase - 1;
                } else if (soc->mcpwm_dir[t] == 0) { /* up/down rising */
                    if (phase == period) {
                        phase = period - 1;
                        soc->mcpwm_dir[t] = 1;
                    } else {
                        phase++;
                    }
                } else { /* up/down falling */
                    if (phase == 0) {
                        phase = 1;
                        soc->mcpwm_dir[t] = 0;
                    } else {
                        phase--;
                    }
                }
                soc->mcpwm_phase[t] = phase;
            }
        }
        /* drive pads routed to MCPWM signals; continuous force (cntuforce
         * mode) pins the level, one-shot force (nciforce) lasts one event */
        for (int p = 0; p < 30; p++) {
            uint32_t sel = mmio32[(0x91554u + 4u * p) >> 2] & 0xFFu;
            if (sel < 87u || sel > 92u)
                continue;
            int op = (int) (sel - 87u) >> 1;
            int g = (int) (sel - 87u) & 1;
            uint32_t gf = soc->mcpwm_reg[(0x3cu + 0x38u * op + 0x10u) >> 2];
            uint32_t cmode = (g == 0) ? ((gf >> 6) & 0x3u) : ((gf >> 8) & 0x3u);
            uint32_t nmode = (g == 0) ? ((gf >> 11) & 0x3u) : ((gf >> 14) & 0x3u);
            uint32_t ntrig = (g == 0) ? ((gf >> 10) & 1u) : ((gf >> 13) & 1u);
            int level;
            if (cmode)
                level = (cmode == 2u);
            else if (ntrig && nmode)
                level = (nmode == 2u);
            else
                level = (soc->mcpwm_level[op][g] != 0);
            if (level)
                soc->gpio_in |= 1u << p;
            else
                soc->gpio_in &= ~(1u << p);
        }
    }

    /* TIMG0/1 alarms: the counter ticks at the selected clock (PLL 80MHz
     * or XTAL 40MHz, ratio vs the 1:1 cycle clock) divided by DIVIDER+1.
     * On alarm: raw bit 0 set and the source raised (level semantics:
     * re-asserted while the counter is past the alarm). With AUTORELOAD
     * the counter reloads from T0LOADLO/HI. */
    for (int g = 0; g < 2; g++) {
        uint32_t cfg = soc->timg_reg[g][TIMG_T0CONFIG >> 2];
        if (!(cfg & TIMG_T0_EN))
            continue;
        uint32_t div = ((cfg & TIMG_T0_DIVIDER) >> 13) + 1u;
        uint32_t ratio = (cfg & TIMG_T0_USE_XTAL) ? 2u : 1u;
        /* accumulate fractional cycles so the counter advances exactly
         * one tick per div*ratio cycles regardless of block granularity */
        uint64_t step = (uint64_t) div * (uint64_t) ratio;
        soc->timg_frac[g] += rv->csr_cycle - soc->timg_anchor[g];
        soc->timg_anchor[g] = rv->csr_cycle;
        uint64_t elapsed = soc->timg_frac[g] / step;
        soc->timg_frac[g] %= step;
        uint64_t cnt;
        if (cfg & TIMG_T0_INCREASE)
            cnt = soc->timg_counter[g] + elapsed;
        else
            cnt = (elapsed > soc->timg_counter[g]) ? 0
                                                   : soc->timg_counter[g] - elapsed;
        soc->timg_counter[g] = cnt;
        uint64_t alarm =
            ((uint64_t) soc->timg_reg[g][TIMG_T0ALARMHI >> 2] << 32) |
            soc->timg_reg[g][TIMG_T0ALARMLO >> 2];
        uint32_t src = (g == 0) ? C6_TG0_T0_INTR_SOURCE
                                : C6_TG1_T0_INTR_SOURCE;
        int past = (cfg & TIMG_T0_ALARM_EN) && alarm &&
                   ((cfg & TIMG_T0_INCREASE) ? cnt >= alarm : cnt <= alarm);
        if (past) {
            soc->timg_reg[g][TIMG_INT_RAW >> 2] |= TIMG_INT_T0_ALARM;
            if (soc->timg_reg[g][TIMG_INT_RAW >> 2] &
                soc->timg_reg[g][TIMG_INT_ENA >> 2])
                soc->intc_status |= ((__uint128_t)1) << src;
            if (cfg & TIMG_T0_AUTORELOAD) {
                uint64_t reload =
                    ((uint64_t) soc->timg_reg[g][TIMG_T0LOADHI >> 2] << 32) |
                    soc->timg_reg[g][TIMG_T0LOADLO >> 2];
                soc->timg_counter[g] = reload;
                soc->timg_anchor[g] = rv->csr_cycle;
                soc->timg_frac[g] = 0;
            }
        }
    }

    /* MWDT (Timer Group Watchdog) timeouts: when armed and the expiry
     * cycle passes without a feed, raise the group's WDT interrupt (level
     * semantics: the raw bit stays set until a feed or disable clears it). */
    for (int g = 0; g < 2; g++) {
        if (!soc->wdt_en[g])
            continue;
        if (rv->csr_cycle < soc->wdt_expire[g])
            continue;
        soc->timg_reg[g][TIMG_INT_RAW >> 2] |= TIMG_INT_WDT;
        if (soc->timg_reg[g][TIMG_INT_RAW >> 2] &
            soc->timg_reg[g][TIMG_INT_ENA >> 2]) {
            uint32_t src = (g == 0) ? C6_TG0_WDT_INTR_SOURCE
                                    : C6_TG1_WDT_INTR_SOURCE;
            soc->intc_status |= ((__uint128_t)1) << src;
        }
    }

    /* advance SYSTIMER counters (both units free-run on the C6) */
    uint64_t elapsed = rv->csr_cycle - soc->last_cycle;
    soc->last_cycle = rv->csr_cycle;

    /* The C6 system timer is clocked by XTAL/2.5 = 16 MHz and the RTC
     * slow clock is ~150 kHz; both derive from the 80 MHz cycle clock. */
    soc->systimer_frac += elapsed;
    uint64_t syst = soc->systimer_frac / 5u;
    soc->systimer_frac %= 5u;
    soc->systimer_counter += syst;
    soc->systimer_unit1_counter += syst;
    soc->clint_mtime += elapsed;
    soc->lp_timer = rv->csr_cycle / 533u; /* RC_SLOW ~150 kHz */

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
                    soc->intc_status |= ((__uint128_t)1) << SYSTIMER_T0_SOURCE;
                }
            } else if (soc->systimer_comp0 && cnt0 >= soc->systimer_comp0) {
                soc->systimer_int_raw |= 1u;
                soc->intc_status |= ((__uint128_t)1) << SYSTIMER_T0_SOURCE;
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
                    soc->intc_status |= ((__uint128_t)1) << SYSTIMER_T2_SOURCE;
                }
            } else if (soc->systimer_comp2 && cnt2 >= soc->systimer_comp2) {
                soc->systimer_int_raw |= 4u;
                soc->intc_status |= ((__uint128_t)1) << SYSTIMER_T2_SOURCE;
            }
        }
    }
}