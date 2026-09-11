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
    unsigned __int128 intc_status; /* pending sources 0..127 */
    uint32_t intc_eip; /* claimed (exception-in-progress) lines */
    uint32_t intc_intmap[72];    /* sources 0..71 (AES=69, etc.) */

    /* GPIO */
    uint32_t gpio_out;
    uint32_t gpio_enable;
    uint32_t gpio_status;     /* latched interrupt status (GPIO_STATUS) */
    uint32_t gpio_in;         /* level-driven external input pins */
    uint32_t gpio_in_prev;    /* previous live input (for edge detection) */

    /* UART output buffering */
    char uart_line[256];
    int uart_line_len;

    /* UART RX FIFO model: TX->RX loopback (CONF0 bit 12) plus interrupt
     * delivery so the esp-idf uart driver actually drains its ring buffer.
     * Port 0 is also the console; port 1 is used by the loopback sketch. */
    uint8_t uart_rx[2][128];
    unsigned int uart_rx_head[2];
    unsigned int uart_rx_tail[2];
    unsigned int uart_tx_cnt[2];
    uint8_t uart_tx_idle[2];

    /* I2C_EXT (0x60013000): virtual EEPROM device model (mirrors i2c_dev_t) */
    uint32_t i2c_reg[128]; /* 0x200 bytes */
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

    /* SPI2 (GPSPI2, 0x60024000): register bank + virtual SRAM device */
    uint32_t spi2_reg[128];
    int spi2_transfer_pending;
    uint8_t spi2_jedec;       /* mid JEDEC read cursor */
    uint8_t spi2_dev_mem[16]; /* virtual SRAM device (JEDEC 0xEF4015) */

    /* TWAI0 (CAN, 0x6002B000): register bank + a virtual bus node */
    uint32_t twai_reg[64];    /* 0x100 bytes, mirrors twai_dev_t */
    int twai_tx_pending;       /* a cmd.tx_request was written */
    uint64_t twai_tx_done_cycle; /* cycle at which the TX completes */
    uint64_t twai_rx_deliver_cycle; /* cycle at which the virtual node frame arrives */
    int twai_rx_delivered;     /* RX delivery is one-shot */

    /* GDMA (0x6003F000): 3 channels. The OUT (TX) side reads from its
     * descriptor buffers, the paired IN (RX) side writes to its descriptor
     * buffers (the ESP-IDF mem2mem pattern). A single channel interrupt
     * (DMA_CH0/1/2 = 44/45/46) covers both OUT_EOF and IN_SUC_EOF. */
    uint32_t gdma_out_link[3];
    uint32_t gdma_in_link[3];
    uint32_t gdma_out_conf0[3];
    uint32_t gdma_in_conf0[3];
    uint32_t gdma_out_conf1[3];
    uint32_t gdma_in_conf1[3];
    uint32_t gdma_out_peri_sel[3];
    uint32_t gdma_in_peri_sel[3];
    uint32_t gdma_int_raw[3];  /* channel-level raw (OUT_EOF=bit4,IN_SUC_EOF=1) */
    uint32_t gdma_int_ena[3];
    uint32_t gdma_out_dscr[3];       /* current OUT descriptor address */
    uint32_t gdma_in_dscr[3];        /* current IN descriptor address */
    uint32_t gdma_out_eof_des[3];    /* completed OUT descriptor (for eof_des_addr) */
    uint32_t gdma_in_eof_des[3];     /* completed IN descriptor (for eof_des_addr) */
    uint8_t  gdma_out_run[3];
    uint8_t  gdma_in_run[3];
    uint32_t gdma_out_desc_buf[3];
    uint32_t gdma_out_desc_len[3];
    uint32_t gdma_out_next_addr[3];
    uint32_t gdma_in_desc_buf[3];
    uint32_t gdma_in_desc_len[3];
    uint32_t gdma_in_next_addr[3];
    uint8_t  gdma_m2m_pending[3];
    uint64_t gdma_m2m_done_cycle[3];

    /* SAR_ADC (0x60040000): oneshot conversion state (mirrors apb_saradc_dev_t) */
    uint32_t adc_reg[257];    /* 0x400 bytes + version reg */

    /* LEDC (0x60019000): register bank + running duty + timer anchors */
    uint32_t ledc_reg[128];   /* 0x200 bytes, mirrors ledc_dev_t */
    uint32_t ledc_duty_r[6];  /* running duty per channel (latched on start) */
    uint64_t ledc_timer_anchor[4]; /* cycle anchor per timer (phase origin) */
    uint64_t ledc_timer_frac[4];   /* fractional cycle remainder per timer */

    /* TIMG0/1 (0x6001F000/0x60020000): one timer per group + MWDT */
    uint32_t timg_reg[2][64]; /* 0x100 bytes, mirrors timer_group_dev_t */

    /* AES accelerator (0x6003A000): key/text/iv/mode/state registers */
    uint32_t aes_reg[64];     /* 0x100 bytes, mirrors aes_dev_t */

    /* I2S0 (0x6002D000): configuration registers */
    uint32_t i2s_reg[32];     /* 0x80 bytes, mirrors i2s_dev_t */
    uint32_t i2s_rx_counter;  /* monotonic counter for synthesized RX data */

    int wdt_en[2];
    uint64_t wdt_expire[2];
    int wdt_unlock[2];
    uint64_t timg_counter[2]; /* live counter value */
    uint64_t timg_anchor[2];  /* cycle at which the counter base applies */
    uint64_t timg_frac[2];     /* fractional cycle remainder per group */

    /* misc logged-MMIO bookkeeping */
    uint32_t logged_unknown;

    /* TIMG0 WDT_CONFIG0 read counter (stable-read XOR scheme) */
    uint32_t wdt_config0_reads;

    /* flash cache MMU page table (128 x 64KB pages), programmed by the
     * bootloader's esp_rom_spiflash_mmap at 0x18031400 + 4*idx */
    uint32_t mmu[128];

    /* RMT: emulate enough of the TX path that the legacy rmtInit/rmtWrite
     * API (used by the Arduino RGB-LED helper for LED_BUILTIN=30) completes.
     * When a channel's CONF0 tx_start is set we schedule a TX_DONE a few
     * cycles later; the firmware's RMT ISR then posts the transaction and
     * unblocks the caller's event-group wait. */
    uint64_t rmt_tx_done_cycle;
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

/* Map a guest (physical) address in DRAM/SRAM to a host pointer, or NULL
 * if the address is not in a RAM region (e.g. a peripheral MMIO address). */
static uint8_t *esp32c3_dma_ptr(esp32c3_t *soc, uint32_t addr)
{
    esp32_region_t *r = esp32_find_region(soc, addr);
    if (!r || r->type != ESP32_REG_RAM)
        return NULL;
    return r->data + (addr - r->base);
}

/* Load one DMA descriptor (16 bytes: DW0 size/len/owner/eof, DW1 buffer
 * pointer, DW2 next pointer). Returns 0 if the descriptor is not in RAM. */
static int esp32c3_gdma_load_desc(esp32c3_t *soc, uint32_t desc_addr,
                                  uint32_t *buf, uint32_t *len, uint32_t *next)
{
    uint8_t *d = esp32c3_dma_ptr(soc, desc_addr);
    if (!d)
        return 0;
    uint32_t dw0, dw1, dw2;
    memcpy(&dw0, d, 4);
    memcpy(&dw1, d + 4, 4);
    memcpy(&dw2, d + 8, 4);
    *buf = dw1;
    *len = (dw0 >> 12) & 0xFFFu;
    *next = dw2;
    return 1;
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

    /* virtual I2C device: 16-byte EEPROM with a known pattern */
    for (int i = 0; i < 16; i++)
        soc->i2c_dev_mem[i] = 0x40 + i;
    soc->i2c_dev_ptr = 0;
    /* SPI2 virtual SRAM device */
    soc->spi2_jedec = 0;
    for (int i = 0; i < 16; i++)
        soc->spi2_dev_mem[i] = 0xA0 + i;
    /* TWAI0: bus starts in reset mode (mode[0]=1) */
    soc->twai_reg[0] = 1u;
    soc->twai_rx_delivered = 0;
    soc->twai_tx_pending = 0;
    soc->twai_tx_done_cycle = 0;
    soc->twai_rx_deliver_cycle = 0;
    /* GDMA: all channels idle; interrupts cleared */
    for (int i = 0; i < 3; i++) {
        soc->gdma_out_run[i] = 0;
        soc->gdma_in_run[i] = 0;
        soc->gdma_m2m_pending[i] = 0;
        soc->gdma_int_raw[i] = 0;
        soc->gdma_int_ena[i] = 0;
    }

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
    for (int i = 0; i < 72; i++)
        soc->intc_intmap[i] = i;

    return soc;
}

/* ------------------------------------------------------------------ */
/* UART0 (0x60000000)                                                  */
/* ------------------------------------------------------------------ */

#define UART_FIFO_REG 0x00u
#define UART_STATUS_REG 0x1Cu
#define UART_INT_RAW_REG 0x04u
#define UART_INT_ST_REG 0x08u
#define UART_INT_ENA_REG 0x0Cu
#define UART_INT_CLR_REG 0x10u
#define UART_CONF0_REG 0x20u
#define UART_CLKDIV_CONF_REG 0x98u
#define UART_RX_FIFO_SZ 128u
#define UART_LOOPBACK_BIT (1u << 14) /* conf0 bit 14: TX->RX loopback (esp32c3) */
#define UART_RXFIFO_TOUT_BIT 0x100u
#define UART_TXFIFO_EMPTY_BIT 0x2u
#define UART_RXFIFO_FULL_BIT 0x1u
/* INTMTX source numbers (esp32c3 interrupts.h, firmware uses this numbering) */
#define C3_UART0_INTR_SOURCE 21u
#define C3_UART1_INTR_SOURCE 22u
#define C3_I2C_EXT0_INTR_SOURCE 29u
#define C3_TWAI_INTR_SOURCE 25u
#define C3_SPI2_INTR_SOURCE 19u
#define C3_DMA_CH0_INTR_SOURCE 44u
#define C3_DMA_CH1_INTR_SOURCE 45u
#define C3_DMA_CH2_INTR_SOURCE 46u
#define C3_AES_INTR_SOURCE 48u   /* ETS_AES_INTR_SOURCE (AES_INT_MAP @0xC0) */
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
/* AES accelerator (0x6003A000): key/text/iv/mode/state registers */
#define C3_AES_BASE 0x6003A000u
#define C3_AES_SIZE 0xB4u
/* I2S0 (0x6002D000): TX/RX serial audio interface */
#define C3_I2S0_BASE 0x6002D000u
#define C3_I2S0_SIZE 0x80u
/* GDMA (0x6003F000): 3 channels, OUT(TX)=source / IN(RX)=dest */
#define C3_GDMA_BASE 0x6003F000u
#define C3_GDMA_SIZE 0x2B0u
#define GDMA_CHAN_INT_STRIDE 0x10u
#define GDMA_CHAN_BLK_STRIDE 0xC0u
#define GDMA_OUT_EOF_BIT 4u
#define GDMA_IN_SUC_EOF_BIT 1u
/* GDMA peripheral select for the AES accelerator (ESP32-C3). Both the OUT
 * (data into AES) and IN (data out of AES) channels use this peri_sel. */
#define C3_GDMA_PERI_AES 6u
#define GDMA_OUTLINK_START_BIT 21u
#define GDMA_OUTLINK_STOP_BIT 20u
#define GDMA_INLINK_START_BIT 22u
#define GDMA_INLINK_STOP_BIT 21u
#define GDMA_LINK_ADDR_MASK 0x000FFFFFu
/* GDMA addresses memory in the 0x3FC00000-0x3FCFFFFF window; the link
 * register holds bits[19:0] and the hardware prepends 0x3FC00000. */
#define C3_GDMA_MEM_BASE 0x3FC00000u
/* Virtual I2C device: 16-byte EEPROM with a known pattern */
#define C3_I2C_DEV_ADDR 0x50u

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

#define GPIO_OUT_REG 0x04u
#define GPIO_OUT_W1TS 0x08u
#define GPIO_OUT_W1TC 0x0Cu
#define GPIO_ENABLE_REG 0x20u
#define GPIO_ENABLE_W1TS 0x24u
#define GPIO_ENABLE_W1TC 0x28u
#define GPIO_IN_REG 0x3Cu
#define GPIO_STRAP_REG 0x38u
#define GPIO_STATUS_REG 0x44u
#define GPIO_STATUS_W1TS_REG 0x48u
#define GPIO_STATUS_W1TC_REG 0x4Cu
#define GPIO_PCPU_INT_REG 0x5Cu
#define GPIO_PIN0 0x74u

/* LEDC (0x60019000): 6 channels x (CONF0/HPOINT/DUTY/CONF1/DUTY_R) */
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

/* TIMG0/1 (0x6001F000/0x60020000): one timer + WDT per group */
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
#define TIMG_T0_EN (1u << 31)
#define TIMG_T0_INCREASE (1u << 30)
#define TIMG_T0_AUTORELOAD (1u << 29)
#define TIMG_T0_DIVIDER (0xFFFFu << 13)
#define TIMG_T0_DIVCNT_RST (1u << 12)
#define TIMG_T0_ALARM_EN (1u << 10)
#define TIMG_T0_USE_XTAL (1u << 9)
/* csr_cycle advances at the C3 SYSTIMER base clock (16 MHz); the SoC models
 * the SYSTIMER counter 1:1 with csr_cycle, so all other clock-derived timers
 * must scale against this rate. */
#define ESP32C3_CSR_CLK_MHZ 16u
#define TIMG_INT_T0_ALARM (1u << 0)
#define TIMG_INT_WDT (1u << 1)
#define TIMG_WDT_CONFIG0 0x48u
#define TIMG_WDT_CONFIG1 0x4cu
#define TIMG_WDT_CONFIG2 0x50u
#define TIMG_WDT_FEED 0x60u
#define TIMG_WDT_WPROTECT 0x64u
#define TIMG_WDT_MAGIC 0x50D83AA1u
#define TIMG_WDT_EN (1u << 31)

/* SAR_ADC (0x60040000): oneshot conversion state */
#define ADC_ONETIME_SAMPLE 0x20u
#define ADC_INT_ENA 0x40u
#define ADC_INT_RAW 0x44u
#define ADC_INT_CLR 0x4Cu
#define ADC_TSENS_CTRL 0x58u
#define ADC_DATA1 0x2cu
#define ADC_DATA2 0x30u

/* C3 interrupt sources (esp32c3 interrupts.h) */
#define C3_GPIO_INTR_SOURCE 16u
#define C3_LEDC_INTR_SOURCE 23u
#define C3_TG0_T0_INTR_SOURCE 32u
#define C3_TG0_WDT_INTR_SOURCE 33u
#define C3_TG1_T0_INTR_SOURCE 34u
#define C3_TG1_WDT_INTR_SOURCE 35u

/* A pin configured as a (peripheral-driven) output reports the live peripheral
 * level on its own pad input; a GPIO-driven output reports gpio_out. Pins
 * routed to a peripheral signal (GPIO matrix FUNCx_OUT_SEL) follow the
 * peripheral; others follow the static gpio_out value. */
static uint32_t esp32c3_gpio_eff_out(esp32c3_t *soc, uint32_t *mmio32)
{
    uint32_t out = 0;
    for (int p = 0; p < 22; p++) {
        if (!(soc->gpio_enable & (1u << p)))
            continue;
        uint32_t sel = mmio32[(0x4554u + 4u * p) >> 2];
        if (sel & 0x100u)            /* peripheral signal drives the pad */
            out |= (soc->gpio_in & (1u << p));
        else
            out |= (soc->gpio_out & (1u << p));
    }
    return out;
}

/* Minimal FIPS-197 AES used to emulate the C3 hardware AES accelerator.
 * State/key are handled as flat 16-byte / keylen-byte arrays in standard
 * (big-endian word) order; the guest's little-endian register words are
 * converted at the MMIO boundary. */
static const uint8_t esp32c3_aes_sbox[256] = {
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
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16};

static uint8_t esp32c3_aes_gmul(uint8_t a, uint8_t b)
{
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        uint8_t hi = a & 0x80;
        a = (uint8_t)(a << 1);
        if (hi) a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

static void esp32c3_aes_keyexp(const uint8_t *key, int Nk, uint8_t *w)
{
    int Nr = Nk + 6, Nb = 4;
    for (int i = 0; i < Nk; i++) {
        w[4*i] = key[4*i]; w[4*i+1] = key[4*i+1];
        w[4*i+2] = key[4*i+2]; w[4*i+3] = key[4*i+3];
    }
    uint8_t rcon = 1, t[4];
    for (int i = Nk; i < Nb*(Nr+1); i++) {
        t[0] = w[4*(i-1)]; t[1] = w[4*(i-1)+1];
        t[2] = w[4*(i-1)+2]; t[3] = w[4*(i-1)+3];
        if (i % Nk == 0) {
            uint8_t x = t[0]; t[0] = t[1]; t[1] = t[2]; t[2] = t[3]; t[3] = x;
            t[0] = esp32c3_aes_sbox[t[0]]; t[1] = esp32c3_aes_sbox[t[1]];
            t[2] = esp32c3_aes_sbox[t[2]]; t[3] = esp32c3_aes_sbox[t[3]];
            t[0] ^= rcon;
            rcon = (uint8_t)((rcon << 1) ^ ((rcon & 0x80) ? 0x1b : 0));
        } else if (Nk > 6 && i % Nk == 4) {
            t[0] = esp32c3_aes_sbox[t[0]]; t[1] = esp32c3_aes_sbox[t[1]];
            t[2] = esp32c3_aes_sbox[t[2]]; t[3] = esp32c3_aes_sbox[t[3]];
        }
        w[4*i]   = w[4*(i-Nk)]   ^ t[0];
        w[4*i+1] = w[4*(i-Nk)+1] ^ t[1];
        w[4*i+2] = w[4*(i-Nk)+2] ^ t[2];
        w[4*i+3] = w[4*(i-Nk)+3] ^ t[3];
    }
}

static void __attribute__((unused))
esp32c3_aes_subshift(uint8_t *s, int dec)
{
    if (!dec) {
        for (int i = 0; i < 16; i++) s[i] = esp32c3_aes_sbox[s[i]];
        uint8_t t;
        t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;
        t = s[2]; s[2] = s[10]; s[10] = t;  t = s[6]; s[6] = s[14]; s[14] = t;
        t = s[3]; s[3] = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = t;
    } else {
        uint8_t t;
        t = s[13]; s[13] = s[9]; s[9] = s[5]; s[5] = s[1]; s[1] = t;
        t = s[2]; s[2] = s[10]; s[10] = t;  t = s[6]; s[6] = s[14]; s[14] = t;
        t = s[3]; s[3] = s[7]; s[7] = s[11]; s[11] = s[15]; s[15] = t;
        /* inverse sbox applied by caller via separate table */
    }
}

static const uint8_t esp32c3_aes_inv_sbox[256] = {
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
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d};

static void esp32c3_aes_mix(uint8_t *s, int inv)
{
    for (int c = 0; c < 4; c++) {
        uint8_t s0 = s[0+4*c], s1 = s[1+4*c], s2 = s[2+4*c], s3 = s[3+4*c];
        if (!inv) {
            s[0+4*c] = esp32c3_aes_gmul(s0,2) ^ esp32c3_aes_gmul(s1,3) ^ s2 ^ s3;
            s[1+4*c] = s0 ^ esp32c3_aes_gmul(s1,2) ^ esp32c3_aes_gmul(s2,3) ^ s3;
            s[2+4*c] = s0 ^ s1 ^ esp32c3_aes_gmul(s2,2) ^ esp32c3_aes_gmul(s3,3);
            s[3+4*c] = esp32c3_aes_gmul(s0,3) ^ s1 ^ s2 ^ esp32c3_aes_gmul(s3,2);
        } else {
            s[0+4*c] = esp32c3_aes_gmul(s0,14) ^ esp32c3_aes_gmul(s1,11) ^ esp32c3_aes_gmul(s2,13) ^ esp32c3_aes_gmul(s3,9);
            s[1+4*c] = esp32c3_aes_gmul(s0,9)  ^ esp32c3_aes_gmul(s1,14) ^ esp32c3_aes_gmul(s2,11) ^ esp32c3_aes_gmul(s3,13);
            s[2+4*c] = esp32c3_aes_gmul(s0,13) ^ esp32c3_aes_gmul(s1,9)  ^ esp32c3_aes_gmul(s2,14) ^ esp32c3_aes_gmul(s3,11);
            s[3+4*c] = esp32c3_aes_gmul(s0,11) ^ esp32c3_aes_gmul(s1,13) ^ esp32c3_aes_gmul(s2,9)  ^ esp32c3_aes_gmul(s3,14);
        }
    }
}

static void esp32c3_aes_block(const uint8_t *in, const uint8_t *key, int Nk,
                               int decrypt, uint8_t *out)
{
    int Nr = Nk + 6;
    /* Max AES-256: 4*(4*(14+1)) = 240 bytes. Use fixed buffer — WASM VLAs
     * corrupt the stack when the VLA is large. */
    uint8_t w[240];
    uint8_t s[16];
    esp32c3_aes_keyexp(key, Nk, w);
    memcpy(s, in, 16);
    if (!decrypt) {
        for (int r = 0; r < Nr; r++) {
            for (int i = 0; i < 16; i++) s[i] ^= w[r*16 + i];
            for (int i = 0; i < 16; i++) s[i] = esp32c3_aes_sbox[s[i]];
            uint8_t t;
            t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;
            t = s[2]; s[2] = s[10]; s[10] = t; t = s[6]; s[6] = s[14]; s[14] = t;
            t = s[3]; s[3] = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = t;
            if (r < Nr - 1) esp32c3_aes_mix(s, 0);
        }
        for (int i = 0; i < 16; i++) s[i] ^= w[Nr*16 + i];
    } else {
        /* AES decrypt: standard cipher inverse */
        for (int i = 0; i < 16; i++) s[i] ^= w[Nr*16 + i];
        for (int r = Nr - 1; r >= 1; r--) {
            uint8_t t;
            t = s[3]; s[3] = s[7]; s[7] = s[11]; s[11] = s[15]; s[15] = t;
            t = s[2]; s[2] = s[10]; s[10] = t; t = s[6]; s[6] = s[14]; s[14] = t;
            t = s[1]; s[1] = s[13]; s[13] = s[9]; s[9] = s[5]; s[5] = t;
            for (int i = 0; i < 16; i++) s[i] = esp32c3_aes_inv_sbox[s[i]];
            for (int i = 0; i < 16; i++) s[i] ^= w[r*16 + i];
            esp32c3_aes_mix(s, 1);
        }
        /* final round: no InvMixColumns */
        uint8_t t;
        t = s[3]; s[3] = s[7]; s[7] = s[11]; s[11] = s[15]; s[15] = t;
        t = s[2]; s[2] = s[10]; s[10] = t; t = s[6]; s[6] = s[14]; s[14] = t;
        t = s[1]; s[1] = s[13]; s[13] = s[9]; s[9] = s[5]; s[5] = t;
        for (int i = 0; i < 16; i++) s[i] = esp32c3_aes_inv_sbox[s[i]];
        for (int i = 0; i < 16; i++) s[i] ^= w[i];
    }
    memcpy(out, s, 16);
}

/* Emulate one AES block operation triggered by a write to AES_TRIGGER_REG. */
/* Run `nblocks` 16-byte AES blocks from `in` to `out`, honouring the
 * key/mode/block-mode registers in soc->aes_reg. CBC chaining (when
 * selected) advances the IV stored in the IV registers. */
static void esp32c3_aes_process_buf(esp32c3_t *soc, const uint8_t *in,
                                    uint8_t *out, int nblocks)
{
    uint32_t mode = soc->aes_reg[0x40u >> 2];
    int decrypt = (mode & 0x4u) ? 1 : 0;
    int key_bytes = ((mode & 0x3u) + 2) * 8;
    int Nk = key_bytes / 4;
    int blk = soc->aes_reg[0x94u >> 2] & 0xF;   /* 0=ECB, 1=CBC, ... */
    uint8_t key[32], iv[16];
    for (int i = 0; i < key_bytes; i++)
        key[i] = (uint8_t)(soc->aes_reg[(0x00u + (i & ~3u)) >> 2] >> (8 * (i & 3)));
    for (int i = 0; i < 16; i++)
        iv[i] = (uint8_t)(soc->aes_reg[(0x50u + (i & ~3u)) >> 2] >> (8 * (i & 3)));
    for (int b = 0; b < nblocks; b++) {
        const uint8_t *pin = in + 16 * b;
        uint8_t *pout = out + 16 * b;
        if (blk == 1) { /* CBC */
            uint8_t x[16];
            if (!decrypt) {
                for (int i = 0; i < 16; i++) x[i] = (uint8_t)(pin[i] ^ iv[i]);
                esp32c3_aes_block(x, key, Nk, 0, pout);
                for (int i = 0; i < 16; i++) iv[i] = pout[i];
            } else {
                esp32c3_aes_block(pin, key, Nk, 1, pout);
                for (int i = 0; i < 16; i++) {
                    pout[i] = (uint8_t)(pout[i] ^ iv[i]);
                    iv[i] = pin[i];
                }
            }
        } else { /* ECB (and other modes fall back to ECB here) */
            esp32c3_aes_block(pin, key, Nk, decrypt, pout);
        }
    }
    if (blk == 1) /* write back updated CBC IV */
        for (int i = 0; i < 16; i++)
            soc->aes_reg[(0x50u + (i & ~3u)) >> 2] =
                (soc->aes_reg[(0x50u + (i & ~3u)) >> 2] & ~(0xFFu << (8 * (i & 3)))) |
                ((uint32_t) iv[i] << (8 * (i & 3)));
}

/* Process one block through the DMA descriptor pair for a given channel.
 * Reads plaintext from the OUT descriptor, encrypts/decrypts, and writes
 * the result to the IN descriptor.  Used by the AES TRIGGER path when the
 * esp_aes driver feeds data via GDMA instead of the TEXT_IN registers. */
static void esp32c3_aes_run_dma(esp32c3_t *soc, int ch_out)
{
    int ch_in = -1;
    for (int ch = 0; ch < 3; ch++)
        if (soc->gdma_in_peri_sel[ch] == C3_GDMA_PERI_AES)
            ch_in = ch;

    uint32_t in_cur = C3_GDMA_MEM_BASE + (soc->gdma_out_link[ch_out] & GDMA_LINK_ADDR_MASK);
    uint32_t out_cur = ch_in >= 0 ? (C3_GDMA_MEM_BASE + (soc->gdma_in_link[ch_in] & GDMA_LINK_ADDR_MASK)) : 0;

    for (int blk = 0; blk < 1; blk++) {
        if (!in_cur || !out_cur) break;
        uint8_t *id = esp32c3_dma_ptr(soc, in_cur);
        if (!id) break;
        uint32_t dw0, dw1, dw2;
        memcpy(&dw0, id, 4); memcpy(&dw1, id + 4, 4); memcpy(&dw2, id + 8, 4);
        /* Always process: don't check owner bit.  The driver sets up
         * descriptors each time and the buffer pointer is valid. */
        uint32_t in_buf = dw1;
        uint32_t in_len = (dw0 >> 12) & 0xFFFu;
        if (in_len < 16) break;
        uint8_t in[16];
        for (int i = 0; i < 16; i++) {
            uint8_t *p = esp32c3_dma_ptr(soc, in_buf + i);
            if (p) in[i] = *p;
        }
        uint8_t out[16];
        esp32c3_aes_process_buf(soc, in, out, 1);
        uint8_t *od = esp32c3_dma_ptr(soc, out_cur);
        if (!od) break;
        memcpy(&dw0, od, 4); memcpy(&dw1, od + 4, 4); memcpy(&dw2, od + 8, 4);
        uint32_t out_buf = dw1;
        uint32_t out_len = (dw0 >> 12) & 0xFFFu;
        if (out_len >= 16) {
            for (int i = 0; i < 16; i++) {
                uint8_t *p = esp32c3_dma_ptr(soc, out_buf + i);
                if (p) *p = out[i];
            }
        }
        /* Clear owner bits (mark descriptors as SW-owned) */
        uint32_t v;
        memcpy(&v, id, 4); v &= ~(1u << 31); memcpy(id, &v, 4);
        memcpy(&v, od, 4); v &= ~(1u << 31); memcpy(od, &v, 4);
        in_cur = dw2;
        out_cur = dw2;
    }
}

/* Trigger path: one block written through the TEXT_IN/TEXT_OUT registers
 * or via GDMA descriptors when the esp_aes driver uses DMA. */
static void esp32c3_aes_run(esp32c3_t *soc)
{
    uint8_t in[16], out[16];
    for (int i = 0; i < 16; i++)
        in[i] = (uint8_t)(soc->aes_reg[(0x20u + (i & ~3u)) >> 2] >> (8 * (i & 3)));
    esp32c3_aes_process_buf(soc, in, out, 1);
    for (int i = 0; i < 16; i++)
        soc->aes_reg[(0x30u + (i & ~3u)) >> 2] =
            (soc->aes_reg[(0x30u + (i & ~3u)) >> 2] & ~(0xFFu << (8 * (i & 3)))) |
            ((uint32_t) out[i] << (8 * (i & 3)));
}

/* MWDT expiry, in emulator cycles: the C3 WDT clock is ~40MHz while the guest
 * cycle clock is ~80MHz, so multiply by 2 as an approximation. */
static uint64_t esp32c3_wdt_cycles(esp32c3_t *soc, int g)
{
    uint32_t prescale =
        (soc->timg_reg[g][TIMG_WDT_CONFIG1 >> 2] >> 16) & 0xFFFFu;
    uint32_t hold = soc->timg_reg[g][TIMG_WDT_CONFIG2 >> 2];
    if (!hold)
        hold = 1u;
    return (uint64_t) hold * (uint64_t) (prescale + 1u) * 2u;
}

/* Detect input edges on GPIO pins and latch the interrupt status; the driver
 * ISR reads GPIO_STATUS and clears it via GPIO_STATUS_W1TC. */
static void esp32c3_gpio_edge_check(esp32c3_t *soc, uint32_t *mmio32,
                                    uint32_t new_live)
{
    uint32_t changed = new_live ^ soc->gpio_in_prev;
    if (!changed)
        return;
    for (int pin = 0; pin < 22; pin++) {
        if (!(changed & (1u << pin)))
            continue;
        uint32_t pr = mmio32[(0x4074u + 4u * pin) >> 2];
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
            soc->intc_status |= ((unsigned __int128) 1) << C3_GPIO_INTR_SOURCE;
        }
    }
}


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

/* RMT (LEDC-less RGB LED uses it on C3): base offset from C3_PERIPH_BASE.
 * DR_REG_RMT_BASE = 0x60016000; the driver's IRQ comes from
 * rmt_periph_signals[0].irq = 28 (NOT the ETS_RMT_INTR_SOURCE enum value). */
#define C3_RMT_BASE 0x16000u
#define C3_RMT_INTR_SOURCE 28u

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

    /* AES accelerator (0x6003A000): registers including computed TEXT_OUT;
     * AES_STATE_REG stays 0 (idle) so the driver's done-poll succeeds. */
    if (addr >= C3_AES_BASE && addr < C3_AES_BASE + C3_AES_SIZE) {
        uint32_t a = addr - C3_AES_BASE;
        if (a == 0xacu)
            fprintf(stderr, "DBG: aes int_raw rd =0x%08x ena=0x%08x\n",
                    soc->aes_reg[a >> 2], soc->aes_reg[0xb0u >> 2]);
        return soc->aes_reg[a >> 2];
    }

    /* I2S0 (0x6002D000): configuration registers.
     * The LL driver reads back config registers it wrote, plus interrupt
     * status and the DATE version register.  All reads just return the
     * stored value except the ones with special behaviour below. */
    if (addr >= C3_I2S0_BASE && addr < C3_I2S0_BASE + C3_I2S0_SIZE) {
        uint32_t o = addr - C3_I2S0_BASE;
        uint32_t rv;
        switch (o) {
        case 0x10u: /* INT_ST = raw & ena */
            rv = soc->i2s_reg[0x0Cu >> 2] & soc->i2s_reg[0x14u >> 2];
            break;
        case 0x6Cu: /* STATE: bit 0 = tx_idle (1 when TX not active) */
            rv = 1u;
            break;
        case 0x80u: /* DATE register — return non-zero so driver init succeeds */
            rv = 0x26062022u;
            break;
        default:
            rv = soc->i2s_reg[o >> 2];
            break;
        }
        return rv;
    }

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

    /* UART0/1 (0x60000000 / 0x60010000) */
    for (int p = 0; p < 2; p++) {
        uint32_t base = C3_PERIPH_BASE + 0x10000u * p;
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
            case UART_STATUS_REG:
                /* RXFIFO_CNT [5:0]; TX side left at 0 (always room) */
                return (soc->uart_rx_head[p] - soc->uart_rx_tail[p]) &
                       (UART_RX_FIFO_SZ - 1u);
            case UART_INT_ST_REG:
                return mmio32[(base + UART_INT_RAW_REG - C3_PERIPH_BASE) >> 2] &
                       mmio32[(base + UART_INT_ENA_REG - C3_PERIPH_BASE) >> 2];
            case UART_CLKDIV_CONF_REG:
                /* the divider sync completes instantly in the model */
                return mmio32[off >> 2] & ~0x1u;
            default:
                return mmio32[off >> 2];
            }
        }
    }
    /* I2C_EXT (0x60013000-0x60013200) */
    if (addr >= C3_PERIPH_BASE + 0x13000u &&
        addr < C3_PERIPH_BASE + 0x13200u) {
        uint32_t *r = soc->i2c_reg + ((addr - C3_PERIPH_BASE - 0x13000u) >> 2);
        if (addr == C3_PERIPH_BASE + 0x13080u && soc->i2c_scl_rst_cnt > 0 &&
            --soc->i2c_scl_rst_cnt == 0)
            *r &= ~1u; /* SCL_RST_SLV_EN self-clears after the pulses */
        if (addr == C3_PERIPH_BASE + 0x1302cu) {
            uint32_t v = soc->i2c_reg[0x20 >> 2] & soc->i2c_reg[0x28 >> 2];
            return v;
        }
        if (addr == C3_PERIPH_BASE + 0x1301cu) { /* data: RX fifo pop */
             if (soc->i2c_rx_pos < soc->i2c_rx_len) {
                uint32_t v = soc->i2c_rx_fifo[soc->i2c_rx_pos++];
                soc->i2c_reg[0x1c >> 2] = v;
            }
        }
        return *r;
    }
    /* SPI2 (GPSPI2, 0x60024000-0x60024100) */
    if (addr >= C3_PERIPH_BASE + 0x24000u &&
        addr < C3_PERIPH_BASE + 0x24100u) {
        uint32_t *r = soc->spi2_reg + ((addr - C3_PERIPH_BASE - 0x24000u) >> 2);
        if (addr == C3_PERIPH_BASE + 0x2403cu) /* dma_int_raw = raw & ena */
            return soc->spi2_reg[0x3c >> 2] &
                   soc->spi2_reg[0x38u >> 2];
        return *r;
    }
    /* TWAI0 (CAN, 0x6002B000-0x6002B100) */
    if (addr >= C3_PERIPH_BASE + 0x2B000u &&
        addr < C3_PERIPH_BASE + 0x2B100u) {
        uint32_t off = addr - C3_PERIPH_BASE - 0x2B000u;
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
            if ((soc->twai_reg[0x08 >> 2] & TWAI0_STATUS_RBS) &&
                (soc->twai_reg[0x10 >> 2] & TWAI0_INTR_RI))
                soc->twai_reg[0x0c >> 2] = TWAI0_INTR_RI;
            if (!soc->twai_reg[0x0c >> 2])
                soc->intc_status &= ~((unsigned __int128) 1) << C3_TWAI_INTR_SOURCE;
            return v;
        }
        return soc->twai_reg[off >> 2];
    }
    /* GDMA (0x6003F000-0x6003F2B0): per-channel INT + IN/OUT blocks */
    if (addr >= C3_GDMA_BASE && addr < C3_GDMA_BASE + C3_GDMA_SIZE) {
        uint32_t o = addr - C3_GDMA_BASE;
        if (o < 3u * GDMA_CHAN_INT_STRIDE) { /* channel INT registers */
            uint32_t ch = o >> 4;
            switch (o & 0xFu) {
            case 0x00: return soc->gdma_int_raw[ch];
            case 0x04: return soc->gdma_int_raw[ch] & soc->gdma_int_ena[ch];
            case 0x08: return soc->gdma_int_ena[ch];
            default:   return 0; /* clr is write-only */
            }
        }
        if (o < 0x70u)
            return 0; /* reserved gap */
        uint32_t c = (o - 0x70u) / GDMA_CHAN_BLK_STRIDE;
        uint32_t r = o - 0x70u - c * GDMA_CHAN_BLK_STRIDE;
        if (r < 0x60u) { /* IN block */
            switch (r) {
            case 0x00: return soc->gdma_in_conf0[c];
            case 0x04: return soc->gdma_in_conf1[c];
            case 0x08: return 0x02u; /* INFIFO_STATUS: empty (bit1=1) */
            case 0x0C: return 0;    /* IN_POP: pop trigger, return 0 */
            case 0x10: return soc->gdma_in_link[c];
            case 0x14: return soc->gdma_in_run[c] ? 0x08000000u : 0; /* state */
            case 0x18: return soc->gdma_in_eof_des[c]; /* suc_eof des addr */
            case 0x20: return soc->gdma_in_dscr[c];
            case 0x24: return soc->gdma_in_desc_buf[c]; /* dscr_bf0 */
            case 0x30: return soc->gdma_in_peri_sel[c];
            default:   return 0;
            }
        } else { /* OUT block (r >= 0x60) */
            uint32_t r2 = r - 0x60u;
            switch (r2) {
            case 0x00: return soc->gdma_out_conf0[c];
            case 0x04: return soc->gdma_out_conf1[c];
            case 0x08: return 0x02u; /* OUTFIFO_STATUS: empty (bit1=1) */
            case 0x0C: return 0;    /* OUT_PUSH: push trigger */
            case 0x10: return soc->gdma_out_link[c];
            case 0x14: return soc->gdma_out_run[c] ? 0x08000000u : 0; /* state */
            case 0x18: return soc->gdma_out_eof_des[c]; /* eof des addr */
            case 0x20: return soc->gdma_out_dscr[c];
            case 0x24: return soc->gdma_out_desc_buf[c]; /* dscr_bf0 */
            case 0x30: return soc->gdma_out_peri_sel[c];
            default:   return 0;
            }
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
            /* strapping: GPIO9 high -> SPI flash boot; plus live input */
            return (1u << 9) | soc->gpio_in |
                   esp32c3_gpio_eff_out(soc, mmio32);
        case GPIO_STRAP_REG:
            /* GPIO9 strapped high: boot mode 1xxx (SPI flash boot) */
            return (1u << 9) | 0x8u;
        case GPIO_STATUS_REG:
            return soc->gpio_status;
        case GPIO_PCPU_INT_REG:
            return soc->gpio_status;
        default:
            return mmio32[off >> 2];
        }
    }
    /* SAR_ADC (0x60040000-0x60040404): oneshot conversion state */
    if (addr >= C3_PERIPH_BASE + 0x40000u &&
        addr < C3_PERIPH_BASE + 0x40404u) {
        uint32_t o = off - 0x40000u;
        if (o == ADC_DATA1)            /* sar1data_status: raw result */
            return soc->adc_reg[o >> 2];
        if (o == ADC_DATA2)
            return soc->adc_reg[o >> 2];
        if (o == ADC_TSENS_CTRL)       /* 8-bit sensor output field is RO */
            return (soc->adc_reg[o >> 2] & ~0xFFu) | 0x78u;
        if (o == ADC_INT_RAW)
            return soc->adc_reg[o >> 2];
        if (o == ADC_INT_ENA)
            return soc->adc_reg[o >> 2];
        if (o == 0x48u)               /* int_st = raw & ena */
            return soc->adc_reg[ADC_INT_RAW >> 2] &
                   soc->adc_reg[ADC_INT_ENA >> 2];
        if (o == 0x400u)              /* version */
            return 0x02206840u;
        return soc->adc_reg[o >> 2];
    }
    /* LEDC (0x60019000-0x60019200) */
    if (addr >= C3_PERIPH_BASE + 0x19000u &&
        addr < C3_PERIPH_BASE + 0x19200u) {
        uint32_t o = addr - C3_PERIPH_BASE - 0x19000u;
        for (int c = 0; c < 6; c++)
            if (o == LEDC_CH_DUTY_R(c))
                return soc->ledc_duty_r[c];
        for (int t = 0; t < 4; t++)
            if (o == LEDC_TIMER_VALUE(t))
                return soc->ledc_reg[o >> 2];
        if (o == LEDC_INT_ST_OFF)
            return soc->ledc_reg[LEDC_INT_RAW_OFF >> 2] &
                   soc->ledc_reg[LEDC_INT_ENA_OFF >> 2];
        if (o == LEDC_INT_RAW_OFF)
            return soc->ledc_reg[o >> 2];
        return soc->ledc_reg[o >> 2];
    }
    /* TIMG0/1 (0x6001F000, 0x60020000): one timer + WDT per group */
    for (int g = 0; g < 2; g++) {
        uint32_t base = (g == 0) ? 0x1F000u : 0x20000u;
        if (addr >= C3_PERIPH_BASE + base &&
            addr < C3_PERIPH_BASE + base + 0x100u) {
            uint32_t o = addr - C3_PERIPH_BASE - base;
            if (o == TIMG_T0LO)
                return (uint32_t) soc->timg_counter[g];
            if (o == TIMG_T0HI)
                return (uint32_t) (soc->timg_counter[g] >> 32);
            if (o == TIMG_INT_ST)
                return soc->timg_reg[g][TIMG_INT_RAW >> 2] &
                       soc->timg_reg[g][TIMG_INT_ENA >> 2];
            return soc->timg_reg[g][o >> 2];
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
    /* RMT (0x60016000) */
    if (addr >= C3_PERIPH_BASE + C3_RMT_BASE &&
        addr < C3_PERIPH_BASE + C3_RMT_BASE + 0x1000u) {
        uint32_t roff = addr - (C3_PERIPH_BASE + C3_RMT_BASE);
        if (roff == 0x3Cu) /* INT_ST = INT_RAW & INT_ENA */
            return mmio32[(C3_RMT_BASE + 0x38u) >> 2] &
                   mmio32[(C3_RMT_BASE + 0x40u) >> 2];
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
            case SYSTIMER_INT_CLR:
                return 0; /* WT, reads as 0 */
            case 0x70u: /* INT_ST = INT_RAW & INT_ENA */
                return soc->systimer_int_raw & soc->systimer_int_ena;
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
        if (o < 52u * 4u)
            return soc->intc_intmap[o >> 2];
        switch (o) {
        case INTC_INTR_STATUS:
            return (uint32_t) soc->intc_status; /* raw pending sources 0-31 */
        case INTC_INTR_STATUS_1:
            return (uint32_t) (soc->intc_status >> 32); /* sources 32-63 */
        case 0x08u:
            return (uint32_t) (soc->intc_status >> 64); /* sources 64-95 */
        case 0x0Cu:
            return (uint32_t) (soc->intc_status >> 96); /* sources 96-127 */
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
            if (0) {
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
        /* UHCI0 (0x60014000): stub - return 0 for status reads */
        if (addr >= C3_PERIPH_BASE + 0x14000u &&
            addr < C3_PERIPH_BASE + 0x15000u) {
            if (addr == C3_PERIPH_BASE + 0x140E8u)
                return 0x02000000u; /* UHCI_STATE: idle */
            return 0;
        }
        /* RSA accelerator (0x6003C000): stub */
        if (addr >= C3_PERIPH_BASE + 0x3C000u &&
            addr < C3_PERIPH_BASE + 0x3D000u)
            return 0;
        /* Digital Signature (0x6003D000): stub */
        if (addr >= C3_PERIPH_BASE + 0x3D000u &&
            addr < C3_PERIPH_BASE + 0x3E000u)
            return 0;
        /* HMAC (0x6003E000): stub */
        if (addr >= C3_PERIPH_BASE + 0x3E000u &&
            addr < C3_PERIPH_BASE + 0x3F000u)
            return 0;
        /* USB-Serial JTAG (0x60043000): stub with DATE register */
        if (addr >= C3_PERIPH_BASE + 0x43000u &&
            addr < C3_PERIPH_BASE + 0x44000u) {
            if (addr == C3_PERIPH_BASE + 0x43080u)
                return 0xFFFFFFFFu; /* USB_SERIAL_JTAG_DATE */
            return 0;
        }
        /* XTS-AES (0x600CC000): stub with DATE register */
        if (addr >= C3_PERIPH_BASE + 0xCC000u &&
            addr < C3_PERIPH_BASE + 0xCD000u) {
            if (addr == C3_PERIPH_BASE + 0xCC05Cu)
                return 0x3FFFFFFFu; /* XTS_AES_DATE */
            return 0;
        }
        /* Assist Debug (0x600CE000): stub with DATE register */
        if (addr >= C3_PERIPH_BASE + 0xCE000u &&
            addr < C3_PERIPH_BASE + 0xCF000u) {
            if (addr == C3_PERIPH_BASE + 0xCE1FCu)
                return 0x0FFFFFFFu; /* ASSIST_DEBUG_DATE */
            return 0;
        }
        /* Dedicated GPIO (0x600CF000): stub */
        if (addr >= C3_PERIPH_BASE + 0xCF000u &&
            addr < C3_PERIPH_BASE + 0xD0000u)
            return 0;
        /* World Controller (0x600D0000): stub */
        if (addr >= C3_PERIPH_BASE + 0xD0000u &&
            addr < C3_PERIPH_BASE + 0xD1000u)
            return 0;
        /* Sensitive/PMS (0x600C1000): stub */
        if (addr >= C3_PERIPH_BASE + 0xC1000u &&
            addr < C3_PERIPH_BASE + 0xC2000u)
            return 0;
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

    /* AES accelerator (0x6003A000): store registers; a TRIGGER write runs
     * the block op and writes the result into the TEXT_OUT registers. The
     * guest polls AES_STATE_REG until it reads DONE (2); config writes reset
     * it to IDLE (0) so a pre-trigger idle wait also succeeds. */
    if (addr >= C3_AES_BASE && addr < C3_AES_BASE + C3_AES_SIZE) {
        uint32_t a = addr - C3_AES_BASE;
        if (a == 0xacu) { /* AES_INT_CLR: write-1-to-clear */
            soc->aes_reg[a >> 2] &= ~val;
            return;
        }
        if (a == 0xb0u) { /* AES_INT_ENA */
            soc->aes_reg[a >> 2] = val;
            return;
        }
        soc->aes_reg[a >> 2] = val;
        if (a == 0x48u) { /* AES_TRIGGER_REG */
            /* Detect DMA mode: if any GDMA OUT channel has AES peri_sel,
             * the esp_aes driver feeds data via GDMA descriptors.  Read
             * directly from the descriptor chain and write the result back
             * to the IN descriptor. */
            int dma_ch = -1;
            for (int ch = 0; ch < 3; ch++) {
                if (soc->gdma_out_peri_sel[ch] == C3_GDMA_PERI_AES) {
                    dma_ch = ch;
                    break;
                }
            }
            if (dma_ch >= 0) {
                esp32c3_aes_run_dma(soc, dma_ch);
                /* Cancel any pending m2m walker so it doesn't overwrite
                 * the AES result in the IN descriptor buffer. */
                soc->gdma_m2m_pending[dma_ch] = 0;
                soc->gdma_out_run[dma_ch] = 0;
                soc->gdma_in_run[dma_ch] = 0;
            } else {
                esp32c3_aes_run(soc);
            }
            soc->aes_reg[0x4cu >> 2] = 2u; /* ESP_AES_STATE_DONE */
        } else {
            soc->aes_reg[0x4cu >> 2] = 0u; /* IDLE */
        }
        return;
    }

    /* I2S0 (0x6002D000): store all configuration writes.
     * INT_CLR (0x18) is write-1-to-clear.
     * rx_update (bit 8 of 0x20) and tx_update (bit 8 of 0x24) are
     * self-clearing: the LL driver polls them until HW clears them. */
    if (addr >= C3_I2S0_BASE && addr < C3_I2S0_BASE + C3_I2S0_SIZE) {
        uint32_t o = addr - C3_I2S0_BASE;
        if (o == 0x18u) { /* INT_CLR: W1C */
            soc->i2s_reg[0x0Cu >> 2] &= ~val; /* clear raw */
            return;
        }
        soc->i2s_reg[o >> 2] = val;
        /* Auto-clear self-clearing update bits */
        if (o == 0x20u) /* RX_CONF: clear rx_update (bit 8) */
            soc->i2s_reg[0x20u >> 2] &= ~(1u << 8);
        if (o == 0x24u) /* TX_CONF: clear tx_update (bit 8) */
            soc->i2s_reg[0x24u >> 2] &= ~(1u << 8);
        return;
    }

    /* UART0/1 (0x60000000 / 0x60010000) */
    for (int p = 0; p < 2; p++) {
        uint32_t base = C3_PERIPH_BASE + 0x10000u * p;
        if (addr >= base && addr < base + 0x1000u) {
            uint32_t o = addr - base;
            if (o == UART_FIFO_REG) {
                uint8_t b = (uint8_t) (val & 0xFFu);
                if (p == 0)
                    esp32_uart_putc(soc, (char) b);
                if (soc->uart_tx_cnt[p] < UART_RX_FIFO_SZ)
                    soc->uart_tx_cnt[p]++;
                soc->uart_tx_idle[p] = 0;
                /* TX->RX loopback (CONF0 bit 14) feeds this port's RX FIFO
                 * so a sketch can send and receive on the same UART */
                if (mmio32[(base + UART_CONF0_REG - C3_PERIPH_BASE) >> 2] &
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
                                     C3_PERIPH_BASE) >> 2];
                        uint32_t *ena =
                            &mmio32[(base + UART_INT_ENA_REG -
                                     C3_PERIPH_BASE) >> 2];
                        *raw |= (UART_RXFIFO_TOUT_BIT | 0x1u);
                        if (*ena & (UART_RXFIFO_TOUT_BIT | 0x1u)) {
                            int src = (p == 0) ? C3_UART0_INTR_SOURCE
                                               : C3_UART1_INTR_SOURCE;
                            soc->intc_status |= ((unsigned __int128) 1) << src;
                        }
                    }
                }
            } else if (o == UART_INT_ENA_REG) {
                mmio32[off >> 2] = val;
                /* when the TX-empty interrupt is enabled, raise it so the
                 * esp-idf TX ISR feeds the TX FIFO from its ring buffer */
                if (val & UART_TXFIFO_EMPTY_BIT) {
                    uint32_t *raw =
                        &mmio32[(base + UART_INT_RAW_REG -
                                 C3_PERIPH_BASE) >> 2];
                    *raw |= UART_TXFIFO_EMPTY_BIT;
                    int src = (p == 0) ? C3_UART0_INTR_SOURCE
                                       : C3_UART1_INTR_SOURCE;
                    soc->intc_status |= ((unsigned __int128) 1) << src;
                }
            } else if (o == UART_INT_CLR_REG) { /* W1C */
                uint32_t *raw =
                    &mmio32[(base + UART_INT_RAW_REG - C3_PERIPH_BASE) >> 2];
                *raw &= ~val;
                if (!(*raw & (UART_RXFIFO_TOUT_BIT | 0x1u |
                              UART_TXFIFO_EMPTY_BIT))) {
                    int src = (p == 0) ? C3_UART0_INTR_SOURCE
                                       : C3_UART1_INTR_SOURCE;
                    soc->intc_status &= ~(((unsigned __int128) 1) << src);
                }
            } else if (o == UART_CONF0_REG) {
                mmio32[off >> 2] = val;
            } else
                mmio32[off >> 2] = val;
            return;
        }
    }
    /* I2C_EXT (0x60013000-0x60013200) */
    if (addr >= C3_PERIPH_BASE + 0x13000u &&
        addr < C3_PERIPH_BASE + 0x13200u) {
        uint32_t *r = soc->i2c_reg + ((addr - C3_PERIPH_BASE - 0x13000u) >> 2);
        if (addr == C3_PERIPH_BASE + 0x13024u) { /* int_clr */
            soc->i2c_reg[0x20 >> 2] &= ~val; /* clear raw status bits */
            soc->intc_status &=
                ~(((unsigned __int128) 1) << C3_I2C_EXT0_INTR_SOURCE); /* drop IRQ */
        } else if (addr == C3_PERIPH_BASE + 0x13018u) { /* fifo_conf */
            soc->i2c_reg[0x18 >> 2] = val;
            if (val & (1u << 13)) /* tx_fifo_rst */
                soc->i2c_tx_len = 0;
            if (val & (1u << 12)) { /* rx_fifo_rst */
                soc->i2c_rx_len = 0;
                soc->i2c_rx_pos = 0;
            }
        } else if (addr == C3_PERIPH_BASE + 0x1301cu) { /* data: TX fifo push */
            soc->i2c_reg[0x1c >> 2] = val;
            if (soc->i2c_tx_len < 32)
                soc->i2c_tx_fifo[soc->i2c_tx_len++] = val & 0xFFu;
        } else if (addr == C3_PERIPH_BASE + 0x13004u) { /* ctr */
            *r = val;
            if (val & (1u << 5)) { /* trans_start (WT): transfer begins */
                uint32_t addr_byte = soc->i2c_tx_len > 0 ?
                                     soc->i2c_tx_fifo[0] : 0xFFu;
                soc->i2c_transfer_pending = 1;
                if ((addr_byte >> 1) == C3_I2C_DEV_ADDR) {
                    soc->i2c_slave_active = 1;
                    soc->i2c_slave_rw = addr_byte & 1u;
                } else {
                    soc->i2c_slave_active = 0;
                }
            }
        } else {
            *r = val;
        }
        if (addr == C3_PERIPH_BASE + 0x13080u) {
            if (val & 1u) /* SCL_RST_SLV_EN: start the reset pulses */
                soc->i2c_scl_rst_cnt = 64; /* held high ~64 reads */
            else
                soc->i2c_scl_rst_cnt = 0;
        }
        return;
    }
    /* SPI2 (GPSPI2, 0x60024000-0x60024100) */
    if (addr >= C3_PERIPH_BASE + 0x24000u &&
        addr < C3_PERIPH_BASE + 0x24100u) {
        uint32_t *r = soc->spi2_reg + ((addr - C3_PERIPH_BASE - 0x24000u) >> 2);
        if (addr == C3_PERIPH_BASE + 0x24000u) { /* cmd */
            *r = val & ~(1u << 23); /* update self-clears: config applied */
            if (val & (1u << 24))   /* usr: transfer begins */
                soc->spi2_transfer_pending = 1;
        } else if (addr == C3_PERIPH_BASE + 0x24038u) { /* dma_int_clr */
            soc->spi2_reg[0x3c >> 2] &= ~val; /* clear raw interrupt bits */
        } else {
            *r = val;
        }
        return;
    }
    /* TWAI0 (CAN, 0x6002B000-0x6002B100) */
    if (addr >= C3_PERIPH_BASE + 0x2B000u &&
        addr < C3_PERIPH_BASE + 0x2B100u) {
        uint32_t off = addr - C3_PERIPH_BASE - 0x2B000u;
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
    /* GDMA (0x6003F000-0x6003F2B0) */
    if (addr >= C3_GDMA_BASE && addr < C3_GDMA_BASE + C3_GDMA_SIZE) {
        uint32_t o = addr - C3_GDMA_BASE;
        if (o < 3u * GDMA_CHAN_INT_STRIDE) { /* channel INT registers */
            uint32_t ch = o >> 4;
            if ((o & 0xFu) == 0x08u) { /* ena */
                soc->gdma_int_ena[ch] = val;
                /* Re-check pending interrupts: if raw bits are set and now
                 * enabled, deliver the INTC line immediately. */
                if (soc->gdma_int_raw[ch] & soc->gdma_int_ena[ch])
                    soc->intc_status |= ((unsigned __int128) 1) << (C3_DMA_CH0_INTR_SOURCE + ch);
            } else if ((o & 0xFu) == 0x0Cu) { /* clr: W1C */
                soc->gdma_int_raw[ch] &= ~val;
                if (!(soc->gdma_int_raw[ch] & soc->gdma_int_ena[ch]))
                    soc->intc_status &=
                        ~((unsigned __int128) 1) << (C3_DMA_CH0_INTR_SOURCE + ch);
            }
            return;
        }
        if (o < 0x70u)
            return; /* reserved gap */
        uint32_t c = (o - 0x70u) / GDMA_CHAN_BLK_STRIDE;
        uint32_t r = o - 0x70u - c * GDMA_CHAN_BLK_STRIDE;
        if (r < 0x60u) { /* IN block */
            switch (r) {
            case 0x00: /* in_conf0 */
                soc->gdma_in_conf0[c] = val & ~1u; /* in_rst is WT */
                if (val & 1u) { /* reset the walker */
                    soc->gdma_in_run[c] = 0;
                    soc->gdma_in_dscr[c] = 0;
                }
                return;
            case 0x04: soc->gdma_in_conf1[c] = val; return;
            case 0x10: /* in_link */
                soc->gdma_in_link[c] = val & ~0xF00000u;
                if (val & (1u << GDMA_INLINK_START_BIT)) {
                    soc->gdma_in_dscr[c] =
                        C3_GDMA_MEM_BASE + (soc->gdma_in_link[c] &
                                        GDMA_LINK_ADDR_MASK);
                    if (esp32c3_gdma_load_desc(soc, soc->gdma_in_dscr[c],
                            &soc->gdma_in_desc_buf[c],
                            &soc->gdma_in_desc_len[c],
                            &soc->gdma_in_next_addr[c]))
                        soc->gdma_in_run[c] = 1;
                    soc->gdma_in_conf0[c] &= ~(1u << 31); /* clear DMA-done */
                    soc->gdma_out_conf0[c] &= ~(1u << 31);
                    if (soc->gdma_out_run[c]) { /* mem2mem pair ready */
                        soc->gdma_m2m_pending[c] = 1;
                        soc->gdma_m2m_done_cycle[c] = rv->csr_cycle + 256u;
                    } else {
                        /* Unpaired peripheral DMA: schedule completion */
                        soc->gdma_m2m_pending[c] = 1;
                        soc->gdma_m2m_done_cycle[c] = rv->csr_cycle + 256u;
                    }
                } else if (val & (1u << GDMA_INLINK_STOP_BIT)) {
                    soc->gdma_in_run[c] = 0;
                }
                return;
            case 0x30: soc->gdma_in_peri_sel[c] = val; return;
            default: return;
            }
        } else { /* OUT block (r >= 0x60) */
            uint32_t r2 = r - 0x60u;
            switch (r2) {
            case 0x00: /* out_conf0 */
                soc->gdma_out_conf0[c] = val & ~1u; /* out_rst is WT */
                if (val & 1u) {
                    soc->gdma_out_run[c] = 0;
                    soc->gdma_out_dscr[c] = 0;
                }
                return;
            case 0x04: soc->gdma_out_conf1[c] = val; return;
            case 0x10: /* out_link */
                soc->gdma_out_link[c] = val & ~0x700000u;
                if (val & (1u << GDMA_OUTLINK_START_BIT)) {
                    soc->gdma_out_dscr[c] =
                        C3_GDMA_MEM_BASE + (soc->gdma_out_link[c] &
                                        GDMA_LINK_ADDR_MASK);
                    int ok = esp32c3_gdma_load_desc(soc, soc->gdma_out_dscr[c],
                            &soc->gdma_out_desc_buf[c],
                            &soc->gdma_out_desc_len[c],
                            &soc->gdma_out_next_addr[c]);
                    if (!ok) {
                        /* load failed — out_run stays 0 */
                    }
                    if (ok)
                        soc->gdma_out_run[c] = 1;
                    soc->gdma_in_conf0[c] &= ~(1u << 31); /* clear DMA-done */
                    soc->gdma_out_conf0[c] &= ~(1u << 31);
                    if (soc->gdma_in_run[c]) { /* mem2mem pair ready */
                        soc->gdma_m2m_pending[c] = 1;
                        soc->gdma_m2m_done_cycle[c] = rv->csr_cycle + 256u;
                    } else {
                        /* Unpaired peripheral DMA: schedule completion */
                        soc->gdma_m2m_pending[c] = 1;
                        soc->gdma_m2m_done_cycle[c] = rv->csr_cycle + 256u;
                    }
                } else if (val & (1u << GDMA_OUTLINK_STOP_BIT)) {
                    soc->gdma_out_run[c] = 0;
                }
                return;
            case 0x30: soc->gdma_out_peri_sel[c] = val; return;
            default: return;
            }
        }
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
        uint32_t o = off - 0x4000u;
        switch (o) {
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
            soc->intc_status |= ((unsigned __int128) 1) << C3_GPIO_INTR_SOURCE;
            return;
        case GPIO_STATUS_W1TC_REG:
            soc->gpio_status &= ~val;
            if (!soc->gpio_status)
                soc->intc_status &=
                    ~(((unsigned __int128) 1) << C3_GPIO_INTR_SOURCE);
            return;
        default:
            mmio32[off >> 2] = val;
            break;
        }
        uint32_t live = soc->gpio_in | esp32c3_gpio_eff_out(soc, mmio32);
        esp32c3_gpio_edge_check(soc, mmio32, live);
        soc->gpio_in_prev = live;
        if (esp32c3_gpio_output) {
            for (int pin = 0; pin < 22; pin++) {
                if (soc->gpio_enable & (1u << pin))
                    esp32c3_gpio_output(pin, !!(soc->gpio_out & (1u << pin)));
            }
        }
        return;
    }
    /* SAR_ADC (0x60040000-0x60040404) */
    if (addr >= C3_PERIPH_BASE + 0x40000u &&
        addr < C3_PERIPH_BASE + 0x40404u) {
        uint32_t o = off - 0x40000u;
        if (o == ADC_INT_CLR) {       /* int_clr: write-to-clear */
            soc->adc_reg[ADC_INT_RAW >> 2] &= ~val;
        } else {
            soc->adc_reg[o >> 2] = val;
            if (o == ADC_ONETIME_SAMPLE && (val & (1u << 29))) {
                /* onetime start: the conversion completes instantly. The
                 * selected converter (bit31=ADC1, bit30=ADC2) produces a done
                 * event; pin channels 0-7 read 1024 + ch*128, internal
                 * channels read mid-scale. */
                uint32_t ch = (val >> 25) & 0xFu;
                if (val & (1u << 31)) { /* sar1 sample */
                    soc->adc_reg[ADC_DATA1 >> 2] =
                        (ch < 8) ? 1024u + ch * 128u : 2048u;
                    soc->adc_reg[ADC_INT_RAW >> 2] |= 1u << 31; /* ADC1 done */
                }
                if (val & (1u << 30)) { /* sar2 sample */
                    soc->adc_reg[ADC_DATA2 >> 2] =
                        (ch < 8) ? 1024u + ch * 128u : 2048u;
                    soc->adc_reg[ADC_INT_RAW >> 2] |= 1u << 30; /* ADC2 done */
                }
            }
        }
        return;
    }
    /* LEDC (0x60019000-0x60019200) */
    if (addr >= C3_PERIPH_BASE + 0x19000u &&
        addr < C3_PERIPH_BASE + 0x19200u) {
        uint32_t o = addr - C3_PERIPH_BASE - 0x19000u;
        for (int c = 0; c < 6; c++) {
            if (o == LEDC_CH_CONF1(c)) {
                soc->ledc_reg[o >> 2] = val;
                if (val & LEDC_DUTY_START) {
                    soc->ledc_duty_r[c] =
                        soc->ledc_reg[LEDC_CH_DUTY(c) >> 2];
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
    /* TIMG0/1 (0x6001F000, 0x60020000) */
    for (int g = 0; g < 2; g++) {
        uint32_t base = (g == 0) ? 0x1F000u : 0x20000u;
        if (addr >= C3_PERIPH_BASE + base &&
            addr < C3_PERIPH_BASE + base + 0x100u) {
            uint32_t o = addr - C3_PERIPH_BASE - base;
            uint32_t *r = soc->timg_reg[g];
            if (o == TIMG_T0CONFIG) {
                soc->timg_anchor[g] = rv->csr_cycle;
                soc->timg_frac[g] = 0;
                r[o >> 2] = val & ~TIMG_T0_DIVCNT_RST;
            } else if (o == TIMG_T0LOAD) {
                soc->timg_counter[g] =
                    ((uint64_t) r[TIMG_T0LOADHI >> 2] << 32) |
                    r[TIMG_T0LOADLO >> 2];
                soc->timg_anchor[g] = rv->csr_cycle;
                soc->timg_frac[g] = 0;
                r[o >> 2] = 0;
            } else if (o == TIMG_T0UPDATE) {
                r[o >> 2] = 0;
            } else if (o == TIMG_INT_CLR) {
                r[TIMG_INT_RAW >> 2] &= ~val;
                if (!(r[TIMG_INT_RAW >> 2] & r[TIMG_INT_ENA >> 2]))
                    soc->intc_status &=
                        ~(((unsigned __int128) 1) << (g == 0 ? C3_TG0_T0_INTR_SOURCE
                                                   : C3_TG1_T0_INTR_SOURCE));
                r[o >> 2] = 0;
            } else if (o == TIMG_RTCCALICFG) {
                r[o >> 2] = val;
                if (val & 0x80000000u) {
                    uint32_t max = (val >> 16) & 0x7FFFu;
                    uint32_t clk_hz;
                    switch ((val >> 13) & 3u) {
                    case 0: clk_hz = 150000u; break;
                    case 1: clk_hz = 20000000u; break;
                    default: clk_hz = 32768u; break;
                    }
                    uint32_t count = (uint32_t) ((uint64_t) max * clk_hz
                                                 * 128u / 40000000u);
                    r[TIMG_RTCCALICFG1 >> 2] = count << 7;
                    r[o >> 2] |= 0x8000u;
                }
            } else if (o == TIMG_WDT_WPROTECT) {
                soc->wdt_unlock[g] = (val == TIMG_WDT_MAGIC);
                r[o >> 2] = val;
            } else if (o == TIMG_WDT_CONFIG0) {
                r[o >> 2] = val;
                if (!soc->wdt_unlock[g])
                    ; /* writes ignored while write-protected */
                else if (val & TIMG_WDT_EN) {
                    soc->wdt_en[g] = 1;
                    soc->wdt_expire[g] =
                        rv->csr_cycle + esp32c3_wdt_cycles(soc, g);
                } else {
                    soc->wdt_en[g] = 0;
                    r[TIMG_INT_RAW >> 2] &= ~TIMG_INT_WDT;
                    soc->intc_status &=
                        ~(((unsigned __int128) 1) << (g == 0 ? C3_TG0_WDT_INTR_SOURCE
                                                   : C3_TG1_WDT_INTR_SOURCE));
                }
            } else if (o == TIMG_WDT_CONFIG1 || o == TIMG_WDT_CONFIG2) {
                r[o >> 2] = val;
                if (soc->wdt_en[g])
                    soc->wdt_expire[g] =
                        rv->csr_cycle + esp32c3_wdt_cycles(soc, g);
            } else if (o == TIMG_WDT_FEED) {
                if (soc->wdt_unlock[g]) {
                    r[TIMG_INT_RAW >> 2] &= ~TIMG_INT_WDT;
                    if (!(r[TIMG_INT_RAW >> 2] & r[TIMG_INT_ENA >> 2]))
                        soc->intc_status &=
                            ~(((unsigned __int128) 1) << (g == 0 ? C3_TG0_WDT_INTR_SOURCE
                                                       : C3_TG1_WDT_INTR_SOURCE));
                    soc->wdt_expire[g] =
                        rv->csr_cycle + esp32c3_wdt_cycles(soc, g);
                }
                r[o >> 2] = val;
            } else {
                r[o >> 2] = val;
            }
            return;
        }
    }
    /* RTC_CNTL / IO_MUX / eFuse / RTC_I2C */
    if (addr < C3_PERIPH_BASE + 0xF000u) {
        mmio32[off >> 2] = val;
        return;
    }
    /* RMT (0x60016000) */
    if (addr >= C3_PERIPH_BASE + C3_RMT_BASE &&
        addr < C3_PERIPH_BASE + C3_RMT_BASE + 0x1000u) {
        uint32_t roff = addr - (C3_PERIPH_BASE + C3_RMT_BASE);
        mmio32[off >> 2] = val;
        switch (roff) {
        case 0x10u: /* CH0 CONF0 */
        case 0x14u: /* CH1 CONF0 */
        case 0x18u: /* CH2 CONF0 */
        case 0x20u: /* CH3 CONF0 */
            if (val & 0x1u) { /* tx_start (channel mem write begins) */
                mmio32[(C3_RMT_BASE + 0x38u) >> 2] &= ~0x1u; /* clear TX_DONE */
                soc->rmt_tx_done_cycle = rv->csr_cycle + 2048u;
            }
            break;
        case 0x44u: /* INT_CLR */
            mmio32[(C3_RMT_BASE + 0x38u) >> 2] &= ~val;
            soc->intc_status &= ~(((unsigned __int128)1) << C3_RMT_INTR_SOURCE);
            break;
        default:
            break;
        }
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
                mmio32[off >> 2] = 0x20000000u; /* bit29 VALUE_VALID, clear UPDATE */
            }
            return;
        case SYSTIMER_UNIT1_OP:
            mmio32[off >> 2] = val;
            if (val & 0x40000000u) { /* UPDATE: latch counter, set VALUE_VALID */
                soc->systimer_unit1_val = soc->systimer_unit1_counter;
                mmio32[off >> 2] = 0x20000000u; /* bit29 VALUE_VALID, clear UPDATE */
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
            /* Only clear intc_status bits that correspond to val */
            if (val & 1u)
                soc->intc_status &= ~(((unsigned __int128)1) << SYSTIMER_T0_SOURCE);
            if (val & 4u)
                soc->intc_status &= ~(((unsigned __int128)1) << SYSTIMER_T2_SOURCE);
            mmio32[off >> 2] = val;
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
            int src = o >> 2;
            int new_line = val & 0x1Fu;
            /* When remapping a source, clear any stale pending bit so that
             * a previously-disabled source doesn't deliver a spurious
             * interrupt on its new line.  This prevents the line-0 storm:
             * the SDK initially maps all sources to line 0 (disable), which
             * can accumulate INT_RAW bits from UART1/I2C init; remapping
             * those sources to real lines would otherwise deliver stale
             * interrupts before ISRs are installed. */
            soc->intc_status &= ~(((unsigned __int128) 1) << src);
            soc->intc_intmap[src] = new_line;
            return;
        }
        switch (o) {
        case INTC_INT_ENABLE:
            soc->intc_enable = val;
            return;
        case INTC_INT_TYPE:
            soc->intc_type = val;
            return;
        case INTC_INT_CLEAR:
            soc->intc_eip &= ~val; /* flush claimed state of the line */
            /* CPU_INT_CLEAR clears by CPU *line*; drop every source mapped to a
             * cleared line (covers high sources such as AES=48 which live in the
             * upper 32 bits of intc_status). */
            for (int s = 0; s < 72; s++)
                if (val & (1u << (soc->intc_intmap[s] & 0x1Fu)))
                    soc->intc_status &= ~(((unsigned __int128) 1) << s);
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
                soc->intc_status |= ((unsigned __int128)1) << 50u;
            else
                soc->intc_status &= ~(((unsigned __int128)1) << 50u);
            mmio32[off >> 2] = val;
            return;
        }
        /* SHA accelerator (0x6003B000) */
        if (addr == C3_PERIPH_BASE + 0x3B000u) { /* SHA_MODE: new session */
            if (sha_reset_pending) {
                esp32_sha_reset();
                sha_reset_pending = 0;
            }
            if (0) fprintf(stderr, "DBG: sha-mode val=0x%08x len=%u\n", val, sha_len);
            mmio32[off >> 2] = val;
            return;
        }
        if (addr == C3_PERIPH_BASE + 0x3B010u) { /* SHA_START */
            if (0) fprintf(stderr, "DBG: sha-start val=0x%08x len=%u\n", val, sha_len);
            mmio32[off >> 2] = val;
            return;
        }
        if (addr == C3_PERIPH_BASE + 0x3B014u) { /* SHA_CONTINUE */
            if (0) fprintf(stderr, "DBG: sha-cont val=0x%08x len=%u\n", val, sha_len);
            mmio32[off >> 2] = val;
            return;
        }
        if (addr >= C3_PERIPH_BASE + 0x3B040u &&
            addr < C3_PERIPH_BASE + 0x3B0C0u) { /* SHA message words */
            esp32_sha_feed_word(val);
            if (0) fprintf(stderr, "DBG: sha-feed addr=0x%08x val=0x%08x len=%u\n",
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
if (0 && rv->csr_cycle < 10000000u && (rv->csr_cycle & 0xFFFu) == 0)
            fprintf(stderr, "DBG: mrd-w pc=0x%08x addr=0x%08x\n", rv->PC, addr);
        if (0 && rv->csr_cycle >= 10000000u && (rv->csr_cycle & 0xFFFu) == 0)
            fprintf(stderr, "DBG: mrd-x pc=0x%08x addr=0x%08x\n", rv->PC, addr);
         if (0 && addr >= 0x6003B000u && addr < 0x6003C000u)
             fprintf(stderr, "DBG: sha-rd-in pc=0x%08x addr=0x%08x\n", rv->PC,
                     addr);
         {
             uint32_t v = esp32_mmio_read(PRIV(rv)->esp32c3, addr);
             if (0 && addr >= 0x60008800u && addr < 0x60008880u)
                 fprintf(stderr, "DBG: efuse-rd pc=0x%08x addr=0x%08x val=0x%08x\n",
                         rv->PC, addr, v);
             return v;
         }
     }
     if (0 && addr == 0x60004038u)
         fprintf(stderr, "DBG: strap-read pc=0x%08x\n", rv->PC);
     uint32_t val;
     uint32_t off = esp32_flash_window_off(PRIV(rv)->esp32c3, addr);
     if (off == ~0u)
         off = addr - r->base;
     memcpy(&val, r->data + off, 4);
     if (0 && addr >= 0x3C7E0000u && addr < 0x3C800000u && rv->PC == 0x403cf4acu)
         fprintf(stderr, "DBG: alias-rd pc=0x%08x addr=0x%08x val=0x%08x\n",
                 rv->PC, addr, val);
    if (addr >= C3_FLASH_I_BASE && addr < C3_FLASH_I_BASE + 0x1000u)
        if (0) fprintf(stderr, "DBG: flash-read  pc=0x%08x addr=0x%08x val=0x%08x\n",
                rv->PC, addr, val);
    if (addr >= C3_FLASH_I_BASE + 0x1000u && addr < C3_FLASH_I_BASE + 0x200000u)
        if (0) fprintf(stderr, "DBG: flash-read  pc=0x%08x addr=0x%08x val=0x%08x\n",
                rv->PC, addr, val);
    if (addr >= C3_FLASH_D_BASE && addr < C3_FLASH_D_BASE + 0x200000u)
        if (0) fprintf(stderr, "DBG: flashd-read pc=0x%08x addr=0x%08x val=0x%08x\n",
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
        if (0) fprintf(stderr, "DBG: verify-s pc=0x%08x addr=0x%08x val=0x%04x\n",
                rv->PC, addr, v);
    }
    if (0 && addr == 0x60004038u)
        fprintf(stderr, "DBG: strap-read-s pc=0x%08x\n", rv->PC);
    if (rv->PC >= 0x403cf000u && rv->PC < 0x403d0560u &&
        addr >= 0x3c7e0000u && addr < 0x3c7f0000u) {
        if (0) fprintf(stderr, "DBG: verify-l pc=0x%08x addr=0x%08x val=0x%08x\n",
                rv->PC, addr,
                *(uint32_t *)(r->data + (addr - r->base)));
    }
    if (rv->PC >= 0x403cf000u && rv->PC < 0x403d0560u &&
        addr >= 0x3c7f0000u && addr < 0x3c800000u) {
        if (0) fprintf(stderr, "DBG: verify-m pc=0x%08x addr=0x%08x val=0x%08x\n",
                rv->PC, addr,
                *(uint32_t *)(r->data + (addr - r->base)));
    }
    uint16_t val;
    uint32_t off = esp32_flash_window_off(PRIV(rv)->esp32c3, addr);
    if (off == ~0u)
        off = addr - r->base;
    memcpy(&val, r->data + off, 2);
    if (addr >= C3_FLASH_I_BASE && addr < C3_FLASH_I_BASE + 0x1000u)
        if (0) fprintf(stderr, "DBG: flash-reads pc=0x%08x addr=0x%08x val=0x%04x\n",
                rv->PC, addr, val);
    return val;
}

uint8_t esp32_read_b(riscv_t *rv, uint32_t addr)
{
    esp32_region_t *r = esp32_lookup(rv, addr);
    if (!r || r->type != ESP32_REG_RAM) {
        if (addr == 0x600C4034u)
            if (0) fprintf(stderr, "DBG: mrd-b pc=0x%08x addr=0x%08x\n", rv->PC, addr);
        return (uint8_t) esp32_mmio_read(PRIV(rv)->esp32c3, addr);
    }
    if (0 && addr == 0x60004038u)
        fprintf(stderr, "DBG: strap-read-b pc=0x%08x\n", rv->PC);
    if (rv->PC >= 0x403cf180u && rv->PC < 0x403cf200u)
        if (0) fprintf(stderr, "DBG: chkrd-b pc=0x%08x addr=0x%08x val=0x%02x\n",
                rv->PC, addr, r->data[addr - r->base]);
    if (addr >= C3_FLASH_I_BASE && addr < C3_FLASH_I_BASE + 0x1000u)
        if (0) fprintf(stderr, "DBG: flash-readb pc=0x%08x addr=0x%08x val=0x%02x\n",
                rv->PC, addr, r->data[addr - r->base]);
    if (rv->PC >= 0x403cf000u && rv->PC < 0x403d0560u &&
        addr >= C3_FLASH_D_BASE && addr < C3_FLASH_D_BASE + 0x10000u &&
        addr != 0x3c000020u) {
        uint32_t off = esp32_flash_window_off(PRIV(rv)->esp32c3, addr);
        if (0) fprintf(stderr, "DBG: verify-b pc=0x%08x addr=0x%08x val=0x%02x\n",
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
            if (0) fprintf(stderr, "DBG: accw %d pc=0x%08x val=0x%08x\n", acc_writes, rv->PC, val);
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
            if (0) fprintf(stderr, "DBG: mmu-w idx=%u page=0x%08x pc=0x%08x\n", idx,
                    val, rv->PC);
        return;
    }
    if (0 && addr >= 0x3FCDF100u && addr < 0x3FCDF130u)
        fprintf(stderr, "DBG: write[0x%08x]=0x%08x from pc=0x%08x\n", addr,
                val, rv->PC);
    if (0 && addr >= 0x3FCD5800u && addr < 0x3FCD5820u)
        fprintf(stderr, "DBG: hdr-wr[0x%08x]=0x%08x from pc=0x%08x\n", addr,
                val, rv->PC);
    if (0 && rv->PC >= 0x40057e52u && rv->PC < 0x40057f10u)
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
    unsigned __int128 pending = soc->intc_status;
    uint32_t lines = 0;
    for (int s = 0; s < 72; s++)
        if (pending & (((unsigned __int128)1) << s))
            lines |= 1u << (soc->intc_intmap[s] & 0x1Fu);
    /* ESP32 interrupt sources are level-triggered: a line stays asserted for
     * as long as its source is pending and enabled. Keep csr_mip high until
     * the ISR clears the source (do not self-clear via the EIP latch). */
    uint32_t raise = 0;
    for (int s = 0; s < 72; s++) {
        if (pending & ((unsigned __int128) 1 << s)) {
            int line = soc->intc_intmap[s] & 0x1Fu;
            /* Line 0 is reserved on real hardware, but this SDK maps a few
             * crypto/DMA sources (44-49) onto it; deliver those, while never
             * delivering line 0 for the many default-mapped (unused) sources
             * that would otherwise storm during boot. */
            int ok = (line >= 1 && line < 31) ||
                     (line == 0 && s >= 44 && s <= 49);
            if (ok && (soc->intc_enable & (1u << line)))
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
    /* The interrupt matrix (intc_enable) is the per-line gate: raise the CPU
     * lines that have a pending, enabled source, then deliver the lowest-numbered
     * one as a machine interrupt (mcause = (1<<31) | line). */
    uint32_t lines = esp32_intc_raise(soc);
    rv->csr_mip = (rv->csr_mip & ~0x7FFFFFFEu) | lines;
    if (!lines)
        return;
    int idx = __builtin_ctz(lines);
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
                    soc->intc_status |= ((unsigned __int128)1) << SYSTIMER_T0_SOURCE;
                }
            } else if (soc->systimer_comp0 && cnt0 >= soc->systimer_comp0) {
                soc->systimer_int_raw |= 1u;
                soc->intc_status |= ((unsigned __int128)1) << SYSTIMER_T0_SOURCE;
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
                    soc->intc_status |= ((unsigned __int128)1) << SYSTIMER_T2_SOURCE;
                }
            } else if (soc->systimer_comp2 && cnt2 >= soc->systimer_comp2) {
                soc->systimer_int_raw |= 4u;
                soc->intc_status |= ((unsigned __int128)1) << SYSTIMER_T2_SOURCE;
            }
        }
    }

    /* I2C transfer completion: a trans_start was issued. Without a slave the
     * address byte is never ACKed -> NACK + trans-complete. With the virtual
     * device (0x50) the transfer is ACKed: writes are stored into its memory,
     * reads return the memory contents via the RX fifo. */
    if (soc->i2c_transfer_pending) {
        soc->i2c_transfer_pending = 0;
        if (soc->i2c_slave_active) {
            uint8_t *t = soc->i2c_tx_fifo;
            int tl = soc->i2c_tx_len;
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
                soc->i2c_rx_len = 0;
                soc->i2c_rx_pos = 0;
                int p = soc->i2c_dev_ptr;
                for (int i = 0; i < 8; i++) {
                    soc->i2c_rx_fifo[i] = soc->i2c_dev_mem[(p++) & 15];
                    soc->i2c_rx_len = 8;
                }
                soc->i2c_dev_ptr = p & 15;
            } else {
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
            soc->intc_status |= ((unsigned __int128) 1) << C3_I2C_EXT0_INTR_SOURCE;
    }

    /* SPI2 transfer completion: cmd.usr was set. The virtual device (a
     * 16-byte SRAM, JEDEC ID 0xEF4015, echo fallback) decodes the TX bytes
     * from the data buffer (little-endian byte order as the HAL packs it)
     * and shifts its response back MSB-first; with no device selected the
     * MISO line floats high so every received byte is 0xFF. */
    if (soc->spi2_transfer_pending) {
        soc->spi2_transfer_pending = 0;
        uint32_t dlen = soc->spi2_reg[0x1c >> 2] & 0x3Fu; /* ms_dbitlen */
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
            for (int i = 0; i < n; i++)
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
     * (transmit interrupt). Delivery is delayed to a later cycle so the
     * interrupt is not delivered while the firmware is still inside
     * twai_transmit_v2 (real hardware takes ~200us for a frame); delivering
     * it instantly made the ISR run before the driver's own tx_msg_count++
     * and assert on it. */
    if (soc->twai_tx_pending &&
        rv->csr_cycle >= soc->twai_tx_done_cycle) {
        soc->twai_tx_pending = 0;
        soc->twai_reg[0x04 >> 2] &= ~TWAI0_CMD_TX_REQUEST;
        soc->twai_reg[0x08 >> 2] |= TWAI0_STATUS_TCS;
        soc->twai_reg[0x0c >> 2] |= TWAI0_INTR_TI;
        soc->intc_status |= ((unsigned __int128) 1) << C3_TWAI_INTR_SOURCE;
    }

    /* TWAI0 RX delivery: a virtual node on the bus sends one frame
     * (~1.5ms after the controller left reset mode): std ID 0x123, DLC 2,
     * data DE AD. The frame buffer words hold one byte each (bits 7-0);
     * bytes 1-2 are the ID left-aligned big-endian ((id << 5) >> 8,
     * (id << 5) & 0xFF). RX delivery sets RBS + rx_message_counter and
     * raises RI, gated on the receive interrupt being enabled. */
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
            soc->intc_status |= ((unsigned __int128) 1) << C3_TWAI_INTR_SOURCE;
        }
    }

    /* GDMA mem2mem completion: when both the OUT (source) and IN (dest)
     * channels of a channel are running, walk the descriptor chains in
     * lockstep and copy each OUT buffer into the paired IN buffer, then
     * raise OUT_EOF + IN_SUC_EOF on the shared channel interrupt. A lone
     * OUT/IN channel just raises its own EOF so peripheral-only DMA does
     * not hang the driver. */
    for (int ch = 0; ch < 3; ch++) {
        if (!soc->gdma_m2m_pending[ch] ||
            rv->csr_cycle < soc->gdma_m2m_done_cycle[ch])
            continue;
        soc->gdma_m2m_pending[ch] = 0;
        uint32_t out_addr = soc->gdma_out_dscr[ch];
        uint32_t in_addr = soc->gdma_in_dscr[ch];
        int paired = soc->gdma_out_run[ch] && soc->gdma_in_run[ch];

        /* Paired (mem2mem) or peripheral TX/RX: walk the descriptor chains
         * and process each descriptor. */
        if (paired) {
            /* Paired mem2mem: walk both chains in lockstep */
            while (out_addr && in_addr) {
                uint8_t *src = esp32c3_dma_ptr(soc, soc->gdma_out_desc_buf[ch]);
                uint8_t *dst = esp32c3_dma_ptr(soc, soc->gdma_in_desc_buf[ch]);
                uint32_t n = soc->gdma_out_desc_len[ch];
                if (n > soc->gdma_in_desc_len[ch])
                    n = soc->gdma_in_desc_len[ch];
                if (src && dst && n) {
                    if (soc->gdma_out_peri_sel[ch] == C3_GDMA_PERI_AES ||
                        soc->gdma_in_peri_sel[ch] == C3_GDMA_PERI_AES) {
                        int nblk = (int)(n / 16u);
                        if (nblk > 0) {
                            uint8_t *enc = malloc(n);
                            esp32c3_aes_process_buf(soc, src, enc, nblk);
                            memcpy(dst, enc, n);
                            free(enc);
                        }
                        soc->aes_reg[0x4cu >> 2] = 2u;
                    } else {
                        memcpy(dst, src, n);
                    }
                }
                uint8_t *od = esp32c3_dma_ptr(soc, out_addr);
                if (od) { uint32_t dw0; memcpy(&dw0, od, 4); dw0 &= ~(1u << 31); memcpy(od, &dw0, 4); }
                uint8_t *id = esp32c3_dma_ptr(soc, in_addr);
                if (id) { uint32_t dw0; memcpy(&dw0, id, 4); dw0 &= ~(1u << 31); memcpy(id, &dw0, 4); }
                if (!soc->gdma_out_next_addr[ch] || !soc->gdma_in_next_addr[ch])
                    break;
                out_addr = soc->gdma_out_next_addr[ch];
                in_addr = soc->gdma_in_next_addr[ch];
                if (!esp32c3_gdma_load_desc(soc, out_addr,
                        &soc->gdma_out_desc_buf[ch], &soc->gdma_out_desc_len[ch],
                        &soc->gdma_out_next_addr[ch]))
                    break;
                if (!esp32c3_gdma_load_desc(soc, in_addr,
                        &soc->gdma_in_desc_buf[ch], &soc->gdma_in_desc_len[ch],
                        &soc->gdma_in_next_addr[ch]))
                    break;
            }
            soc->gdma_int_raw[ch] |=
                (1u << GDMA_OUT_EOF_BIT) | (1u << GDMA_IN_SUC_EOF_BIT);
            soc->gdma_out_run[ch] = 0;
            soc->gdma_in_run[ch] = 0;
        } else if (soc->gdma_out_run[ch]) {
            /* Unpaired OUT (I2S TX): save completed descriptor, clear
             * owner, fire OUT_EOF, advance to the next descriptor
             * and re-arm. */
            soc->gdma_out_eof_des[ch] = out_addr;
            uint8_t *od = esp32c3_dma_ptr(soc, out_addr);
            if (od) { uint32_t dw0; memcpy(&dw0, od, 4); dw0 &= ~(1u << 31); memcpy(od, &dw0, 4); }
            soc->gdma_int_raw[ch] |= (1u << GDMA_OUT_EOF_BIT);
            if (soc->gdma_out_next_addr[ch]) {
                uint32_t next = soc->gdma_out_next_addr[ch];
                if (esp32c3_gdma_load_desc(soc, next,
                        &soc->gdma_out_desc_buf[ch], &soc->gdma_out_desc_len[ch],
                        &soc->gdma_out_next_addr[ch])) {
                    soc->gdma_out_dscr[ch] = next;
                    soc->gdma_m2m_pending[ch] = 1;
                    soc->gdma_m2m_done_cycle[ch] = rv->csr_cycle + 20000u;
                }
            } else {
                soc->gdma_out_run[ch] = 0;
            }
        } else if (soc->gdma_in_run[ch]) {
            /* Unpaired IN (I2S RX): synthesize a monotonic counter into the
             * current descriptor buffer, save the completed descriptor address,
             * clear owner, fire IN_SUC_EOF, advance to the next descriptor
             * and re-arm. */
            soc->gdma_in_eof_des[ch] = in_addr;
            {
                uint8_t *dst = esp32c3_dma_ptr(soc, soc->gdma_in_desc_buf[ch]);
                uint32_t n = soc->gdma_in_desc_len[ch];
                if (dst && n) {
                    uint32_t nw = n / 4u;
                    for (uint32_t i = 0; i < nw; i++) {
                        uint32_t v = soc->i2s_rx_counter++;
                        memcpy(dst + i * 4, &v, 4);
                    }
                }
            }
            uint8_t *id = esp32c3_dma_ptr(soc, in_addr);
            if (id) { uint32_t dw0; memcpy(&dw0, id, 4); dw0 &= ~(1u << 31); memcpy(id, &dw0, 4); }
            soc->gdma_int_raw[ch] |= (1u << GDMA_IN_SUC_EOF_BIT);
            if (soc->gdma_in_next_addr[ch]) {
                uint32_t next = soc->gdma_in_next_addr[ch];
                if (esp32c3_gdma_load_desc(soc, next,
                        &soc->gdma_in_desc_buf[ch], &soc->gdma_in_desc_len[ch],
                        &soc->gdma_in_next_addr[ch])) {
                    soc->gdma_in_dscr[ch] = next;
                    soc->gdma_m2m_pending[ch] = 1;
                    soc->gdma_m2m_done_cycle[ch] = rv->csr_cycle + 20000u;
                }
            } else {
                soc->gdma_in_run[ch] = 0;
            }
        }
        if (soc->gdma_int_raw[ch] & soc->gdma_int_ena[ch])
            soc->intc_status |= ((unsigned __int128) 1) << (C3_DMA_CH0_INTR_SOURCE + ch);
    }

    /* RMT TX_DONE: a few cycles after a channel's CONF0 tx_start was seen,
     * raise the RMT interrupt so the firmware's RMT ISR can post the
     * transaction and unblock the caller's event-group wait. */
    if (soc->rmt_tx_done_cycle && rv->csr_cycle >= soc->rmt_tx_done_cycle) {
        uint32_t *mmio32 = (uint32_t *) soc->mmio;
        soc->rmt_tx_done_cycle = 0;
        mmio32[(C3_RMT_BASE + 0x38u) >> 2] |= 0x1u; /* INT_RAW TX_DONE (CH0) */
        soc->intc_status |= ((unsigned __int128)1) << C3_RMT_INTR_SOURCE;
    }

    /* LEDC output drive: enabled channels drive their routed pads. The GPIO
     * matrix FUNCx_OUT_SEL (0x60004554 + 4*pin) picks the signal; LEDC
     * channels 0-5 are signals 0-5. The pad level follows the PWM phase. */
    {
        uint32_t *mmio32 = (uint32_t *) soc->mmio;
        for (int c = 0; c < 6; c++) {
            uint32_t conf0 = soc->ledc_reg[LEDC_CH_CONF0(c) >> 2];
            int level;
            if (conf0 & LEDC_SIG_OUT_EN) {
                uint32_t t = conf0 & 0x3u;
                uint32_t conf = soc->ledc_reg[LEDC_TIMER_CONF(t) >> 2];
                uint32_t res = conf & 0x1Fu;
                uint32_t f = (conf >> 5) & 0x3FFFFu;
                uint32_t ratio = (conf & LEDC_TICK_SEL) ? 10u : 1u;
                uint32_t period = 1u << (res < 25 ? res : 25);
                if (f == 0) {
                    level = (conf0 & LEDC_IDLE_LV) ? 1 : 0;
                } else {
                    uint64_t span = (uint64_t) f * (uint64_t) period * ratio;
                    soc->ledc_timer_frac[t] +=
                        (rv->csr_cycle - soc->ledc_timer_anchor[t]) * 512ull;
                    soc->ledc_timer_anchor[t] = rv->csr_cycle;
                    soc->ledc_timer_frac[t] %= span;
                    uint64_t ticks = soc->ledc_timer_frac[t] / f;
                    uint32_t pos = (uint32_t)(ticks % period);
                    uint32_t hpoint =
                        soc->ledc_reg[LEDC_CH_HPOINT(c) >> 2] & 0xFFFFFu;
                    uint32_t duty =
                        (soc->ledc_duty_r[c] & 0x1FFFFFFu) >> 4u;
                    level = ((pos + period - hpoint) % period) < duty;
                }
            } else {
                level = (conf0 & LEDC_IDLE_LV) ? 1 : 0;
            }
            for (int p = 0; p < 22; p++) {
                uint32_t sel = mmio32[(0x4554u + 4u * p) >> 2] & 0xFFu;
                if (sel == (uint32_t) c) {
                    if (level)
                        soc->gpio_in |= 1u << p;
                    else
                        soc->gpio_in &= ~(1u << p);
                }
            }
        }
    }

    /* GPIO level interrupt poll: level-triggered interrupts (type 4=low,
     * 5=high) must remain pending while the level persists. The edge
     * checker only fires on transitions, so after the ISR clears
     * GPIO_STATUS the pending bit would be lost. Re-assert it here while
     * the live level still matches. */
    {
        uint32_t *mmio32 = (uint32_t *) soc->mmio;
        uint32_t live = soc->gpio_in | esp32c3_gpio_eff_out(soc, mmio32);
        for (int pin = 0; pin < 22; pin++) {
            uint32_t pr = mmio32[(0x4074u + 4u * pin) >> 2];
            int type = (pr >> 7) & 0x7u;
            int ena = (pr >> 13) & 0x1Fu;
            if (!ena)
                continue;
            if (type != 4 && type != 5)
                continue;
            int level = (live >> pin) & 1;
            int fire = (type == 4) ? !level : level;
            if (fire && !(soc->gpio_status & (1u << pin))) {
                soc->gpio_status |= 1u << pin;
                soc->intc_status |= ((unsigned __int128) 1) << C3_GPIO_INTR_SOURCE;
            }
        }
    }

    /* TIMG0/1 alarms: the counter ticks at the selected clock (PLL 80MHz or
     * XTAL 40MHz, ratio vs the 1:1 cycle clock) divided by DIVIDER+1. On
     * alarm: raw bit 0 set and the source raised (level semantics). With
     * AUTORELOAD the counter reloads from T0LOADLO/HI. */
    for (int g = 0; g < 2; g++) {
        uint32_t cfg = soc->timg_reg[g][TIMG_T0CONFIG >> 2];
        if (!(cfg & TIMG_T0_EN))
            continue;
        uint32_t div = ((cfg & TIMG_T0_DIVIDER) >> 13) + 1u;
        /* csr_cycle advances at the C3 SYSTIMER base clock (16 MHz); the GPTIMER
         * reference is APB (80 MHz) or XTAL (40 MHz). Convert to csr_cycle units
         * so the timer ticks at the requested frequency relative to the rest of
         * the SoC (the SYSTIMER model counts 1:1 with csr_cycle). */
        uint32_t timer_mhz = (cfg & TIMG_T0_USE_XTAL) ? 40u : 80u;
        uint64_t step = ((uint64_t) div * ESP32C3_CSR_CLK_MHZ) / timer_mhz;
        if (step == 0)
            step = 1;
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
        uint32_t src = (g == 0) ? C3_TG0_T0_INTR_SOURCE
                                : C3_TG1_T0_INTR_SOURCE;
        int past = (cfg & TIMG_T0_ALARM_EN) && alarm &&
                   ((cfg & TIMG_T0_INCREASE) ? cnt >= alarm : cnt <= alarm);
        if (past) {
            soc->timg_reg[g][TIMG_INT_RAW >> 2] |= TIMG_INT_T0_ALARM;
            if (soc->timg_reg[g][TIMG_INT_RAW >> 2] &
                soc->timg_reg[g][TIMG_INT_ENA >> 2])
                soc->intc_status |= ((unsigned __int128) 1) << src;
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

    /* MWDT (Timer Group Watchdog) timeouts: when armed and the expiry cycle
     * passes without a feed, raise the group's WDT interrupt. */
    for (int g = 0; g < 2; g++) {
        if (!soc->wdt_en[g])
            continue;
        if (rv->csr_cycle < soc->wdt_expire[g])
            continue;
        soc->timg_reg[g][TIMG_INT_RAW >> 2] |= TIMG_INT_WDT;
        if (soc->timg_reg[g][TIMG_INT_RAW >> 2] &
            soc->timg_reg[g][TIMG_INT_ENA >> 2]) {
            uint32_t src = (g == 0) ? C3_TG0_WDT_INTR_SOURCE
                                    : C3_TG1_WDT_INTR_SOURCE;
            soc->intc_status |= ((unsigned __int128) 1) << src;
        }
    }
}