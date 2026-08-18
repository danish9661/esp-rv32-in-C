/*
 * rv32emu is freely redistributable under the MIT License. See the file
 * "LICENSE" for information on usage and redistribution of this file.
 */

#include "em_runtime.h"

#if defined(__EMSCRIPTEN__)
#if RV32_HAS(SYSTEM_MMIO)
extern uint8_t input_buf_size;

char *get_input_buf();
uint8_t get_input_buf_cap();
void set_input_buf_size(uint8_t size);
uint8_t get_input_buf_size();
void u8250_put_rx_char(uint8_t c);
#endif
#endif