# WebAssembly build configuration
#
# Provides Emscripten-specific build flags and targets.

ifndef _MK_WASM_INCLUDED
_MK_WASM_INCLUDED := 1

CFLAGS_emcc ?=
deps_emcc :=
ASSETS := assets/wasm
WEB_HTML_RESOURCES := $(ASSETS)/html
WEB_JS_RESOURCES := $(ASSETS)/js
# Base exported functions (ESP UART input buffer functions included;
# the ESP32-only tree always builds CONFIG_SYSTEM=y).
EXPORTED_FUNCS := _main,_indirect_rv_halt,_indirect_rv_alive,_indirect_rv_cleanup,_get_input_buf,_get_input_buf_cap,_set_input_buf_size,_get_input_buf_size,_u8250_put_rx_char
DEMO_DIR_BASE := demo
# ESP32-only tree: always the system/ESP demo dir (user mode removed).
DEMO_DIR := $(DEMO_DIR_BASE)/system

# Base web files: the WASM bundle only (ESP firmware is fetched at runtime
# by system.html and written into MEMFS).
WEB_FILES := $(BIN).js \
             $(BIN).wasm

# Only configure Emscripten settings when using emcc
ifeq ("$(CC_IS_EMCC)", "1")

BIN := $(BIN).js

# Tail-call optimization - requires both compile and link flags
CFLAGS += -mtail-call
LDFLAGS += -mtail-call

# SDL configuration for Emscripten
ifeq ($(CONFIG_SDL),y)
# Disable STRICT mode to avoid -Werror in SDL2_mixer port compilation
CFLAGS_emcc += -sSTRICT=0 -sUSE_SDL=2 -sSDL2_MIXER_FORMATS=wav,mid -sUSE_SDL_MIXER=2
CFLAGS_emcc += -pthread -sPTHREAD_POOL_SIZE=navigator.hardwareConcurrency
OBJS_EXT += syscall_sdl.o
LDFLAGS += -pthread
# Note: Emscripten 4.x inlines worker code into the main JS file
endif

LDFLAGS += --js-library $(WEB_JS_RESOURCES)/emruntime-library.js

# Emscripten build flags
CFLAGS_emcc += -sALLOW_MEMORY_GROWTH \
               \
               -s"EXPORTED_FUNCTIONS=$(EXPORTED_FUNCS)" \
               -sSTACK_SIZE=4MB \
               -DCYCLE_PER_STEP=32000000 \
               -DWASM_BLOCK_LIMIT=20000 \
               -DWASM_BLOCK_HARD_LIMIT=40000 \
               -O3 \
               -w

# ESP boot path: fixed system/ELF-loader flags (firmware boots from the
# flash image via -C <chip> -F; no DTB, no embedded ELFs, no game data).
CFLAGS_emcc += -sINITIAL_MEMORY=768MB \
               -DMEM_SIZE=0x20000000 \
               -sEXPORTED_RUNTIME_METHODS='["callMain","FS"]' \
               --pre-js $(WEB_JS_RESOURCES)/system-pre.js

# mimalloc support detection
MIMALLOC_SUPPORT_SINCE_MAJOR := 3
MIMALLOC_SUPPORT_SINCE_MINOR := 1
MIMALLOC_SUPPORT_SINCE_PATCH := 50
ifeq ($(call version_gte,$(EMCC_MAJOR),$(EMCC_MINOR),$(EMCC_PATCH),$(MIMALLOC_SUPPORT_SINCE_MAJOR),$(MIMALLOC_SUPPORT_SINCE_MINOR),$(MIMALLOC_SUPPORT_SINCE_PATCH)), 1)
    CFLAGS_emcc += -sMALLOC=mimalloc
else
    $(warning mimalloc requires Emscripten $(MIMALLOC_SUPPORT_SINCE_MAJOR).$(MIMALLOC_SUPPORT_SINCE_MINOR).$(MIMALLOC_SUPPORT_SINCE_PATCH)+)
endif

# xterm.js terminal library for web UI.
# Fetched at build time from jsdelivr (primary) with unpkg as a backup. Both
# serve the same npm payload; jsdelivr is friendlier to CI runners while
# unpkg has been observed to return 403 to GitHub Actions traffic.
# Package renamed from 'xterm' to '@xterm/xterm' in v6.0.0.
XTERM_VERSION := 6.0.0
XTERM_VENDOR := $(ASSETS)/vendor
XTERM_JS := $(XTERM_VENDOR)/xterm.min.js
XTERM_CSS := $(XTERM_VENDOR)/xterm.min.css

XTERM_JS_URLS := \
    https://cdn.jsdelivr.net/npm/@xterm/xterm@$(XTERM_VERSION)/lib/xterm.js \
    https://unpkg.com/@xterm/xterm@$(XTERM_VERSION)/lib/xterm.js
XTERM_CSS_URLS := \
    https://cdn.jsdelivr.net/npm/@xterm/xterm@$(XTERM_VERSION)/css/xterm.css \
    https://unpkg.com/@xterm/xterm@$(XTERM_VERSION)/css/xterm.css

$(XTERM_VENDOR):
	$(Q)mkdir -p $@

# Fetch with --fail so a 4xx/5xx is a build error instead of writing an HTML
# error page over the bundle. Falls through the URL list until one succeeds.
$(XTERM_JS): | $(XTERM_VENDOR)
	$(VECHO) "  FETCH\t$@\n"
	$(Q)set -e; ok=0; \
	    for u in $(XTERM_JS_URLS); do \
	        if curl -fsSL --retry 3 -o $@ "$$u"; then ok=1; break; fi; \
	    done; \
	    [ $$ok -eq 1 ] || { echo "ERROR: failed to fetch $@"; exit 1; }

$(XTERM_CSS): | $(XTERM_VENDOR)
	$(VECHO) "  FETCH\t$@\n"
	$(Q)set -e; ok=0; \
	    for u in $(XTERM_CSS_URLS); do \
	        if curl -fsSL --retry 3 -o $@ "$$u"; then ok=1; break; fi; \
	    done; \
	    [ $$ok -eq 1 ] || { echo "ERROR: failed to fetch $@"; exit 1; }

XTERM_DATA := $(XTERM_JS) $(XTERM_CSS)

# Dependencies for the ESP WASM build: prebuilt ELF fixtures only
# (no game data, no timidity, no kernel image).
deps_emcc += artifact

# Browser TCO Support Detection

CHROME_SUPPORT_TCO_AT_MAJOR := 112
FIREFOX_SUPPORT_TCO_AT_MAJOR := 121
SAFARI_SUPPORT_TCO_AT_MAJOR := 18
SAFARI_SUPPORT_TCO_AT_MINOR := 2

# Browser detection (platform-specific)
ifeq ($(UNAME_S),Darwin)
    CHROME_MAJOR := $(shell "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --version 2>/dev/null | awk '{print $$3}' | cut -f1 -d.)
    FIREFOX_MAJOR := $(shell /Applications/Firefox.app/Contents/MacOS/firefox --version 2>/dev/null | awk '{print $$3}' | cut -f1 -d.)
    SAFARI_VERSION := $(shell mdls -name kMDItemVersion /Applications/Safari.app 2>/dev/null | sed 's/"//g' | awk '{print $$3}')
else ifeq ($(UNAME_S),Linux)
    CHROME_MAJOR := $(shell google-chrome --version 2>/dev/null | awk '{print $$3}' | cut -f1 -d.)
    FIREFOX_MAJOR := $(shell firefox -v 2>/dev/null | awk '{print $$3}' | cut -f1 -d.)
endif

# Browser support notifications
ifneq ($(CHROME_MAJOR),)
ifeq ($(call version_gte,$(CHROME_MAJOR),,,$(CHROME_SUPPORT_TCO_AT_MAJOR),,), 1)
    $(info $(call noticex, Chrome $(CHROME_MAJOR) supports TCO))
else
    $(warning Chrome $(CHROME_MAJOR) does not support TCO (requires $(CHROME_SUPPORT_TCO_AT_MAJOR)+))
endif
endif

ifneq ($(FIREFOX_MAJOR),)
ifeq ($(call version_gte,$(FIREFOX_MAJOR),,,$(FIREFOX_SUPPORT_TCO_AT_MAJOR),,), 1)
    $(info $(call noticex, Firefox $(FIREFOX_MAJOR) supports TCO))
else
    $(warning Firefox $(FIREFOX_MAJOR) does not support TCO (requires $(FIREFOX_SUPPORT_TCO_AT_MAJOR)+))
endif
endif

# Web Demo Server

DEMO_IP := 127.0.0.1
DEMO_PORT := 8000

check-demo-dir-exist:
	$(Q)if [ ! -d "$(DEMO_DIR)" ]; then mkdir -p "$(DEMO_DIR)"; fi

define cp-web-file
    $(Q)cp $(1) $(DEMO_DIR)
    $(info)
endef

# Emscripten 3.x emits $(BIN).worker.js for pthread builds (SDL/system mode on
# the documented 3.1.51 toolchain); Emscripten 4.x inlines the worker code
# into the main JS file. Copy the sidecar only when it exists so the build is
# correct on both toolchains and a pthread build doesn't ship missing it.
define cp-web-worker
    $(Q)if [ -f $(BIN).worker.js ]; then cp $(BIN).worker.js $(DEMO_DIR)/; fi
endef

STATIC_WEB_FILES := $(WEB_JS_RESOURCES)/coi-serviceworker.min.js \
                    $(XTERM_JS) $(XTERM_CSS) \
                    $(WEB_HTML_RESOURCES)/system.html

# ESP32-only tree: single demo root (demo/system); no user-mode page,
# no landing page (upstream demo-index.html removed).

start_web_deps := check-demo-dir-exist $(BIN) $(XTERM_DATA)

# Populate the ESP demo tree (demo/system) without starting a server.
prepare-web: $(start_web_deps)
	$(Q)rm -f $(DEMO_DIR)/*.html
	$(foreach T, $(WEB_FILES), $(call cp-web-file, $(T)))
	$(foreach T, $(STATIC_WEB_FILES), $(call cp-web-file, $(T)))
	$(call cp-web-worker)
	$(Q)mv $(DEMO_DIR)/*.html $(DEMO_DIR)/index.html

# Serve whatever is currently under $(DEMO_DIR_BASE). Run `prepare-web` first.
serve-web:
	$(Q)python3 tools/dev-server.py --bind $(DEMO_IP) --port $(DEMO_PORT) --directory $(DEMO_DIR_BASE)

start-web: prepare-web serve-web

# Compressed web build for production deployment
# Creates gzip and brotli compressed versions of large assets
compress-web: $(start_web_deps)
	$(Q)rm -f $(DEMO_DIR)/*.html $(DEMO_DIR)/*.gz $(DEMO_DIR)/*.br
	$(foreach T, $(WEB_FILES), $(call cp-web-file, $(T)))
	$(foreach T, $(STATIC_WEB_FILES), $(call cp-web-file, $(T)))
	$(call cp-web-worker)
	$(Q)mv $(DEMO_DIR)/*.html $(DEMO_DIR)/index.html
	@$(call notice, Compressing web assets...)
	$(Q)gzip -9 -k $(DEMO_DIR)/rv32emu.wasm 2>/dev/null || true
	$(Q)gzip -9 -k $(DEMO_DIR)/rv32emu.js 2>/dev/null || true
	$(Q)if command -v brotli >/dev/null 2>&1; then \
		brotli -9 -k $(DEMO_DIR)/rv32emu.wasm 2>/dev/null || true; \
		brotli -9 -k $(DEMO_DIR)/rv32emu.js 2>/dev/null || true; \
	fi
	@$(call notice, Compression complete)
	$(Q)ls -lh $(DEMO_DIR)/rv32emu.* | awk '{print $$5, $$9}'

.PHONY: check-demo-dir-exist prepare-web serve-web start-web compress-web

endif # CC_IS_EMCC

endif # _MK_WASM_INCLUDED
