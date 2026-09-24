Module["noInitialRun"] = true;

// Generic entry used by the node headless runners (run_*.js) and CI gates.
Module["run_system"] = function (cli_param) {
  callMain(cli_param.split(" "));
};

// ESP32 flash-only boot: each chip boots its merged flash image through
// the ROM reset vector (no ELF arg needed; the SoC ignores the positional
// ELF when -F is given, so all six entries take just the flash MEMFS path).
Module["run_esp32c3"] = function (flash_name) {
  callMain(["-C", "esp32c3", "-F", "/" + flash_name]);
};

Module["run_esp32c6"] = function (flash_name) {
  callMain(["-C", "esp32c6", "-F", "/" + flash_name]);
};

Module["run_esp32h2"] = function (flash_name) {
  callMain(["-C", "esp32h2", "-F", "/" + flash_name]);
};

Module["run_esp32p4"] = function (flash_name) {
  callMain(["-C", "esp32p4", "-F", "/" + flash_name]);
};

Module["run_esp32p4smp"] = function (flash_name) {
  callMain(["-C", "esp32p4smp", "-F", "/" + flash_name]);
};

// Note: Terminal initialization is defined in system.html
// Module.onRuntimeInitialized is defined in the HTML file
