Module["noInitialRun"] = true;

Module["run_system"] = function (cli_param) {
  callMain(cli_param.split(" "));
};

Module["run_esp32c3"] = function (elf_name, flash_name) {
  callMain(["-C", "esp32c3", "-F", "/" + flash_name, "/" + elf_name]);
};

Module["run_esp32c6"] = function (elf_name, flash_name) {
  callMain(["-C", "esp32c6", "-F", "/" + flash_name, "/" + elf_name]);
};

Module["run_esp32h2"] = function (elf_name, flash_name) {
  callMain(["-C", "esp32h2", "-F", "/" + flash_name, "/" + elf_name]);
};

Module["run_esp32p4"] = function (elf_name, flash_name) {
  callMain(["-C", "esp32p4", "-F", "/" + flash_name, "/" + elf_name]);
};

// Note: Terminal initialization is defined in system.html
// Module.onRuntimeInitialized is defined in the HTML file
