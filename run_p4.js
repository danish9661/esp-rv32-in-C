const fs=require('fs'),path=require('path');
const bin=fs.readFileSync(path.resolve(process.argv[2]));
const args=process.argv[3]||'-C esp32p4 -F /merged.bin';
const el=new Proxy(function(){},{get:(t,p)=>p==='style'?el:el,set:()=>true,apply:()=>el});
global.document={getElementById:()=>el,querySelector:()=>el,addEventListener:()=>{},createElement:()=>el};
const M=require('/home/danish1075/Documents/esp-rv32emu/build/rv32emu.js');
M.locateFile=p=>p==='rv32emu.wasm'?'/home/danish1075/Documents/esp-rv32emu/build/rv32emu.wasm':p;
M.onRuntimeInitialized=()=>{M.FS.writeFile('/merged.bin',bin);if(process.env.P4_RX_FILE){M.FS.writeFile('/uartrx',fs.readFileSync(path.resolve(process.env.P4_RX_FILE)));}M.run_system(args);};
