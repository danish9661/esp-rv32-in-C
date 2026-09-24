const fs=require('fs'),path=require('path');
const bin=fs.readFileSync(path.resolve(process.argv[2]));
const el=new Proxy(function(){},{get:(t,p)=>p==='style'?el:el,set:()=>true,apply:()=>el});
global.document={getElementById:()=>el,querySelector:()=>el,addEventListener:()=>{},createElement:()=>el};
const M=require(path.join(__dirname,'build/rv32emu.js'));
M.locateFile=p=>p==='rv32emu.wasm'?path.join(__dirname,'build/rv32emu.wasm'):p;
M.onRuntimeInitialized=()=>{M.FS.writeFile('/merged.bin',bin);if(process.env.C3_RX_FILE){M.FS.writeFile('/uartrx',fs.readFileSync(path.resolve(process.env.C3_RX_FILE)));}M.run_system('-C esp32c3 -F /merged.bin');};
