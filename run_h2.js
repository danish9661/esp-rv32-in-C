const fs=require('fs'),path=require('path');
const bin=fs.readFileSync(path.resolve(process.argv[2]));
const args=process.argv[3]||'-C esp32h2 -F /merged.bin';
const el=new Proxy(function(){},{get:(t,p)=>p==='style'?el:el,set:()=>true,apply:()=>el});
global.document={getElementById:()=>el,querySelector:()=>el,addEventListener:()=>{},createElement:()=>el};
const M=require(path.join(__dirname,'build/rv32emu.js'));
M.locateFile=p=>p==='rv32emu.wasm'?path.join(__dirname,'build/rv32emu.wasm'):p;
M.onRuntimeInitialized=()=>{M.FS.writeFile('/merged.bin',bin);if(process.env.H2_RX_FILE){M.FS.writeFile('/uartrx',fs.readFileSync(path.resolve(process.env.H2_RX_FILE)));}M.run_system(args);};
