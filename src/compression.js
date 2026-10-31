export async function previewHead(file,encoding='utf-8'){
  if(!/\.gz$/i.test(file.name))return new TextDecoder(encoding).decode(await file.slice(0,16384).arrayBuffer());
  if(typeof DecompressionStream==='undefined')return '\0Gzip wird von diesem Browser nicht unterstützt';
  const magic=new Uint8Array(await file.slice(0,2).arrayBuffer());
  if(magic[0]!==0x1f||magic[1]!==0x8b)return '\0Ungültige Gzip-Datei';
  try{
    const reader=file.stream().pipeThrough(new DecompressionStream('gzip')).getReader();
    const decoder=new TextDecoder(encoding);let result='';
    while(result.length<16384){const {done,value}=await reader.read();if(done)break;result+=decoder.decode(value,{stream:true})}
    await reader.cancel();
    return result.slice(0,16384);
  }catch{return '\0Gzip-Vorschau fehlgeschlagen'}
}
export async function sampleFingerprint(file){
  if(!crypto.subtle)return null;
  const first=new Uint8Array(await file.slice(0,65536).arrayBuffer());
  const last=new Uint8Array(await file.slice(Math.max(0,file.size-65536)).arrayBuffer());
  const size=new TextEncoder().encode(String(file.size));
  const bytes=new Uint8Array(first.length+last.length+size.length);
  bytes.set(first);bytes.set(last,first.length);bytes.set(size,first.length+last.length);
  const hash=new Uint8Array(await crypto.subtle.digest('SHA-256',bytes));
  return [...hash].map(b=>b.toString(16).padStart(2,'0')).join('');
}
