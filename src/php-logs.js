const months={Jan:0,Feb:1,Mar:2,Apr:3,May:4,Jun:5,Jul:6,Aug:7,Sep:8,Oct:9,Nov:10,Dec:11};
const header=/^\[(\d{1,2}-[A-Za-z]{3}-\d{4} \d\d:\d\d:\d\d(?:\.\d+)?(?:\s+[^\]]+)?)\]\s*(.*)$/;
const diagnostic=/\bPHP\s+(Fatal error|Recoverable fatal error|Parse error|Warning|Notice|Deprecated|Strict Standards|Core error|Core warning|Compile error|Compile warning|User warning|User notice|User deprecated):\s*([^\r\n]*)/i;
const slowHeader=/^\[pool\s+[^\]]+\]\s+pid\s+\d+/i;

export function isPhpLogLine(line){
  const value=line.trim(),match=value.match(header);
  if(match)return /^(?:PHP\s+|PHP message:\s*PHP\s+|(?:ERROR|WARNING|NOTICE|DEBUG):\s*|\[pool\s+[^\]]+\]\s+pid\s+\d+)/i.test(match[2]);
  return /^(?:PHP\s+|PHP message:\s*PHP\s+)/i.test(value);
}

export function startsPhpEvent(line){return isPhpLogLine(line)}

function zoneOffset(zone,epoch){
  const pieces=new Intl.DateTimeFormat('en-GB',{timeZone:zone,year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit',hourCycle:'h23'}).formatToParts(new Date(epoch));
  const p=Object.fromEntries(pieces.map(piece=>[piece.type,piece.value]));
  return Math.round((Date.UTC(Number(p.year),Number(p.month)-1,Number(p.day),Number(p.hour),Number(p.minute),Number(p.second))-Math.floor(epoch/1000)*1000)/60000);
}

function phpTime(raw){
  const match=raw.match(/^(\d{1,2})-([A-Za-z]{3})-(\d{4}) (\d\d):(\d\d):(\d\d)(\.\d+)?(?:\s+(\S+))?$/);
  if(!match||months[match[2]]===undefined)return {timestamp:null,warning:'PHP-Zeitstempel nicht lesbar'};
  const [,day,month,year,hour,minute,second,fraction='',zone]=match;
  const local=`${year}-${String(months[month]+1).padStart(2,'0')}-${day.padStart(2,'0')}T${hour}:${minute}:${second}${fraction}`;
  if(!zone)return {timestamp:local};
  if(/^(?:UTC|GMT|Z)$/i.test(zone))return {timestamp:local+'Z'};
  if(/^[+-]\d\d:?(?:\d\d)$/.test(zone))return {timestamp:local+zone.replace(/^([+-]\d\d)(\d\d)$/,'$1:$2')};
  try{
    const naive=Date.UTC(Number(year),months[month],Number(day),Number(hour),Number(minute),Number(second),Number((fraction.slice(1)+'000').slice(0,3)));
    let offset=zoneOffset(zone,naive),utc=naive-offset*60000;
    const actual=zoneOffset(zone,utc);
    if(actual!==offset){offset=actual;utc=naive-offset*60000}
    return {timestamp:new Date(utc).toISOString()};
  }catch{return {timestamp:null,warning:'Unbekannte PHP-Zeitzone: '+zone}}
}

function details(message,raw){
  const hit=message.match(diagnostic),level=hit?.[1]??null,body=hit?.[2]??message;
  const slow=slowHeader.test(message)||/executing too slow|slow request/i.test(message);
  const kind=slow?'slow':/fatal|core error|compile error/i.test(level??'')?'fatal':/parse error/i.test(level??'')?'parse':/warning/i.test(level??'')?'warning':/deprecated/i.test(level??'')?'deprecated':/notice|strict/i.test(level??'')?'notice':/\bERROR:/.test(message)?'error':/\bWARNING:/.test(message)?'warning':'info';
  const fileLine=(body+'\n'+raw).match(/\b(?:thrown\s+)?in\s+(.+?)(?:\s+on\s+line\s+(\d+)|:(\d+))(?=\s*(?:["']|$|\n))/im);
  const script=raw.match(/^script_filename\s*=\s*(.+)$/im)?.[1]?.trim()??message.match(/\bscript\s+'([^']+)'/)?.[1]??null;
  const stackFrames=[...raw.matchAll(/^\s*#\d+\s+(.+)$/gm)].map(match=>match[1]);
  const pool=message.match(/\[pool\s+([^\]]+)\]/i)?.[1]??null;
  const pid=message.match(/\b(?:pid|child)\s+(\d+)/i)?.[1]??null;
  const duration=message.match(/executing too slow\s*\(([\d.]+)\s*sec\)/i)?.[1];
  const request=message.match(/request:\s*"([A-Z]+)\s+([^"\s]+)/i);
  const exceptionClass=body.match(/\bUncaught\s+([\w\\]+)(?::|\s)/)?.[1]??null;
  return {kind,phpLevel:level,file:fileLine?.[1]?.trim()??script,line:fileLine?Number(fileLine[2]??fileLine[3]):null,script,stackFrames,pool,pid:pid?Number(pid):null,durationMs:duration?Number(duration)*1000:null,requestMethod:request?.[1]??null,requestPath:request?.[2]??null,exceptionClass,description:body.trim()};
}

export function parsePhpBlock(raw){
  const first=raw.split('\n')[0],match=first.match(header),message=match?match[2]:first;
  const time=match?phpTime(match[1]):{timestamp:null};
  const fields=details(message,raw);
  if(time.warning)fields.timeWarning=time.warning;
  const level=fields.kind==='fatal'||fields.kind==='parse'||fields.kind==='error'?'error':fields.kind==='warning'||fields.kind==='slow'?'warn':'info';
  return {message:fields.description||message,ts:time.timestamp,timestampRaw:match?.[1]??null,level,host:null,service:/\[pool\s+[^\]]+\]/i.test(message)?'php-fpm':'php',process:null,pid:fields.pid,fields,warnings:time.warning?[time.warning]:[]};
}

export function phpRecord(event){
  if(event.parserId==='php-error')return {...event.fields,event,kind:event.fields.kind??'info'};
  const message=String(event.message??'');
  if(!diagnostic.test(message)&&!/(?:^|\s)PHP message:\s*PHP\s+/i.test(message)&&!/^php(?:-fpm)?(?:\d+(?:\.\d+)?)?(?:\.service)?$/i.test(event.service??''))return null;
  const fields=details(message,event.raw??message);
  if(fields.kind==='info'&&!diagnostic.test(message))return null;
  return {...fields,event};
}

function increment(map,key){if(key!==null&&key!==undefined&&key!=='')map.set(String(key),(map.get(String(key))??0)+1)}
function ranked(map,limit=10){return [...map].sort((a,b)=>b[1]-a[1]||a[0].localeCompare(b[0])).slice(0,limit).map(([label,count])=>({label,count}))}

export function analyzePhp(events,{source='all',kind='all'}={}){
  const counts={fatal:0,parse:0,warning:0,deprecated:0,notice:0,slow:0,error:0,info:0};
  const files=new Map(),exceptions=new Map(),pools=new Map(),signatures=new Map(),sources=new Map(),days=new Map();
  const hours=Array.from({length:7},()=>Array(24).fill(0)),recent=[],slowest=[];
  let total=0,dated=0,undated=0,stackCount=0;
  for(const event of events){
    const record=phpRecord(event);
    if(!record||source!=='all'&&event.sourceId!==source||kind!=='all'&&record.kind!==kind)continue;
    total++;counts[record.kind]=(counts[record.kind]??0)+1;
    increment(files,record.file);increment(exceptions,record.exceptionClass);increment(pools,record.pool);increment(sources,event.sourceId);
    const signature=(record.phpLevel??record.kind)+': '+record.description.replace(/\b\d+\b/g,'#').slice(0,180);
    increment(signatures,signature);
    if(record.stackFrames?.length)stackCount++;
    if(record.kind==='slow'&&Number.isFinite(record.durationMs)){slowest.push(record);slowest.sort((a,b)=>b.durationMs-a.durationMs);if(slowest.length>10)slowest.pop()}
    if(event.timestampUtc){const date=new Date(event.timestampUtc);if(Number.isFinite(date.getTime())){dated++;increment(days,event.timestampUtc.slice(0,10));hours[(date.getUTCDay()+6)%7][date.getUTCHours()]++}else undated++}else undated++;
    recent.push(record);recent.sort((a,b)=>(a.event.timestampUtc??'').localeCompare(b.event.timestampUtc??''));if(recent.length>20)recent.shift();
  }
  recent.sort((a,b)=>(b.event.timestampUtc??'').localeCompare(a.event.timestampUtc??''));
  return {total,counts,dated,undated,stackCount,sourceCount:sources.size,fileCount:files.size,files:ranked(files),exceptions:ranked(exceptions),pools:ranked(pools),signatures:ranked(signatures),days:[...days].sort((a,b)=>a[0].localeCompare(b[0])).map(([label,count])=>({label,count})),hours,recent,slowest};
}
