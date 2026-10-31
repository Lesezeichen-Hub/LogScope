const ACCESS_FORMATS=new Set(['web-access','caddy-json']);
function finiteNumber(value){if(value===null||value===undefined||value===''||value==='-')return null;const n=Number(value);return Number.isFinite(n)?n:null}
function first(...values){return values.find(value=>value!==null&&value!==undefined&&value!==''&&value!=='-')??null}
function text(value){return typeof value==='string'&&value.trim()?value.trim():null}
function header(headers,name){if(!headers||typeof headers!=='object')return null;const key=Object.keys(headers).find(key=>key.toLowerCase()===name);const value=key&&headers[key];return text(Array.isArray(value)?value[0]:value)}
function pathOnly(value){if(!value)return null;let path=value;if(/^[a-z][a-z0-9+.-]*:\/\//i.test(path)){try{path=new URL(path).pathname}catch{return null}}else path=path.split(/[?#]/,1)[0];return path.slice(0,300)||'/'}
function referrerHost(value){if(!value)return null;try{return new URL(value).host||null}catch{return pathOnly(value)}}
function requestParts(value){if(typeof value!=='string')return {};const match=value.match(/^([A-Z]+)\s+(\S+)(?:\s+(HTTP\/\d(?:\.\d)?))?$/i);return match?{method:match[1].toUpperCase(),path:pathOnly(match[2]),protocol:match[3]??null}:{}}
function count(map,key){if(key!==null&&key!==undefined&&key!=='')map.set(String(key),(map.get(String(key))??0)+1)}
function top(map,limit=10){return [...map].sort((a,b)=>b[1]-a[1]||a[0].localeCompare(b[0])).slice(0,limit).map(([label,count])=>({label,count}))}
function percentile(sorted,p){if(!sorted.length)return null;const index=(sorted.length-1)*p,low=Math.floor(index),high=Math.ceil(index);return sorted[low]+(sorted[high]-sorted[low])*(index-low)}
function durationMs(event){const f=event.fields??{};const seconds=event.parserId==='caddy-json'?finiteNumber(f.duration):first(finiteNumber(f.request_time),finiteNumber(f.requestTime));return seconds!==null&&seconds>=0?seconds*1000:null}

export function accessRecord(event){
  const f=event.fields??{},request=f.request&&typeof f.request==='object'?f.request:{};
  const status=finiteNumber(first(f.status,f.status_code,f.statusCode,f.response?.status));
  if(status===null||status<100||status>599||!Number.isInteger(status))return null;
  const isWeb=ACCESS_FORMATS.has(event.parserId);
  const jsonAccess=event.parserId==='jsonl'&&(request.method||request.uri||f.request_method||f.request_uri||typeof f.request==='string');
  if(!isWeb&&!jsonAccess)return null;
  const parts=requestParts(typeof f.request==='string'?f.request:null);
  const method=text(first(request.method,f.method,f.request_method,parts.method))?.toUpperCase()??null;
  const path=pathOnly(text(first(request.uri,request.url,f.uri,f.path,f.request_uri,parts.path)));
  const bytes=finiteNumber(first(f.bytes,f.size,f.body_bytes_sent,f.bytes_sent));
  const client=text(first(f.remoteAddress,request.remote_ip,request.client_ip,request.remote_addr,f.remote_addr,f.remote_ip,f.client_ip));
  const host=text(first(request.host,f.host,event.host));
  const agent=text(first(f.userAgent,f.http_user_agent,header(request.headers,'user-agent')));
  const referrer=referrerHost(text(first(f.referrer,f.http_referer,header(request.headers,'referer'))));
  return {sourceId:event.sourceId,timestamp:event.timestampUtc,status,method,path,bytes:bytes!==null&&bytes>=0?bytes:null,durationMs:durationMs(event),client,host,agent,referrer,protocol:text(first(f.protocol,request.proto,parts.protocol))};
}

export function accessYears(events){const years=new Map();for(const event of events){const record=accessRecord(event);if(record?.timestamp){const year=record.timestamp.slice(0,4);years.set(year,(years.get(year)??0)+1)}}return [...years].sort((a,b)=>a[0].localeCompare(b[0]))}
export function analyzeAccess(events,{source='all',year='all',bucket='day'}={}){
  const maps={status:new Map(),statusClass:new Map(),method:new Map(),path:new Map(),failedPath:new Map(),client:new Map(),host:new Map(),agent:new Map(),referrer:new Map(),protocol:new Map(),source:new Map(),time:new Map()};
  const clients=new Set(),latencies=[],hourly=Array(24).fill(0),week=Array.from({length:7},()=>Array(24).fill(0));
  let requests=0,bytes=0,bytesKnown=0,dated=0,undated=0,firstTime=null,lastTime=null;
  for(const event of events){
    const r=accessRecord(event);if(!r||source!=='all'&&r.sourceId!==source||year!=='all'&&(!r.timestamp||!r.timestamp.startsWith(year+'-')))continue;
    requests++;count(maps.source,r.sourceId);count(maps.status,r.status);count(maps.statusClass,Math.floor(r.status/100)+'xx');
    count(maps.method,r.method);count(maps.path,r.path);if(r.status>=400)count(maps.failedPath,r.path);
    count(maps.client,r.client);count(maps.host,r.host);count(maps.agent,r.agent);count(maps.referrer,r.referrer);count(maps.protocol,r.protocol);
    if(r.client)clients.add(r.client);
    if(r.bytes!==null){bytes+=r.bytes;bytesKnown++}
    if(r.durationMs!==null)latencies.push(r.durationMs);
    if(r.timestamp){const d=new Date(r.timestamp);if(Number.isFinite(d.getTime())){dated++;if(!firstTime||r.timestamp<firstTime)firstTime=r.timestamp;if(!lastTime||r.timestamp>lastTime)lastTime=r.timestamp;const h=d.getUTCHours(),day=(d.getUTCDay()+6)%7;hourly[h]++;week[day][h]++;const key=bucket==='hour'?r.timestamp.slice(0,13)+':00':bucket==='month'?r.timestamp.slice(0,7):r.timestamp.slice(0,10);count(maps.time,key)}else undated++}else undated++;
  }
  latencies.sort((a,b)=>a-b);
  const status=Object.fromEntries(maps.statusClass);
  const time=[...maps.time].sort((a,b)=>a[0].localeCompare(b[0])).map(([label,count])=>({label,count}));
  return {requests,sourceCount:maps.source.size,status,errors4xx:status['4xx']??0,errors5xx:status['5xx']??0,clients:clients.size,bytes,bytesKnown,dated,undated,firstTime,lastTime,latencyCount:latencies.length,p50:percentile(latencies,.5),p95:percentile(latencies,.95),p99:percentile(latencies,.99),hourly,week,time,top:Object.fromEntries(Object.entries(maps).filter(([key])=>key!=='time').map(([key,map])=>[key,top(map)]))};
}
