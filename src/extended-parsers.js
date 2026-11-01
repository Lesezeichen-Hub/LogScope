// Offline parsers for common web, database, AWS and container exports.
import {isPhpLogLine,parsePhpBlock,startsPhpEvent} from './php-logs.js';
const mongoCode={F:'fatal',E:'error',W:'warning',I:'info',D:'debug'};
const month={Jan:'01',Feb:'02',Mar:'03',Apr:'04',May:'05',Jun:'06',Jul:'07',Aug:'08',Sep:'09',Oct:'10',Nov:'11',Dec:'12'};
const db2Header=/^(\d{4}-\d\d-\d\d-\d\d\.\d\d\.\d\d\.\d{1,9}[+-]\d{1,4})\s+/;
const criLine=/^(\d{4}-\d\d-\d\dT\S+)\s+(stdout|stderr)\s+([FP])\s?(.*)$/;
const albLine=/^(?:http|https|h2|grpcs|ws|wss)\s+\d{4}-\d\d-\d\dT\S+\s+\S+\s+/;
const accessLine=/^\s*((?:[^\s"\[\]]+\s+)+)\[(\d{1,2}\/\w{3}\/\d{4}:\d\d:\d\d:\d\d\s+[+-]\d{4})\]\s+"((?:\\.|[^"\\\r\n])*)"\s+(\d{3}|-)\s+(\d+|-)(?=\s|$)/;
const redisLine=/^\s*(\d+):([MCSX])\s+(\d{1,2})\s+(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(\d{4})\s+(\d\d:\d\d:\d\d(?:\.\d{1,6})?)\s+([.\-*#])\s+(.+)$/;
const nginxError=/^\d{4}\/\d\d\/\d\d \d\d:\d\d:\d\d \[(?:error|warn|notice|info|debug|crit|alert|emerg)\]/i;
const apacheError=/^\[[A-Za-z]{3} [A-Za-z]{3} \d{1,2} \d\d:\d\d:\d\d(?:\.\d+)? \d{4}\] \[[^\]]+:(?:error|warn|notice|info|debug|crit|alert|emerg)\]/i;
const mysqlError=/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)?\s+(?:\d+\s+)?\[(?:ERROR|Warning|Note|System)\]\s+\[MY-\d+\]/i;

export const extendedFormats=['web-access','nginx-error','apache-error','php-error','mysql-error','mysql-error-json','mysql-slow','mysql-general','mongodb-json','mongodb-text','db2diag','postgresql-stderr','postgresql-json','postgresql-csv','redis','aws-cloudtrail','aws-cloudwatch','aws-alb','aws-vpc','aws-waf','aws-s3','aws-cloudfront','aws-ecs','aws-lambda','k8s-cri','k8s-klog','k8s-docker-json','k8s-audit-json','k8s-event-json','twisted'];

export function detectExtended(sample){
  const lines=sample.trim().split(/\r?\n/).slice(0,30), first=lines.find(x=>x.trim())||'';
  if(/^<\d{1,3}>1 \S+ \S+ \S+ \S+ \S+ (?:-|\[)/.test(first))return {format:'syslog',confidence:.98};
  if(/"Records"\s*:\s*\[/.test(sample)&&/"eventVersion"|"eventSource"/.test(sample))return {format:'aws-cloudtrail',confidence:.96};
  if(/"logEvents"\s*:\s*\[/.test(sample)&&/"timestamp"|"message"/.test(sample))return {format:'aws-cloudwatch',confidence:.9};
  if(/"kind"\s*:\s*"EventList"/.test(sample)&&/"items"\s*:\s*\[/.test(sample))return {format:'k8s-event-json',confidence:.96};
  if(/^#Fields:\s+date\s+time\s+/m.test(sample)&&/x-edge-location|sc-status/.test(sample))return {format:'aws-cloudfront',confidence:.97};
  if(criLine.test(first))return {format:'k8s-cri',confidence:.97};
  if(/^(?:CRITICAL|ERROR|WARNING|INFO|DEBUG):twisted:/i.test(first))return {format:'twisted',confidence:.97};
  if(/^[IWEF]\d{4}\s+\d\d:\d\d:\d\d\.\d+\s+\d+\s+\S+:\d+\]/.test(first))return {format:'k8s-klog',confidence:.95};
  if(db2Header.test(first))return {format:'db2diag',confidence:.96};
  if(albLine.test(first))return {format:'aws-alb',confidence:.94};
  if(/^\S+\s+\S+\s+\[\d{1,2}\/\w{3}\/\d{4}:\d\d:\d\d:\d\d [+-]\d{4}\]\s+\S+\s+\S+\s+\S+\s+\S+/.test(first))return {format:'aws-s3',confidence:.9};
  const flow=first.trim().split(/\s+/);
  if(/^version\s+account-id\s+interface-id\s+/i.test(first)||flow.length>=14&&/^\d+$/.test(flow[0])&&/^\d{12}$/.test(flow[1])&&/^eni-/.test(flow[2])&&['ACCEPT','REJECT'].includes(flow[12]))return {format:'aws-vpc',confidence:.94};
  if(accessLine.test(first))return {format:'web-access',confidence:.9};
  if(isPhpLogLine(first))return {format:'php-error',confidence:.93};
  if(redisLine.test(first))return {format:'redis',confidence:.98};
  if(nginxError.test(first))return {format:'nginx-error',confidence:.93};
  if(apacheError.test(first))return {format:'apache-error',confidence:.93};
  if(mysqlError.test(first))return {format:'mysql-error',confidence:.94};
  if(/^\d{4}-\d\d-\d\d[ T]/.test(first)&&first.includes(',')){const row=parseCsv(first);if(row.length>=14&&/^(?:LOG|ERROR|FATAL|PANIC|WARNING|NOTICE|INFO|DEBUG\d?)$/.test(row[11]||''))return {format:'postgresql-csv',confidence:.93}}
  if(/^\d{4}-\d\d-\d\d[ T]\d\d:\d\d:\d\d(?:\.\d+)?\s+(?:UTC|[+-]\d\d(?::?\d\d)?)\s+\[\d+\]\s+(?:LOG|ERROR|FATAL|PANIC|WARNING|NOTICE|INFO|DEBUG\d?):/.test(first))return {format:'postgresql-stderr',confidence:.92};
  if(/^\d{4}-\d\d-\d\dT\S+\s+[FIWED]\s+\w+\s+\[[^\]]+\]/.test(first))return {format:'mongodb-text',confidence:.88};
  if(/^(?:START|END|REPORT) RequestId: [\w-]+/.test(first))return {format:'aws-lambda',confidence:.8};
  if(first.startsWith('{')){
    try{
      const o=JSON.parse(first);
      if(o?.t?.$date&&o.s&&o.c&&o.msg!==undefined)return {format:'mongodb-json',confidence:.98};
      if(o.prio!==undefined&&o.msg!==undefined&&o.err_code!==undefined)return {format:'mysql-error-json',confidence:.96};
      if(o.timestamp&&o.error_severity&&o.message!==undefined)return {format:'postgresql-json',confidence:.97};
      if(o.eventVersion&&o.eventSource&&o.eventName)return {format:'aws-cloudtrail',confidence:.98};
      if(o.webaclId&&o.httpRequest&&o.action)return {format:'aws-waf',confidence:.97};
      if(o.ecs_cluster&&o.ecs_task_arn&&o.log!==undefined)return {format:'aws-ecs',confidence:.95};
      if(o.auditID&&o.stage&&o.requestURI)return {format:'k8s-audit-json',confidence:.97};
      if(o.kind==='Event'&&(o.involvedObject||o.regarding)&&(o.reason||o.note))return {format:'k8s-event-json',confidence:.95};
      if(typeof o.log==='string'&&o.stream&&o.time)return {format:'k8s-docker-json',confidence:.95};
      if((o.logEvents&&Array.isArray(o.logEvents))||o.logGroupName&&o.logStreamName)return {format:'aws-cloudwatch',confidence:.91};
      if(o.requestId&&o.type&&o.record||o.level&&o.requestId&&o.timestamp)return {format:'aws-lambda',confidence:.78};
    }catch{}
  }
  if(lines.some(line=>accessLine.test(line)))return {format:'web-access',confidence:.8};
  if(lines.some(isPhpLogLine))return {format:'php-error',confidence:.8};
  if(lines.some(line=>redisLine.test(line)))return {format:'redis',confidence:.85};
  return null;
}

function parseApacheTime(raw){const m=raw.match(/^(\d{1,2})\/(\w{3})\/(\d{4}):(\d\d:\d\d:\d\d)\s+([+-]\d\d)(\d\d)$/);return m&&month[m[2]]?`${m[3]}-${month[m[2]]}-${m[1].padStart(2,'0')}T${m[4]}${m[5]}:${m[6]}`:null}
function parseApacheErrorTime(raw){const m=raw.match(/^\w{3}\s+(\w{3})\s+(\d{1,2})\s+(\d\d:\d\d:\d\d(?:\.\d+)?)\s+(\d{4})$/);return m&&month[m[1]]?`${m[4]}-${month[m[1]]}-${m[2].padStart(2,'0')}T${m[3]}`:null}
function parseDb2Time(raw){const m=raw.match(/^(\d{4}-\d\d-\d\d)-(\d\d)\.(\d\d)\.(\d\d)\.(\d+)([+-])(\d{1,4})$/);if(!m)return null;const offset=Number(m[7]),h=String(Math.floor(offset/60)).padStart(2,'0'),min=String(offset%60).padStart(2,'0');return `${m[1]}T${m[2]}:${m[3]}:${m[4]}.${m[5]}${m[6]}${h}:${min}`}
function tokens(line){return line.match(/"(?:\\.|[^"\\])*"|\[[^\]]*\]|\S+/g)?.map(x=>x[0]==='"'?x.slice(1,-1):x)||[]}
function accessClient(columns){return columns.find(value=>/^(?:\d{1,3}\.){3}\d{1,3}$/.test(value)||value.includes(':')&&/^[\da-f:.]+$/i.test(value))??columns[0]}
function accessTail(line){
  const parts=line.match(/"(?:\\.|[^"\\])*"|\S+/g)||[],values=parts.map(part=>part[0]==='"'?part.slice(1,-1):part);
  const quoted=parts.flatMap((part,index)=>part[0]==='"'?[index]:[]);
  if(quoted.length<2)return {referrer:values[0]??null,userAgent:values[1]??null,extraColumns:values.slice(2)};
  const [refIndex,agentIndex]=quoted;
  return {referrer:values[refIndex],userAgent:values[agentIndex],extraColumns:values.filter((_,index)=>index!==refIndex&&index!==agentIndex)};
}
function parseCsv(raw){const cells=[];let value='',quoted=false;for(let i=0;i<raw.length;i++){const c=raw[i];if(c==='"'){if(quoted&&raw[i+1]==='"'){value+='"';i++}else quoted=!quoted}else if(c===','&&!quoted){cells.push(value);value=''}else value+=c}cells.push(value);return cells}
function firstMatch(raw,re){return raw.match(re)?.[1]||null}

export function parseExtended(raw,format,context={}){
  const first=raw.split('\n')[0],result={message:first,ts:null,timestampRaw:null,level:null,host:null,service:null,process:null,pid:null,fields:{},warnings:[]};
  const r=result,f=r.fields;
  try{
    if(format==='php-error')return parsePhpBlock(raw);
    if(format==='web-access'){
      const m=first.match(accessLine);if(!m){r.warnings.push('Access-Zeile nicht erkannt');return r}
      const prefixColumns=m[1].trim().split(/\s+/),tail=accessTail(first.slice(m[0].length)),client=accessClient(prefixColumns);r.ts=parseApacheTime(m[2]);r.timestampRaw=m[2];r.host=null;r.service='web';r.message=m[3];Object.assign(f,{remoteAddress:client,request:m[3],status:Number(m[4])||null,bytes:m[5]==='-'?null:Number(m[5]),referrer:tail.referrer,userAgent:tail.userAgent});
      if(prefixColumns.length!==3||prefixColumns[0]!==client||prefixColumns[1]!=='-'||prefixColumns[2]!=='-')f.prefixColumns=prefixColumns;
      if(tail.extraColumns.length)f.extraColumns=tail.extraColumns;
    }else if(format==='redis'){
      const m=first.match(redisLine);if(!m){r.warnings.push('Redis-Zeile nicht erkannt');return r}
      r.ts=`${m[5]}-${month[m[4]]}-${m[3].padStart(2,'0')}T${m[6]}`;r.timestampRaw=`${m[3]} ${m[4]} ${m[5]} ${m[6]}`;r.pid=Number(m[1]);r.service='redis';r.message=m[8];r.level=({'.':'debug','-':'info','*':'notice','#':'warning'})[m[7]];Object.assign(f,{role:m[2],logLevel:({'.':'debug','-':'verbose','*':'notice','#':'warning'})[m[7]]});
    }else if(format==='nginx-error'){
      const m=first.match(/^(\d{4}\/\d\d\/\d\d \d\d:\d\d:\d\d) \[([^\]]+)\] (\d+)#(\d+):\s*(.*)$/);if(!m){r.warnings.push('Nginx-Fehlerzeile nicht erkannt');return r}r.ts=m[1].replace(/^(\d{4})\/(\d\d)\/(\d\d) /,'$1-$2-$3T');r.timestampRaw=m[1];r.level=m[2];r.pid=Number(m[3]);r.service='nginx';r.message=m[5];Object.assign(f,{threadId:Number(m[4]),connectionId:firstMatch(m[5],/\*(\d+)/),client:firstMatch(m[5],/client:\s*([^,]+)/),server:firstMatch(m[5],/server:\s*([^,]+)/),request:firstMatch(m[5],/request:\s*"([^"]+)/)});
    }else if(format==='apache-error'){
      const m=first.match(/^\[([^\]]+)\] \[([^:\]]+):([^\]]+)\](?: \[pid (\d+)(?::tid (\d+))?\])?\s*(.*)$/);if(!m){r.warnings.push('Apache-Fehlerzeile nicht erkannt');return r}r.ts=parseApacheErrorTime(m[1]);r.timestampRaw=m[1];r.level=m[3];r.pid=Number(m[4])||null;r.service='apache';r.message=m[6];Object.assign(f,{module:m[2],threadId:Number(m[5])||null});
    }else if(format==='mysql-error'){
      const m=first.match(/^(\S+)\s+(?:(\d+)\s+)?\[([^\]]+)\](?:\s+\[([^\]]+)\])?(?:\s+\[([^\]]+)\])?\s*(.*)$/);if(!m){r.warnings.push('MySQL-Fehlerzeile nicht erkannt');return r}r.ts=m[1];r.pid=Number(m[2])||null;r.level=m[3];r.service='mysql';r.message=m[6];Object.assign(f,{errorCode:m[4]||null,subsystem:m[5]||null});
    }else if(format==='mysql-error-json'){
      const o=JSON.parse(first);r.ts=o.time??o.ts??null;r.pid=Number(o.thread)||null;r.level=o.label??null;r.service='mysql';r.message=String(o.msg??first);r.fields=o;
    }else if(format==='mongodb-json'){
      const o=JSON.parse(first);r.ts=o.t?.$date??null;r.level=mongoCode[String(o.s)[0]]||o.s;r.service='mongodb';r.process=o.ctx??null;r.message=String(o.msg??first);r.fields=o;
    }else if(format==='mongodb-text'){
      const m=first.match(/^(\S+)\s+([FIWED])\s+(\S+)\s+\[([^\]]+)\]\s*(.*)$/);if(!m){r.warnings.push('MongoDB-Textzeile nicht erkannt');return r}r.ts=m[1];r.level=mongoCode[m[2]];r.service='mongodb';r.process=m[4];r.message=m[5];Object.assign(f,{component:m[3],context:m[4]});
    }else if(format==='db2diag'){
      const m=first.match(db2Header);if(!m){r.warnings.push('Db2-Diagnosekopf nicht erkannt');return r}r.ts=parseDb2Time(m[1]);r.timestampRaw=m[1];r.service='db2';r.level=firstMatch(first,/\bLEVEL:\s*(\w+)/i);r.pid=Number(firstMatch(raw,/\bPID\s*:\s*(\d+)/))||null;r.process=firstMatch(raw,/\bPROC\s*:\s*(\S+)/);r.message=firstMatch(raw,/^MESSAGE\s*:\s*(.*)$/m)||first;Object.assign(f,{recordId:firstMatch(first,/\s(\S+)\s+LEVEL:/),instance:firstMatch(raw,/\bINSTANCE\s*:\s*(\S+)/),database:firstMatch(raw,/\bDB\s*:\s*(\S+)/),function:firstMatch(raw,/^FUNCTION\s*:\s*(.*)$/m),messageId:firstMatch(r.message,/^([A-Z]{3}\d+[A-Z])/),threadId:firstMatch(raw,/\bTID\s*:\s*(\d+)/),eduId:firstMatch(raw,/\bEDUID\s*:\s*(\d+)/),eduName:firstMatch(raw,/\bEDUNAME\s*:\s*(.*)$/m),member:firstMatch(raw,/\b(?:MEMBER|NODE)\s*:\s*(\d+)/),probe:firstMatch(raw,/\bprobe\s*:\s*(\d+)/i),sqlCode:firstMatch(raw,/\bSQLCODE\s*[:=]\s*(-?\d+)/i),sqlState:firstMatch(raw,/\bSQLSTATE\s*[:=]\s*["']?([A-Z0-9]{5})/i),zrc:firstMatch(raw,/\bZRC\s*[:=]\s*(\S+)/),dataBlocks:raw.split(/(?=^DATA #\d+)/m).slice(1)});
    }else if(format==='postgresql-stderr'){
      const m=first.match(/^(\d{4}-\d\d-\d\d[ T]\d\d:\d\d:\d\d(?:\.\d+)?)\s+(UTC|[+-]\d\d(?::?\d\d)?)\s+\[(\d+)\]\s+(\w+(?:\d+)?):\s*(.*)$/);if(!m){r.warnings.push('PostgreSQL-Zeile nicht erkannt');return r}
      r.ts=m[1].replace(' ','T')+(m[2]==='UTC'?'Z':m[2]);r.pid=Number(m[3]);r.level=m[4];r.service='postgresql';r.message=m[5];Object.assign(f,{detail:firstMatch(raw,/^DETAIL:\s*(.*)$/m),hint:firstMatch(raw,/^HINT:\s*(.*)$/m),statement:firstMatch(raw,/^STATEMENT:\s*(.*)$/m)});
    }else if(format==='postgresql-json'){
      const o=JSON.parse(first);r.ts=typeof o.timestamp==='string'?o.timestamp.replace(' ','T').replace(/ UTC$/,'Z'):o.timestamp??null;r.pid=Number(o.pid)||null;r.level=o.error_severity??null;r.service='postgresql';r.message=String(o.message??first);r.fields=o;
    }else if(format==='postgresql-csv'){
      const cells=parseCsv(raw);if(cells.length<14){r.warnings.push('PostgreSQL-CSV-Zeile unvollständig');return r}
      r.ts=cells[0].replace(' ','T').replace(/ UTC$/,'Z');r.pid=Number(cells[3])||null;r.level=cells[11];r.service='postgresql';r.message=cells[13];Object.assign(f,{user:cells[1],database:cells[2],client:cells[4],sessionId:cells[5],sessionLine:cells[6],commandTag:cells[7],sqlState:cells[12],detail:cells[14]??null,hint:cells[15]??null,statement:cells[19]??null,columns:cells});
    }else if(format==='aws-cloudtrail'){
      const o=JSON.parse(raw);r.ts=o.eventTime??null;r.service=o.eventSource??'cloudtrail';r.process=o.eventName??null;r.message=`${o.eventSource??'AWS'} ${o.eventName??'Ereignis'}${o.errorCode?' · '+o.errorCode:''}`;r.level=o.errorCode?'error':'info';r.fields=o;
    }else if(format==='aws-cloudwatch'){
      const o=JSON.parse(raw);r.ts=o.timestamp??o.eventTime??o['@timestamp']??null;r.service=o.logGroupName??o.logGroup??context.cloudWatchLogGroup??'cloudwatch';r.message=String(o.message??o['@message']??first);r.level=o.level??o.severity??null;r.fields=o;
    }else if(format==='aws-alb'){
      const t=tokens(first);if(t.length<14){r.warnings.push('ALB-Zeile unvollständig');return r}r.ts=t[1];r.service='aws-alb';r.message=t[12];Object.assign(f,{type:t[0],loadBalancer:t[2],client:t[3],target:t[4],requestProcessingTime:Number(t[5]),targetProcessingTime:Number(t[6]),responseProcessingTime:Number(t[7]),status:Number(t[8])||null,targetStatus:Number(t[9])||null,receivedBytes:Number(t[10])||null,sentBytes:Number(t[11])||null,request:t[12],userAgent:t[13],extra:t.slice(14)});
    }else if(format==='aws-vpc'){
      const t=first.trim().split(/\s+/);if(t[0]==='version'){r.message='VPC-Flow-Header';r.fields={columns:t};return r}if(t.length<14){r.warnings.push('VPC-Flow-Zeile unvollständig');return r}r.ts=t[10];r.service='aws-vpc';r.message=`${t[3]}:${t[5]} → ${t[4]}:${t[6]} ${t[12]}`;Object.assign(f,{version:t[0],accountId:t[1],interfaceId:t[2],srcaddr:t[3],dstaddr:t[4],srcport:Number(t[5]),dstport:Number(t[6]),protocol:Number(t[7]),packets:Number(t[8]),bytes:Number(t[9]),start:Number(t[10]),end:Number(t[11]),action:t[12],logStatus:t[13],extra:t.slice(14)});
    }else if(format==='aws-waf'){
      const o=JSON.parse(first);r.ts=o.timestamp??null;r.service='aws-waf';r.message=`${o.action??'WAF'} ${o.httpRequest?.httpMethod??''} ${o.httpRequest?.uri??''}`.trim();r.fields=o;
    }else if(format==='aws-s3'){
      const t=tokens(first);if(t.length<15){r.warnings.push('S3-Access-Zeile unvollständig');return r}r.ts=parseApacheTime(t[2].slice(1,-1));r.timestampRaw=t[2];r.service='aws-s3';r.message=t[8];Object.assign(f,{bucketOwner:t[0],bucket:t[1],remoteAddress:t[3],requester:t[4],requestId:t[5],operation:t[6],key:t[7],request:t[8],status:Number(t[9])||null,errorCode:t[10]==='-'?null:t[10],bytesSent:Number(t[11])||null,objectSize:Number(t[12])||null,totalTimeMs:Number(t[13])||null,turnaroundTimeMs:Number(t[14])||null,extra:t.slice(15)});
    }else if(format==='aws-cloudfront'){
      r.service='aws-cloudfront';if(first.startsWith('#')){r.message=first;f.header=true;return r}
      const columns=context.cloudFrontColumns??['date','time','x-edge-location','sc-bytes','c-ip','cs-method','cs(Host)','cs-uri-stem','sc-status'];const values=first.split('\t');if(values.length<9){r.warnings.push('CloudFront-Zeile unvollständig');return r}
      for(let i=0;i<Math.min(columns.length,values.length);i++)f[columns[i]]=values[i];r.ts=`${f.date}T${f.time}Z`;r.timestampRaw=`${f.date} ${f.time}`;r.host=f['cs(Host)']??null;r.message=`${f['cs-method']??''} ${f['cs-uri-stem']??''}`.trim();f.status=Number(f['sc-status'])||null;f.remoteAddress=f['c-ip']??null;
    }else if(format==='aws-ecs'){
      const o=JSON.parse(first);r.ts=o.time??o.timestamp??null;r.service=o.container_name??'aws-ecs';r.message=String(o.log??first).replace(/\n$/,'');r.fields=o;
    }else if(format==='aws-lambda'){
      if(first.startsWith('{')){const o=JSON.parse(first);r.ts=o.timestamp??o.time??null;r.level=o.level??o.severity??null;r.service='aws-lambda';r.message=String(o.message??o.type??first);r.fields=o}else{r.service='aws-lambda';r.message=first;const id=firstMatch(first,/RequestId:\s*([\w-]+)/);if(id)f.requestId=id;f.eventType=first.match(/^(START|END|REPORT)/)?.[1]??null}
    }else if(format==='k8s-cri'){
      const m=first.match(criLine);if(!m){r.warnings.push('CRI-Zeile nicht erkannt');return r}r.ts=m[1];r.service='kubernetes';r.message=raw.split('\n').map(x=>x.match(criLine)?.[4]??x).join('');Object.assign(f,{stream:m[2],partial:raw.includes(' P '),fragments:raw.split('\n').length});
      const name=String(context.fileName??'').match(/^(.+)_([^_]+)_(.+)-([a-f0-9]{16,})\.log$/i);
      if(name)Object.assign(f,{pod:name[1],namespace:name[2],container:name[3],containerId:name[4]});
      if(raw.split('\n').at(-1).match(criLine)?.[3]==='P')r.warnings.push('Letztes CRI-Fragment ist unvollständig');
    }else if(format==='k8s-klog'){
      const m=first.match(/^([IWEF])(\d\d)(\d\d)\s+(\d\d:\d\d:\d\d\.\d+)\s+(\d+)\s+(\S+):(\d+)\]\s*(.*)$/);
      if(!m){r.warnings.push('Klog-Kopf nicht erkannt');return r}
      r.level=mongoCode[m[1]];r.pid=Number(m[5]);r.service='kubernetes';r.process=m[6];r.message=[m[8],...raw.split('\n').slice(1)].join('\n');r.ts=context.year?`${context.year}-${m[2]}-${m[3]}T${m[4]}`:null;r.timestampRaw=`${m[2]}${m[3]} ${m[4]}`;
      Object.assign(f,{caller:m[6],sourceLine:Number(m[7]),timestampPartial:`${m[2]}-${m[3]} ${m[4]}`});
      if(!context.year)r.warnings.push('Klog benötigt ein Bezugsjahr für die Timeline');
    }else if(format==='k8s-docker-json'){
      const o=JSON.parse(first);r.ts=o.time;r.service='container';r.message=String(o.log??'').replace(/\n$/,'');r.fields=o;
    }else if(format==='k8s-audit-json'){
      const o=JSON.parse(first);r.ts=o.requestReceivedTimestamp??o.stageTimestamp??null;r.service='k8s-audit';r.process=o.verb??null;r.message=`${o.verb??'request'} ${o.requestURI??''} ${o.responseStatus?.code??''}`.trim();r.fields=o;
    }else if(format==='k8s-event-json'){
      const o=JSON.parse(raw);r.ts=o.eventTime??o.lastTimestamp??o.metadata?.creationTimestamp??null;r.service='k8s-event';r.host=o.source?.host??null;r.level=o.type==='Warning'?'warn':'info';r.message=String(o.message??o.note??o.reason??first);r.fields=o;
    }else if(format==='twisted'){
      const m=first.match(/^(CRITICAL|ERROR|WARNING|INFO|DEBUG):([^:]+):(.*)$/i);
      if(!m){r.warnings.push('Twisted-Kopf nicht erkannt');return r}
      r.level=m[1];r.service=m[2];r.message=m[3].trim();
      const exception=raw.match(/^(?:[\w.]+(?:Error|Exception)|builtins\.[\w]+):\s*.*$/gm)?.at(-1);
      Object.assign(f,{exception:exception??null,traceback:raw.includes('Traceback (most recent call last):'),frames:(raw.match(/^\s*File "/gm)||[]).length});
      if(exception)r.message+=` · ${exception}`;
    }
  }catch(error){r.warnings.push(`JSON oder Feldstruktur nicht lesbar: ${error.message}`)}
  return r;
}

export function startsNewEvent(format,line,block){
  if(format==='php-error')return startsPhpEvent(line);
  if(block.length&&['db2diag','postgresql-stderr','mysql-error'].includes(format)){
    const other=detectExtended(line)?.format;
    if(other&&other!==format)return true;
  }
  if(format==='db2diag')return db2Header.test(line);
  if(format==='postgresql-stderr')return /^\d{4}-\d\d-\d\d[ T]\d\d:\d\d:\d\d/.test(line);
  if(format==='postgresql-csv')return (block.join('\n').match(/"/g)||[]).length%2===0;
  if(format==='mysql-error')return /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d/.test(line);
  if(format==='k8s-cri'){
    if(!block.length)return true;
    const previous=block.at(-1).match(criLine),current=line.match(criLine);
    return !(previous&&current&&previous[2]===current[2]&&previous[3]==='P');
  }
  if(format==='k8s-klog')return /^[IWEF]\d{4}\s+\d\d:\d\d:\d\d\.\d+\s+\d+\s+\S+:\d+\]/.test(line);
  if(format==='twisted')return /^(?:CRITICAL|ERROR|WARNING|INFO|DEBUG):twisted:/i.test(line);
  return true;
}

export function isExtended(format){return extendedFormats.includes(format)}
