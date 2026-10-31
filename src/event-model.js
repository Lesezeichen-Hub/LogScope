import {sqlFingerprint} from './core.js';
import {accessRecord} from './access-analytics.js';

export const eventSchemaVersion=2;

export function identifyEvent(event,context){
  context.recordSequence=(context.recordSequence||0)+1;
  event.recordSequence=context.recordSequence;
  event.schemaVersion=eventSchemaVersion;
  event.id=event.sourceId+':record:'+event.recordSequence;
  return event;
}

function finite(value){
  if(value===null||value===undefined||typeof value==='boolean'||typeof value==='object'||typeof value==='string'&&!value.trim())return null;
  const number=Number(value);
  return Number.isFinite(number)&&number>=0?number:null;
}

export function normalizeEvent(event,originalLevel=null){
  const fields=event.fields||{},parser=event.parserId||'',message=event.message||'',access=accessRecord(event);
  const product=/^(mysql|mariadb|mongodb|postgresql|db2)/.exec(parser)?.[1]||
    (/^(?:caddy|nginx|apache)/.exec(parser)?.[0])||
    (parser==='web-access'||access?'webserver':/^(syslog|journal)/.test(parser)?'linux':null);
  const domain=/^(mysql|mariadb|mongodb|postgresql|db2)$/.test(product)?'database':
    /^(caddy|nginx|apache|webserver)$/.test(product)?'web':product==='linux'?'system':'other';
  const normalized={domain,product,originalLevel,clientIp:null,user:null,outcome:null,eventType:null,
    database:null,instance:null,operation:null,durationMs:null,lockMs:null,rowsExamined:null,
    status:null,method:null,path:null,bytes:null,httpHost:null,userAgent:null,referrer:null,protocol:null,diagnosticCode:null,queryPattern:null};
  if(domain==='system'){
    let match=message.match(/^(Accepted|Failed) (?:password|publickey|keyboard-interactive(?:\/pam)?) for (?:invalid user )?(\S+) from (\S+) port \d+/);
    if(match)Object.assign(normalized,{eventType:'login',outcome:match[1]==='Accepted'?'success':'failure',user:match[2],clientIp:match[3]});
    if(!match&&/authentication failure/i.test(message)){
      Object.assign(normalized,{eventType:'login',outcome:'failure',user:message.match(/\buser=(\S+)/)?.[1]??null,clientIp:message.match(/\brhost=(\S+)/)?.[1]??null});
    }
    if(/^(?:sudo|sudo\[)/.test(event.process||event.service||'')||/\bsudo:/.test(message)){
      Object.assign(normalized,{eventType:'sudo',user:message.match(/^\s*(\S+)\s*:/)?.[1]??null});
      if(/authentication failure|incorrect password|NOT in sudoers|not allowed/i.test(message))normalized.outcome='failure';
      else if(/COMMAND=/.test(message))normalized.outcome='command';
    }
    if(/out of memory|oom-kill|killed process \d+.*total-vm|invoked oom-killer/i.test(message))normalized.eventType='oom';
    else if(/(?:failed to (?:start|restart)|main process exited|failed with result|entered failed state)/i.test(message)){
      normalized.eventType='service';normalized.outcome='failure';
    }else if(/^(?:Started|Starting|Stopped|Stopping)\s/.test(message)&&/systemd/.test(event.process||event.service||''))normalized.eventType='service';
  }
  if(domain==='web'){
    const request=fields.request,requestText=typeof request==='string'?request:fields.request_uri??'';
    const parts=requestText.match(/^([A-Z]+)\s+(\S+)/);
    normalized.status=finite(fields.status??fields.statusCode);
    normalized.clientIp=fields.remoteAddress??fields.client??request?.client_ip??request?.remote_ip??null;
    normalized.method=parts?.[1]??request?.method??fields.request_method??null;
    normalized.path=parts?.[2]??request?.uri??fields.uri??null;
    normalized.bytes=finite(fields.bytes??fields.size);
    const seconds=finite(fields.duration??fields.request_time);
    normalized.durationMs=seconds===null?finite(fields.durationMs):seconds*1000;
    normalized.eventType=normalized.status===null?'web-error':'request';
    if(access)Object.assign(normalized,{status:access.status,clientIp:access.client,method:access.method,path:access.path,bytes:access.bytes,durationMs:access.durationMs,httpHost:access.host,userAgent:access.agent,referrer:access.referrer,protocol:access.protocol,eventType:'request'});
  }
  if(domain==='database'){
    const attributes=fields.attr||{};
    normalized.database=fields.database??fields.db??fields.dbname??attributes.ns??attributes.namespace??null;
    normalized.instance=fields.instance??null;
    normalized.user=fields.user??fields.user_name??null;
    normalized.diagnosticCode=fields.sqlState??fields.state_code??fields.sql_state_code??fields.errorCode??fields.err_code??fields.messageId??fields.id??null;
    normalized.rowsExamined=finite(fields.rowsExamined??attributes.docsExamined);
    const querySeconds=finite(fields.queryTime),duration=finite(fields.duration_ms??fields.durationMillis??attributes.durationMillis);
    const loggedDuration=message.match(/\bduration:\s*([\d.]+)\s*ms\b/i);
    normalized.durationMs=querySeconds===null?(duration??(loggedDuration?finite(loggedDuration[1]):null)):querySeconds*1000;
    const lockSeconds=finite(fields.lockTime);
    normalized.lockMs=lockSeconds===null?null:lockSeconds*1000;
    const statement=fields.sql??fields.statement??fields.query??message.match(/\b(?:statement|execute [^:]+):\s*([\s\S]+)/i)?.[1];
    if(typeof statement==='string'&&statement.trim()&&product!=='mongodb'){
      normalized.queryPattern=sqlFingerprint(statement);
      normalized.operation=statement.match(/^\s*(\w+)/)?.[1]?.toUpperCase()??null;
    }
    if(product==='mongodb'){
      normalized.queryPattern=attributes.queryShapeHash??attributes.queryHash??attributes.planCacheShapeHash??null;
      normalized.operation=attributes.type??attributes.commandName??null;
      normalized.instance=fields.ctx??null;
    }
    normalized.eventType=normalized.durationMs!==null?'db-operation':'db-message';
    if(/deadlock|lock wait|SQL0911|SQL0913/i.test(message))normalized.eventType='lock';
    else if(/replication|replica set|replica|GTID|relay.log/i.test(message))normalized.eventType='replication';
  }
  event.normalized=normalized;
  return event;
}

export function upgradeEvents(events){
  const contexts=new Map();
  return events.map(event=>{
    let context=contexts.get(event.sourceId);
    if(!context){context={};contexts.set(event.sourceId,context)}
    const upgraded=normalizeEvent({...event},event.normalized?.originalLevel??event.severity);
    upgraded.legacyId=event.legacyId??event.id;
    return identifyEvent(upgraded,context);
  });
}