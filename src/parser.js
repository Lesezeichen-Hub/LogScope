import {leadingTimestamp} from './generic-time.js';
import {identifyEvent,normalizeEvent} from './event-model.js';
﻿import {parseExtended,isExtended,startsNewEvent} from './extended-parsers.js';
import {detect,time,severity,category,sqlFingerprint,fingerprint} from './core.js';
const ansi=/\x1b\[[0-?]*[ -/]*[@-~]/g;
const lineWiseFormats=new Set(['syslog','journal-text','caddy-console','mariadb-error','mariadb-general','jenkins','web-access','nginx-error','apache-error','mysql-error','mongodb-text','postgresql-stderr','redis','aws-alb','aws-vpc','aws-s3','aws-cloudfront','aws-lambda','k8s-klog','twisted']);
const lineJsonFormats=new Set(['jsonl','journal-json','caddy-json','mongodb-json','postgresql-json','mysql-error-json','aws-waf','aws-ecs','k8s-audit-json','k8s-docker-json']);
export function parseBlock(raw,format,ctx,start,end){if(format==='mysql-slow'||format==='mysql-general'){let e=parseBlock(raw,format==='mysql-slow'?'mariadb-slow':'mariadb-general',ctx,start,end);e.parserId=format;e.service='mysql';return normalizeEvent(e,e.normalized.originalLevel)}let lines=raw.split('\n'),first=lines[0].replace(ansi,'');if(lines.length===1&&(format==='text'||lineJsonFormats.has(format))){const found=detect(first);if(found.confidence>=.8&&found.format!==format)return parseBlock(raw,found.format,ctx,start,end)}let fields={},message=first,ts=null,timestampRawOverride=null,level=null,host=null,service=null,process=null,pid=null,warnings=[];try{
if(isExtended(format)){let x=parseExtended(raw,format,ctx);({message,ts,level,host,service,process,pid,fields}=x);timestampRawOverride=x.timestampRaw;warnings.push(...x.warnings)}
else if(['journal-json','caddy-json','jsonl'].includes(format)){let o=JSON.parse(first);fields=o;message=String(o.MESSAGE??o.msg??o.message??first);ts=o.__REALTIME_TIMESTAMP??o.ts??o.timestamp??o.time??o.time_iso8601??o.msec??null;level=o.PRIORITY??o.level??o.severity??null;host=o._HOSTNAME??o.request?.host??o.host??null;service=o._SYSTEMD_UNIT??o.logger??o.service??null;process=o.SYSLOG_IDENTIFIER??null;pid=Number(o._PID)||null;if(format==='caddy-json'&&o.status>=500)fields.httpError=true}
else if(format==='syslog'){
	const modern=first.match(/^<(\d{1,3})>1 (\S+) (\S+) (\S+) (\S+) (\S+) (-|(?:\[(?:[^\]\\]|\\.)*\])+)(?: (.*))?$/);
	const legacy=first.match(/^(?:<(?<pri>\d+)>)?(?<date>[A-Z][a-z]{2} +\d+ \d\d:\d\d:\d\d|\d{4}-\d\d-\d\dT\S+)\s+(?<host>\S+)\s+(?<proc>[^\s:[]+)(?:\[(?<pid>\d+)\])?:\s*(?<msg>.*)$/);
	let priority=null;
	if(modern){
		ts=modern[2]==='-'?null:modern[2];host=modern[3]==='-'?null:modern[3];
		service=process=modern[4]==='-'?null:modern[4];pid=/^\d+$/.test(modern[5])?Number(modern[5]):null;
		message=modern[8]??'';priority=Number(modern[1]);
		Object.assign(fields,{syslogVersion:1,syslogProcessId:modern[5],syslogMessageId:modern[6],syslogStructuredData:modern[7]});
	}else if(legacy){
		const groups=legacy.groups;
		ts=groups.date;host=groups.host;process=service=groups.proc;pid=Number(groups.pid)||null;message=groups.msg;
		if(groups.pri!==undefined)priority=Number(groups.pri);
	}else warnings.push('Syslog-Zeile nicht erkannt');
	if(priority!==null){
		fields.syslogPriority=priority;fields.syslogFacility=Math.floor(priority/8);fields.syslogSeverity=priority%8;
		if(priority>191)warnings.push('Ungueltige Syslog-Prioritaet');
		else level=priority%8<=3?'error':priority%8===4?'warn':'info';
	}
}
else if(format==='journal-text'){let m=first.match(/^(\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:[.,]\d+)?(?:Z|[+-]\d\d:?\d\d)?)\s+(\S+)\s+([^\s:[]+)(?:\[(\d+)\])?:\s*(.*)$/);if(m){[,ts,host,process,,message]=m;service=process;pid=Number(m[4])||null}}
else if(format==='mariadb-error'){let m=first.match(/^(\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:[.,]\d+)?(?:Z|[+-]\d\d:?\d\d)?)\s+(?:(\d+)\s+)?\[(\w+)\](?:\s+\[([^\]]+)\])?\s*(.*)$/);if(m){ts=m[1];pid=Number(m[2])||null;level=m[3];service='mariadb';fields.subsystem=m[4]||null;message=m[5]}}
else if(format==='mariadb-slow'){
	ts=raw.match(/^# Time:\s*(.+)$/m)?.[1]||null;
	const query=raw.match(/^# Query_time:\s*([\d.]+)\s+Lock_time:\s*([\d.]+)\s+Rows_sent:\s*(\d+)\s+Rows_examined:\s*(\d+)/m);
	if(query)Object.assign(fields,{queryTime:Number(query[1]),lockTime:Number(query[2]),rowsSent:Number(query[3]),rowsExamined:Number(query[4])});
	const user=raw.match(/^# User@Host:\s*(.+)$/m);
	if(user)fields.userHost=user[1];
	fields.database=raw.match(/^# Schema:\s*(\S+)/m)?.[1]??raw.match(/^use\s+`?([^`;\s]+)`?;\s*$/im)?.[1]??null;
	const sql=lines.filter(line=>!line.startsWith('#')&&!/^SET timestamp=/i.test(line)&&!/^use\s+`?[^`;\s]+`?;\s*$/i.test(line)).join('\n').trim();
	fields.sql=sql;fields.sqlFingerprint=sqlFingerprint(sql);fields.sqlType=sql.match(/^\s*(\w+)/)?.[1]?.toUpperCase()||null;
	message=sql||first;service='mariadb';
}
else if(format==='mariadb-general'){let m=first.match(/^(?:(\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:[.,]\d+)?(?:Z|[+-]\d\d:?\d\d)?)\s+)?(\d+)\s+(Query|Connect|Quit|Init DB|Prepare|Execute)\s*(.*)$/i);if(m){ts=m[1]||null;pid=Number(m[2]);fields.command=m[3];message=[m[4],...lines.slice(1)].join('\n');service='mariadb';if(/query|execute/i.test(m[3]))fields.sql=message}}
else if(format==='jenkins'){let m=first.match(/^\[?(\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:[.,]\d+)?(?:Z|[+-]\d\d:?\d\d)?)\]?\s*(.*)$/);if(m){ts=m[1];message=m[2]}let stage=raw.match(/\[Pipeline\] \{ \((.+?)\)/);if(stage)fields.stage=stage[1];let status=raw.match(/Finished: (SUCCESS|FAILURE|ABORTED|UNSTABLE)/);if(status)fields.buildStatus=status[1];let exit=raw.match(/(?:exit code|returned exit code)\s+(\d+)/i);if(exit)fields.exitCode=Number(exit[1]);service='jenkins'}
else if(format==='caddy-console'){let m=first.match(/^(\d{4}-\d\d-\d\d[T ]\S+)\s+(INFO|WARN|ERROR|DEBUG)\s+([^\s]+)\s+(.*)$/i);if(m){ts=m[1];level=m[2];service=m[3];message=m[4]}}
else if(format==='text'){let found=leadingTimestamp(first);if(found){ts=found.normalized;timestampRawOverride=found.raw;message=found.message;fields.timestampPattern=found.pattern}}
}catch(e){warnings.push('JSON nicht lesbar: '+e.message)}
if(lines.length===1&&lineWiseFormats.has(format)&&!ts&&!service&&!Object.keys(fields).length){const found=detect(first);if(found.format!==format&&found.format!=='text'&&found.confidence>=.8)return parseBlock(raw,found.format,ctx,start,end)}
if(!level&&!['web-access','aws-alb','aws-vpc','k8s-cri','k8s-docker-json','k8s-audit-json','aws-s3','aws-cloudfront'].includes(format)){let m=message.match(/\b(ERROR|WARN(?:ING)?|INFO|FATAL|CRITICAL)\b/i);level=m?.[1]||null}let parsed;if(format==='syslog'&&ts&&/^[A-Z][a-z]{2}/.test(ts)){if(ctx.year&&ctx.offsetMinutes!==null&&ctx.offsetMinutes!==undefined){let date=new Date(`${ts} ${ctx.year} UTC`);parsed=Number.isFinite(date.getTime())?time(date.toISOString().slice(0,19),ctx):{utc:null,warning:'Ungültiger Syslog-Zeitstempel'}}else parsed={utc:null,warning:'Syslog benötigt Bezugsjahr und Zeitzone',raw:ts}}else parsed=time(ts,ctx);if(parsed.warning&&ts)warnings.push(parsed.warning);let event={id:null,sourceId:ctx.sourceId,timestampUtc:parsed.utc,timestampRaw:timestampRawOverride??(ts===null?null:String(ts)),timestampPrecision:null,severity:severity(level,format),category:category(message),host,service,process,processId:pid,message,raw,fields,lineStart:start,lineEnd:end,parserId:format,parseWarnings:warnings};event.fingerprint=fingerprint(event);return normalizeEvent(identifyEvent(event,ctx),level)}
export function* parseLines(lines,format,ctx){let buffer=[],start=1,lineNo=0;function flush(end=lineNo){if(!buffer.length)return null;let e=parseBlock(buffer.join('\n'),format,ctx,start,end);buffer=[];return e}for(let line of lines){lineNo++;if(format==='aws-cloudfront'&&line.startsWith('#Fields:'))ctx.cloudFrontColumns=line.slice(8).trim().split(/\s+/);let fresh=isExtended(format)&&format!=='mysql-slow'&&format!=='mysql-general'?startsNewEvent(format,line,buffer):format==='mariadb-slow'||format==='mysql-slow'?/^# Time:/.test(line):format==='jenkins'?(!/^\s|^at |^Caused by:|^Suppressed:/.test(line)&&buffer.length>0):format==='mariadb-error'?/^\d{4}-\d\d-\d\d[T ]/.test(line):format==='mariadb-general'||format==='mysql-general'?/^(?:\d{4}-\d\d-\d\d[T ]\S+\s+)?\d+\s+(?:Query|Connect|Quit|Init DB|Prepare|Execute)/.test(line):true;if(fresh&&buffer.length){let e=flush(lineNo-1);if(e)yield e;start=lineNo}if(!buffer.length)start=lineNo;buffer.push(line);if(buffer.length>=1000){let e=flush();if(e){e.parseWarnings.push('Mehrzeilenlimit erreicht');yield e}start=lineNo+1}}let e=flush();if(e)yield e}
