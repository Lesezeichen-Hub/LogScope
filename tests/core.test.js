import {test} from 'node:test';import assert from 'node:assert/strict';
import {detect,time,sqlFingerprint,percentile,groupErrors,compare,redact,redactValue} from '../src/core.js';
import {parseBlock,parseLines} from '../src/parser.js';
import {upgradeEvents} from '../src/event-model.js';
const ctx={sourceId:'s',year:2026,offsetMinutes:60,shiftSeconds:0};
test('upgrades legacy snapshots without losing colliding records or notes',()=>{
	const input=[{id:'s:1',sourceId:'s',parserId:'text',message:'first',fields:{},note:'keep'},{id:'s:1',sourceId:'s',parserId:'text',message:'second',fields:{}}];
	const upgraded=upgradeEvents(input);
	assert.equal(new Set(upgraded.map(event=>event.id)).size,2);
	assert.equal(upgraded[0].note,'keep');
	assert.equal(upgraded[1].legacyId,'s:1');
	assert.equal(input[0].schemaVersion,undefined);
});
test('record identity is independent of physical line and preserves provenance',()=>{
	const context={sourceId:'records'};
	const first=parseBlock('{"message":"one"}','jsonl',context,1,1);
	const second=parseBlock('{"message":"two"}','jsonl',context,1,1);
	assert.notEqual(first.id,second.id);
	assert.equal(first.lineStart,second.lineStart);
	assert.equal(second.recordSequence,2);
	assert.equal(second.schemaVersion,2);
});
test('normalizes SSH IPv6 authentication and retains original fields',()=>{
	const event=parseBlock('Oct 31 12:30:00 host sshd[42]: Failed password for invalid user admin from 2001:db8::4 port 2222 ssh2','syslog',{...ctx},1,1);
	assert.equal(event.normalized.domain,'system');
	assert.equal(event.normalized.eventType,'login');
	assert.equal(event.normalized.outcome,'failure');
	assert.equal(event.normalized.clientIp,'2001:db8::4');
	assert.equal(event.normalized.user,'admin');
});
test('normalizes MySQL and MariaDB duration to the same millisecond scale',()=>{
	for(const parser of ['mysql-slow','mariadb-slow']){
		const event=parseBlock('# Time: 2026-10-31T10:00:00Z\n# Query_time: 2.5 Lock_time: 0.1 Rows_sent: 1 Rows_examined: 500\nSELECT * FROM users WHERE id=42;',parser,{...ctx},1,3);
		assert.equal(event.normalized.product,parser.split('-')[0]);
		assert.equal(event.normalized.durationMs,2500);
		assert.equal(event.normalized.lockMs,100);
		assert.equal(event.normalized.queryPattern,'SELECT * FROM USERS WHERE ID=?;');
		assert.equal(event.recordSequence,1);
	}
});
test('slow logs expose selected database independently of SQL fingerprint',()=>{
	const event=parseBlock('# Time: 2026-10-31T10:00:00Z\n# Query_time: 2 Lock_time: 0 Rows_sent: 1 Rows_examined: 1\nuse `shop-db`;\nSET timestamp=1793440800;\nSELECT * FROM orders WHERE id=1;','mysql-slow',{...ctx},1,5);
	assert.equal(event.normalized.database,'shop-db');
	assert.equal(event.normalized.operation,'SELECT');
	assert.equal(event.fields.sql,'SELECT * FROM orders WHERE id=1;');
});
test('malformed numeric measurements are not reported as zero or one',()=>{
	const event=parseBlock('{"ts":1793440800,"status":200,"request":{"uri":"/api"},"duration":true,"size":" "}','caddy-json',{...ctx},1,1);
	assert.equal(event.normalized.durationMs,null);
	assert.equal(event.normalized.bytes,null);
});
test('normalizes MongoDB attributes without inventing a SQL fingerprint',()=>{
	const event=parseBlock(JSON.stringify({t:{$date:'2026-10-31T10:00:00Z'},s:'I',c:'COMMAND',msg:'Slow query',attr:{ns:'shop.orders',durationMillis:150,docsExamined:200,queryHash:'shape'}}),'mongodb-json',{...ctx},1,1);
	assert.equal(event.normalized.database,'shop.orders');
	assert.equal(event.normalized.durationMs,150);
	assert.equal(event.normalized.queryPattern,'shape');
	assert.equal(event.fields.attr.docsExamined,200);
});
test('unknown durations stay null and HTTP status remains separate from severity',()=>{
	const event=parseBlock('192.0.2.1 - - [31/Oct/2026:12:10:00 +0100] "GET /api HTTP/1.1" 503 123','web-access',{...ctx},1,1);
	assert.equal(event.normalized.durationMs,null);
	assert.equal(event.normalized.status,503);
	assert.equal(event.normalized.path,'/api');
	assert.equal(event.severity,null);
});
test('RFC5424 preserves structured data and numeric facility with explicit UTC',()=>{
	const raw='<34>1 2026-10-31T12:00:00Z host sshd 42 ID47 [auth@32473 note="a\\]b"] Failed password for admin from 192.0.2.1 port 22 ssh2';
	assert.equal(detect(raw).format,'syslog');
	const event=parseBlock(raw,'syslog',{sourceId:'rfc'},1,1);
	assert.equal(event.timestampUtc,'2026-10-31T12:00:00.000Z');
	assert.equal(event.fields.syslogFacility,4);
	assert.equal(event.fields.syslogSeverity,2);
	assert.equal(event.fields.syslogMessageId,'ID47');
	assert.equal(event.normalized.outcome,'failure');
	assert.equal(event.processId,42);
	assert.equal(event.severity,'error');
});
test('critical webserver levels are classified without rewriting original severity',()=>{
	const event=parseBlock('2026/10/31 12:00:00 [crit] 12#12: upstream failed','nginx-error',{...ctx},1,1);
	assert.equal(event.severity,'error');
	assert.equal(event.normalized.originalLevel,'crit');
});
test('Db2 diagnostic attributes remain structured and queryable',()=>{
	const event=parseBlock('2026-10-31-12.00.00.123456+060 I123E456 LEVEL: Error\nPID : 42 TID : 71 PROC : db2sysc\nINSTANCE : db2inst1 NODE : 000 DB : SAMPLE\nEDUID : 88\nFUNCTION : DB2 UDB, lock manager, sqlplrq, probe:123\nMESSAGE : ADM5501E Lock failure SQLCODE=-911 SQLSTATE=40001\nDATA #1 : SQLCA\nZRC=0x80000001','db2diag',{...ctx},1,8);
	assert.equal(event.fields.recordId,'I123E456');
	assert.equal(event.fields.probe,'123');
	assert.equal(event.fields.sqlCode,'-911');
	assert.equal(event.normalized.diagnosticCode,'40001');
	assert.equal(event.normalized.database,'SAMPLE');
	assert.equal(event.fields.dataBlocks.length,1);
});
test('detects representative formats',()=>{assert.equal(detect('{"__REALTIME_TIMESTAMP":"1760000000000000","MESSAGE":"x"}').format,'journal-json');assert.equal(detect('{"ts":1760000000,"logger":"http.log.access","status":502}').format,'caddy-json');assert.equal(detect('# Time: 2026-10-31T10:00:00\n# Query_time: 1.2 Lock_time: 0 Rows_sent: 1 Rows_examined: 5').format,'mariadb-slow');assert.equal(detect('[Pipeline] stage\nFinished: FAILURE').format,'jenkins')});
test('normalizes microseconds, seconds, timezone and correction',()=>{assert.equal(time('1760000000000000').utc,new Date(1760000000000).toISOString());assert.equal(time('1760000000.5').utc,new Date(1760000000500).toISOString());assert.equal(time('2026-10-31T12:00:00',{offsetMinutes:60}).utc,'2026-10-31T11:00:00.000Z');assert.equal(time('2026-10-31T12:00:00',{offsetMinutes:60,shiftSeconds:-72}).utc,'2026-10-31T10:58:48.000Z');assert.equal(time('2026-10-31T12:00:00').utc,null)});
test('parses syslog with explicit year and zone',()=>{let e=parseBlock('Oct 31 12:30:00 host sshd[42]: Failed password for user','syslog',ctx,1,1);assert.equal(e.timestampUtc,'2026-10-31T11:30:00.000Z');assert.equal(e.host,'host');assert.equal(e.processId,42);assert.equal(e.category,'Zugriff')});
test('retains multiline slow query as one event',()=>{let rows=['# Time: 2026-10-31T10:00:00','# User@Host: demo[demo] @ localhost []','# Query_time: 2.5 Lock_time: 0 Rows_sent: 1 Rows_examined: 500','SELECT *','FROM users WHERE id = 123;','# Time: 2026-10-31T10:02:00','# Query_time: 1.5 Lock_time: 0 Rows_sent: 1 Rows_examined: 20','SELECT * FROM users WHERE id = 456;'];let ev=[...parseLines(rows,'mariadb-slow',ctx)];assert.equal(ev.length,2);assert.equal(ev[0].lineEnd,5);assert.equal(ev[0].fields.queryTime,2.5);assert.equal(ev[0].fields.sqlFingerprint,ev[1].fields.sqlFingerprint)});
test('parses journald priority without altering source scale',()=>{let e=parseBlock('{"__REALTIME_TIMESTAMP":"1760000000000000","PRIORITY":"3","_SYSTEMD_UNIT":"demo.service","MESSAGE":"failed"}','journal-json',ctx,1,1);assert.equal(e.severity,'error');assert.equal(e.fields.PRIORITY,'3');assert.equal(e.service,'demo.service')});
test('fingerprinting, grouping and comparison',()=>{assert.equal(sqlFingerprint("select * from t where id=123 and name='A'"),sqlFingerprint("select * from t where id=456 and name='B'"));let a=[{severity:'error',message:'Connection refused to 192.0.2.1',sourceId:'a',fields:{},parserId:'text'}],b=[{...a[0],message:'Connection refused to 192.0.2.2',sourceId:'b'}];assert.equal(groupErrors(a).length,1);assert.equal(compare(a,b)[0].a,1);assert.match(redact('token=abc 192.0.2.1'),/\[MASKIERT\]/)});
test('percentile interpolates and empty values remain unknown',()=>{assert.equal(percentile([1,2,3,4],.5),2.5);assert.equal(percentile([],.95),null)});
test('redacts nested report fields without changing source',()=>{let input={request:{client_ip:'192.0.2.4'},message:'token=secret user@example.test'},output=redactValue(input);assert.equal(output.request.client_ip,'[IP]');assert.match(output.message,/\[MASKIERT\]/);assert.equal(input.request.client_ip,'192.0.2.4')});
test('malformed JSON stays visible with warning',()=>{let e=parseBlock('{bad json','jsonl',ctx,8,8);assert.equal(e.raw,'{bad json');assert.match(e.parseWarnings[0],/JSON nicht lesbar/);assert.equal(e.lineStart,8)});
test('unknown timestamp remains unknown',()=>{let e=parseBlock('plain line','text',ctx,1,1);assert.equal(e.timestampUtc,null);assert.equal(e.message,'plain line')});
test('Caddy status does not overwrite log level',()=>{let e=parseBlock('{"ts":1793449800,"level":"info","logger":"http.log.access","status":502,"duration":1.25,"request":{"host":"example.test","uri":"/api"}}','caddy-json',ctx,1,1);assert.equal(e.severity,'info');assert.equal(e.fields.status,502);assert.equal(e.host,'example.test')});
test('Jenkins ANSI is stripped from display but original retained',()=>{let e=parseBlock('\x1b[31mERROR: failed\x1b[0m','jenkins',ctx,1,1);assert.equal(e.message,'ERROR: failed');assert.match(e.raw,/\x1b/);assert.equal(e.severity,'error')});
