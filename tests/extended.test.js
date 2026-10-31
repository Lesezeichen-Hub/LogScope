import {test} from 'node:test';import assert from 'node:assert/strict';
import {detect} from '../src/core.js';import {parseBlock,parseLines} from '../src/parser.js';import {JsonRecordStream} from '../src/record-stream.js';
const ctx={sourceId:'extended',year:2026,offsetMinutes:60,shiftSeconds:0};

test('recognizes web access and error logs',()=>{
  const access='203.0.113.4 - - [31/Oct/2026:12:01:02 +0100] "GET /api HTTP/1.1" 502 123 "-" "curl/8.0"';
  assert.equal(detect(access).format,'web-access');let e=parseBlock(access,'web-access',ctx,1,1);assert.equal(e.timestampUtc,'2026-10-31T11:01:02.000Z');assert.equal(e.timestampRaw,'31/Oct/2026:12:01:02 +0100');assert.equal(e.fields.status,502);assert.equal(e.fields.userAgent,'curl/8.0');
  const nginx='2026/10/31 12:00:00 [error] 123#45: *67 connect() failed, client: 203.0.113.4, server: example.test';
  assert.equal(detect(nginx).format,'nginx-error');e=parseBlock(nginx,'nginx-error',ctx,1,1);assert.equal(e.processId,123);assert.equal(e.severity,'error');
  const apache='[Sat Oct 31 12:00:00.123 2026] [core:error] [pid 123:tid 456] AH00001: synthetic error';
  assert.equal(detect(apache).format,'apache-error');e=parseBlock(apache,'apache-error',ctx,1,1);assert.equal(e.timestampUtc,'2026-10-31T11:00:00.123Z');assert.equal(e.fields.module,'core')
});

test('recognizes MySQL error, slow and general formats',()=>{
  const raw='2026-10-31T12:00:00.123456Z 8 [ERROR] [MY-010123] [Server] synthetic failure';
  assert.equal(detect(raw).format,'mysql-error');let e=parseBlock(raw,'mysql-error',ctx,1,1);assert.equal(e.fields.errorCode,'MY-010123');assert.equal(e.service,'mysql');
  e=parseBlock('# Time: 2026-10-31T12:00:00Z\n# Query_time: 2.5 Lock_time: 0 Rows_sent: 1 Rows_examined: 50\nSELECT * FROM t WHERE id=1;','mysql-slow',ctx,1,3);assert.equal(e.fields.queryTime,2.5);assert.equal(e.parserId,'mysql-slow');assert.equal(e.service,'mysql');
  e=parseBlock('2026-10-31T12:00:00Z 12 Query SELECT *\nFROM demo','mysql-general',ctx,1,2);assert.equal(e.fields.command,'Query');assert.equal(e.fields.sql,'SELECT *\nFROM demo')
});

test('parses MySQL JSON error sink and AWS WAF',()=>{
  let raw=JSON.stringify({prio:1,err_code:10051,msg:'synthetic mysql error',time:'2026-10-31T12:00:00.123456Z',ts:1793448000123,thread:5,subsystem:'Server',label:'Error'});
  assert.equal(detect(raw).format,'mysql-error-json');let e=parseBlock(raw,'mysql-error-json',ctx,1,1);assert.equal(e.severity,'error');assert.equal(e.fields.err_code,10051);assert.equal(e.timestampUtc,'2026-10-31T12:00:00.123Z');
  raw=JSON.stringify({timestamp:1793448000123,formatVersion:1,webaclId:'arn:aws:wafv2:demo',action:'BLOCK',httpRequest:{clientIp:'203.0.113.4',httpMethod:'GET',uri:'/admin'}});
  assert.equal(detect(raw).format,'aws-waf');e=parseBlock(raw,'aws-waf',ctx,1,1);assert.equal(e.severity,null);assert.equal(e.fields.action,'BLOCK')
});

test('parses PostgreSQL stderr and JSON logs',()=>{
  const rows=['2026-10-31 12:00:00.123 UTC [123] ERROR: synthetic failure','DETAIL: synthetic detail','STATEMENT: SELECT 1','2026-10-31 12:00:01.123 UTC [123] LOG: recovery'];
  assert.equal(detect(rows.join('\n')).format,'postgresql-stderr');let events=[...parseLines(rows,'postgresql-stderr',ctx)];assert.equal(events.length,2);assert.equal(events[0].lineEnd,3);assert.equal(events[0].timestampUtc,'2026-10-31T12:00:00.123Z');assert.equal(events[0].fields.detail,'synthetic detail');
  const raw=JSON.stringify({timestamp:'2026-10-31 12:00:00.123 UTC',pid:123,error_severity:'ERROR',message:'synthetic failure',sql_state_code:'XX000'});
  assert.equal(detect(raw).format,'postgresql-json');let e=parseBlock(raw,'postgresql-json',ctx,1,1);assert.equal(e.severity,'error');assert.equal(e.fields.sql_state_code,'XX000')
});

test('parses multiline PostgreSQL CSV records',()=>{
  const rows=['2026-10-31 12:00:00.123 UTC,demo,app,123,203.0.113.4,s1,1,SELECT,2026-10-31 11:00:00 UTC,1,2,ERROR,XX000,"synthetic','failure",detail,hint,,,,SELECT 1','2026-10-31 12:00:01.123 UTC,demo,app,123,203.0.113.4,s1,2,SELECT,2026-10-31 11:00:00 UTC,1,2,LOG,00000,synthetic recovery'];
  assert.equal(detect(rows[0]+'"').format,'postgresql-csv');const events=[...parseLines(rows,'postgresql-csv',ctx)];assert.equal(events.length,2);assert.equal(events[0].lineEnd,2);assert.equal(events[0].message,'synthetic\nfailure');assert.equal(events[0].fields.sqlState,'XX000')
});

test('parses MongoDB structured and legacy text logs',()=>{
  const raw=JSON.stringify({t:{$date:'2026-10-31T12:00:00.000Z'},s:'W',c:'NETWORK',id:123,ctx:'conn4',msg:'synthetic warning',attr:{remote:'203.0.113.4:123'}});
  assert.equal(detect(raw).format,'mongodb-json');let e=parseBlock(raw,'mongodb-json',ctx,1,1);assert.equal(e.severity,'warn');assert.equal(e.fields.attr.remote,'203.0.113.4:123');assert.equal(e.timestampUtc,'2026-10-31T12:00:00.000Z');
  const old='2026-10-31T12:00:00.000+0100 I NETWORK [conn4] synthetic connection';assert.equal(detect(old).format,'mongodb-text');e=parseBlock(old,'mongodb-text',ctx,1,1);assert.equal(e.service,'mongodb');assert.equal(e.process,'conn4')
});

test('keeps Db2 diagnostic records together and handles minute offsets',()=>{
  const rows=['2026-10-31-12.00.00.123456-300 27204 LEVEL: Error (OS)','PID     : 123 TID : 456 PROC : db2sysc','INSTANCE: db2inst1 DB : SAMPLE','FUNCTION: DB2 UDB, test, probe:1','MESSAGE : ADM0001E Synthetic failure','2026-10-31-12.01.00.000000-300 27300 LEVEL: Info (OS)','MESSAGE : ADM0002I Synthetic recovery'];
  assert.equal(detect(rows.join('\n')).format,'db2diag');let events=[...parseLines(rows,'db2diag',ctx)];assert.equal(events.length,2);assert.equal(events[0].lineEnd,5);assert.equal(events[0].timestampUtc,'2026-10-31T17:00:00.123Z');assert.equal(events[0].timestampRaw,'2026-10-31-12.00.00.123456-300');assert.equal(events[0].fields.messageId,'ADM0001E')
});

test('streams CloudTrail Records across chunk boundaries',()=>{
  let records=[],scan=new JsonRecordStream('Records',(raw,start,end)=>records.push({raw,start,end}));let doc=JSON.stringify({Records:[{eventVersion:'1.08',eventTime:'2026-10-31T12:00:00Z',eventSource:'ec2.amazonaws.com',eventName:'StartInstances'},{eventVersion:'1.08',eventTime:'2026-10-31T12:01:00Z',eventSource:'iam.amazonaws.com',eventName:'CreateUser',errorCode:'AccessDenied'}]});
  assert.equal(detect(doc).format,'aws-cloudtrail');for(let i=0;i<doc.length;i+=7)scan.feed(doc.slice(i,i+7));scan.finish();assert.equal(records.length,2);let e=parseBlock(records[1].raw,'aws-cloudtrail',ctx,1,1);assert.equal(e.severity,'error');assert.equal(e.fields.errorCode,'AccessDenied')
});

test('reports truncated JSON record arrays',()=>{const scan=new JsonRecordStream('Records',()=>{});scan.feed('{"Records":[{"eventTime":"2026-10-31T12:00:00Z"}');assert.throws(()=>scan.finish(),/unvollständig/)});

test('parses CloudWatch, ALB and VPC exports',()=>{
  let raw=JSON.stringify({timestamp:1793448000000,message:'synthetic cloudwatch message',logGroupName:'/aws/lambda/demo'});let e=parseBlock(raw,'aws-cloudwatch',ctx,1,1);assert.equal(e.service,'/aws/lambda/demo');assert.ok(e.timestampUtc);
  e=parseBlock(JSON.stringify({timestamp:1793448000000,message:'synthetic nested event'}),'aws-cloudwatch',{...ctx,cloudWatchLogGroup:'/aws/lambda/demo'},1,1);assert.equal(e.service,'/aws/lambda/demo');
  raw='http 2026-10-31T12:00:00.000000Z app/demo/123 203.0.113.4:123 10.0.0.2:80 0.001 0.002 0.003 502 502 10 20 "GET https://example.test/api HTTP/1.1" "curl/8.0" - - -';assert.equal(detect(raw).format,'aws-alb');e=parseBlock(raw,'aws-alb',ctx,1,1);assert.equal(e.fields.status,502);assert.equal(e.severity,null);
  raw='2 123456789012 eni-123abc 203.0.113.4 10.0.0.2 45678 443 6 10 1234 1793448000 1793448060 REJECT OK';assert.equal(detect(raw).format,'aws-vpc');e=parseBlock(raw,'aws-vpc',ctx,1,1);assert.equal(e.fields.action,'REJECT');assert.equal(e.severity,null)
});

test('parses CloudFront, S3 and ECS access/container logs',()=>{
  const cf=['#Version: 1.0','#Fields: date time x-edge-location sc-bytes c-ip cs-method cs(Host) cs-uri-stem sc-status','2026-10-31\t12:00:00\tFRA1\t123\t203.0.113.4\tGET\texample.test\t/api\t502'];
  assert.equal(detect(cf.join('\n')).format,'aws-cloudfront');let events=[...parseLines(cf,'aws-cloudfront',{...ctx})];assert.equal(events.length,3);assert.equal(events[2].fields.status,502);assert.equal(events[2].timestampUtc,'2026-10-31T12:00:00.000Z');
  const s3='owner bucket [31/Oct/2026:12:01:02 +0000] 203.0.113.4 requester requestid REST.GET.OBJECT key "GET /bucket/key HTTP/1.1" 200 - 123 456 1 1 "-" "curl/8.0"';
  assert.equal(detect(s3).format,'aws-s3');let e=parseBlock(s3,'aws-s3',ctx,1,1);assert.equal(e.fields.status,200);assert.equal(e.fields.bucket,'bucket');assert.equal(e.timestampUtc,'2026-10-31T12:01:02.000Z');
  const ecs=JSON.stringify({time:'2026-10-31T12:00:00Z',log:'synthetic container output\n',ecs_cluster:'demo',ecs_task_arn:'arn:aws:ecs:demo',container_name:'web'});
  assert.equal(detect(ecs).format,'aws-ecs');e=parseBlock(ecs,'aws-ecs',ctx,1,1);assert.equal(e.service,'web');assert.equal(e.message,'synthetic container output')
});

test('parses Kubernetes CRI partial, Docker JSON, audit and events',()=>{
  const rows=['2026-10-31T12:00:00.123456789Z stdout P first ','2026-10-31T12:00:00.123456789Z stdout F second','2026-10-31T12:00:01Z stderr F failed'];assert.equal(detect(rows.join('\n')).format,'k8s-cri');let events=[...parseLines(rows,'k8s-cri',ctx)];assert.equal(events.length,2);assert.equal(events[0].message,'first second');assert.equal(events[0].lineEnd,2);
  let withName=parseBlock(rows[0],'k8s-cri',{...ctx,fileName:'web_default_app-0123456789abcdef.log'},1,1);assert.equal(withName.fields.namespace,'default');assert.equal(withName.fields.container,'app');assert.match(withName.parseWarnings.join(' '),/unvollständig/);
  let raw=JSON.stringify({log:'hello\n',stream:'stdout',time:'2026-10-31T12:00:00Z'});assert.equal(detect(raw).format,'k8s-docker-json');assert.equal(parseBlock(raw,'k8s-docker-json',ctx,1,1).message,'hello');
  raw=JSON.stringify({kind:'Event',apiVersion:'audit.k8s.io/v1',auditID:'a',stage:'ResponseComplete',requestURI:'/api/v1/pods',verb:'delete',responseStatus:{code:403},requestReceivedTimestamp:'2026-10-31T12:00:00Z'});assert.equal(detect(raw).format,'k8s-audit-json');assert.equal(parseBlock(raw,'k8s-audit-json',ctx,1,1).severity,null);
  raw=JSON.stringify({kind:'Event',reason:'BackOff',message:'Back-off restarting failed container',type:'Warning',involvedObject:{kind:'Pod',name:'demo'},metadata:{creationTimestamp:'2026-10-31T12:00:00Z'}});assert.equal(detect(raw).format,'k8s-event-json');assert.equal(parseBlock(raw,'k8s-event-json',ctx,1,1).service,'k8s-event')
  raw=JSON.stringify({kind:'Event',apiVersion:'events.k8s.io/v1',reason:'BackOff',note:'synthetic modern event',type:'Warning',regarding:{kind:'Pod',name:'demo'},eventTime:'2026-10-31T12:00:00Z'});assert.equal(detect(raw).format,'k8s-event-json');assert.equal(parseBlock(raw,'k8s-event-json',ctx,1,1).message,'synthetic modern event')
});

test('parses Kubernetes klog with explicit year and EventList records',()=>{
  const rows=['I1031 12:00:00.123456 42 kubelet.go:79] synthetic startup','  continued detail','E1031 12:00:01.123456 42 kubelet.go:80] synthetic failure'];
  assert.equal(detect(rows.join('\n')).format,'k8s-klog');let events=[...parseLines(rows,'k8s-klog',{...ctx})];assert.equal(events.length,2);assert.equal(events[0].lineEnd,2);assert.equal(events[1].severity,'error');assert.equal(events[0].timestampUtc,'2026-10-31T11:00:00.123Z');
  let noYear=parseBlock(rows[0],'k8s-klog',{sourceId:'s',offsetMinutes:60},1,1);assert.equal(noYear.timestampUtc,null);assert.match(noYear.parseWarnings.join(' '),/Bezugsjahr/);
  const list={kind:'EventList',items:[{kind:'Event',reason:'BackOff',type:'Warning',message:'synthetic failure',metadata:{creationTimestamp:'2026-10-31T12:00:00Z'}}]};const doc=JSON.stringify(list);assert.equal(detect(doc).format,'k8s-event-json');let raw=[];const scanner=new JsonRecordStream('items',x=>raw.push(x));for(let i=0;i<doc.length;i+=5)scanner.feed(doc.slice(i,i+5));scanner.finish();assert.equal(raw.length,1);assert.equal(parseBlock(raw[0],'k8s-event-json',ctx,1,1).severity,'warn')
});

test('keeps timestamp-free Twisted tracebacks visible as single events',()=>{
  const lines=['CRITICAL:twisted:Removing stale pidfile /var/run/demo.pid','CRITICAL:twisted:Unhandled Error','Traceback (most recent call last):','  File "/srv/demo.py", line 10, in run','    raise ValueError("synthetic")','builtins.ValueError: synthetic failure','CRITICAL:twisted:Unhandled Error','Traceback (most recent call last):','  File "/srv/demo.py", line 12, in run','builtins.KeyError: synthetic'];
  assert.equal(detect(lines.join('\n')).format,'twisted');const events=[...parseLines(lines,'twisted',ctx)];assert.equal(events.length,3);assert.equal(events[1].lineStart,2);assert.equal(events[1].lineEnd,6);assert.equal(events[1].timestampUtc,null);assert.equal(events[1].fields.frames,1);assert.match(events[1].message,/ValueError/)
});
