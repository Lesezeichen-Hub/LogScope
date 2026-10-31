import test from 'node:test';
import assert from 'node:assert/strict';
import {parseBlock} from '../src/parser.js';
import {accessRecord,accessYears,analyzeAccess} from '../src/access-analytics.js';
const context={sourceId:'web',offsetMinutes:null,shiftSeconds:0};
const parse=(raw,format,sourceId,line)=>parseBlock(raw,format,{...context,sourceId},line,line);

test('combines nginx and Apache combined access with Caddy JSON',()=>{
  const apache=parse('203.0.113.4 - - [31/Oct/2026:12:01:02 +0100] "GET /api?token=secret HTTP/1.1" 200 123 "https://example.test/page?q=x" "curl/8.0"','web-access','apache',1);
  const nginx=parse('203.0.113.5 - - [31/Oct/2026:12:01:03 +0100] "POST /api HTTP/1.1" 502 0 "-" "test-agent"','web-access','nginx',2);
  const caddy=parse(JSON.stringify({ts:1793449800,level:'info',logger:'http.log.access',request:{method:'GET',host:'example.test',uri:'/home?x=1',remote_ip:'203.0.113.6',headers:{'User-Agent':['browser']}},status:404,duration:.25,size:1024}),'caddy-json','caddy',3);
  const records=[apache,nginx,caddy].map(accessRecord);
  assert.deepEqual(records.map(record=>record.path),['/api','/api','/home']);
  assert.deepEqual(records.map(record=>record.method),['GET','POST','GET']);
  assert.deepEqual(records.map(record=>record.status),[200,502,404]);
  assert.equal(records[0].referrer,'example.test');
  const result=analyzeAccess([apache,nginx,caddy]);
  assert.equal(result.requests,3);assert.equal(result.sourceCount,3);assert.equal(result.status['2xx'],1);assert.equal(result.errors4xx,1);assert.equal(result.errors5xx,1);
  assert.equal(result.clients,3);assert.equal(result.bytes,1147);assert.equal(result.bytesKnown,3);
  assert.equal(result.p95,250);assert.equal(result.latencyCount,1);
  assert.deepEqual(result.top.path[0],{label:'/api',count:2});
  assert.deepEqual(accessYears([apache,nginx,caddy]),[['2026',3]]);
  assert.equal(analyzeAccess([apache,nginx,caddy],{source:'nginx'}).sourceCount,1);
});
test('treats missing metrics as unavailable and ignores non-access records',()=>{
  const event={parserId:'web-access',sourceId:'s',timestampUtc:null,fields:{status:200,request:'GET / HTTP/1.1',bytes:null},message:'GET /',raw:''};
  const result=analyzeAccess([event,{...event,parserId:'text',fields:{status:500}}]);
  assert.equal(result.requests,1);assert.equal(result.bytesKnown,0);assert.equal(result.latencyCount,0);assert.equal(result.p95,null);assert.equal(result.undated,1);
  assert.equal(accessRecord({...event,fields:{...event.fields,status:'bogus'}}),null);
});
test('includes structured Nginx JSON with an explicit timestamp',()=>{
  const raw=JSON.stringify({time_iso8601:'2026-10-31T12:02:00+01:00',remote_addr:'203.0.113.8',request:'GET /json?q=private HTTP/2.0',status:201,body_bytes_sent:512,request_time:'0.125',http_user_agent:'synthetic-agent'});
  const event=parse(raw,'jsonl','nginx-json',1),record=accessRecord(event);
  assert.equal(event.timestampUtc,'2026-10-31T11:02:00.000Z');
  assert.equal(record.path,'/json');assert.equal(record.protocol,'HTTP/2.0');assert.equal(record.durationMs,125);
  assert.equal(analyzeAccess([event]).bytes,512);
});
