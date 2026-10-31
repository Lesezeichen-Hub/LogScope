import {test} from 'node:test';
import assert from 'node:assert/strict';
import {compileFilter,aggregateEvents,fieldValue,analysisPresets} from '../src/query.js';
const events=[
  {host:'alpha',timestampUtc:'2026-10-31T10:00:00Z',fields:{nested:{code:42}},normalized:{domain:'database',product:'mysql',durationMs:0,database:'shop'}},
  {host:'beta',timestampUtc:'2026-10-31T10:01:00Z',fields:{},normalized:{domain:'database',product:'mysql',durationMs:2000,database:'shop'}},
  {host:'beta',timestampUtc:null,fields:{},normalized:{domain:'database',product:'db2',durationMs:null,database:null}}
];
test('typed AND/OR/NOT filters handle missing values and numerical zero',()=>{
  assert.equal(events.filter(compileFilter({field:'durationMs',op:'eq',value:0})).length,1);
  assert.equal(events.filter(compileFilter({field:'durationMs',op:'neq',value:0})).length,1);
  assert.equal(events.filter(compileFilter({field:'durationMs',op:'missing'})).length,1);
  assert.equal(events.filter(compileFilter({field:'host',op:'exact',value:'ALPHA'})).length,0);
  assert.equal(events.filter(compileFilter({op:'any',conditions:[{field:'host',op:'eq',value:'ALPHA'},{field:'durationMs',op:'gte',value:1000}]})).length,2);
  assert.equal(events.filter(compileFilter({op:'not',condition:{field:'host',op:'eq',value:'alpha'}})).length,2);
});
test('time filters express exact half-open buckets and exclude undated records',()=>{
  const match=compileFilter({op:'all',conditions:[{field:'timestampUtc',op:'gte',value:'2026-10-31T10:00:00Z'},{field:'timestampUtc',op:'lt',value:'2026-10-31T10:01:00Z'}]});
  assert.deepEqual(events.filter(match).map(event=>event.host),['alpha']);
});
test('invalid field types and values cannot silently broaden a filter',()=>{
  assert.throws(()=>compileFilter({field:'durationMs',op:'contains',value:'1'}));
  assert.throws(()=>compileFilter({field:'durationMs',op:'gte',value:'no'}));
  assert.throws(()=>compileFilter({field:'timestampUtc',op:'gte',value:'no'}));
  assert.throws(()=>compileFilter({field:'unknown',op:'eq',value:'yes'}));
  assert.equal(fieldValue(events[0],'fields.nested.code'),42);
  assert.equal(fieldValue(events[0],'fields.__proto__.toString'),undefined);
});
test('grouping keeps missing metrics unknown and includes genuine zero measurements',()=>{
  const result=aggregateEvents(events,{dimensions:['product'],metric:'average',field:'durationMs'});
  assert.equal(result.total,3);
  assert.equal(result.rows[0].value,1000);
  assert.equal(result.rows[0].measured,2);
  assert.equal(result.rows[1].value,null);
  assert.equal(result.rows[1].count,1);
});
test('group cardinality is bounded explicitly rather than silently truncated',()=>{
  assert.throws(()=>aggregateEvents(events,{dimensions:['host'],maxGroups:1}),/Zu viele Gruppen/);
  assert.equal(aggregateEvents(events,{dimensions:['host'],limit:1}).groupCount,2);
  assert.throws(()=>aggregateEvents(events,{metric:'sum',field:'host'}));
});
test('analysis templates compile and slow queries include all database products',()=>{
  for(const preset of analysisPresets)assert.equal(typeof compileFilter({op:'all',conditions:preset.conditions}),'function');
  const preset=analysisPresets.find(item=>item.id==='slow-database');
  assert.equal(events.filter(compileFilter({op:'all',conditions:preset.conditions})).length,1);
});
test('grouping and drilldown agree on case folding and missing empty fields',()=>{
  const rows=[{host:'ALPHA'},{host:'alpha'},{host:''},{host:' '},{host:null}];
  const result=aggregateEvents(rows,{dimensions:['host']});
  assert.equal(result.groupCount,2);
  for(const group of result.rows){
    const condition={field:'host',op:group.values[0]===null?'missing':'eq',value:group.values[0]};
    assert.equal(rows.filter(compileFilter(condition)).length,group.count);
  }
});