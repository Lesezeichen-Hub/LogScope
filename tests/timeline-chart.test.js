import test from 'node:test';
import assert from 'node:assert/strict';
import {timelineBars} from '../src/timeline-chart.js';

test('keeps every dated event when dense timelines are condensed',()=>{
  const start=Date.parse('2017-02-06T10:00:00Z');
  const events=Array.from({length:640},(_,index)=>({timestampUtc:new Date(start+index*60000).toISOString(),severity:index%10===0?'error':null}));
  events.push({timestampUtc:null,severity:'error'});
  const result=timelineBars(events,60000,160);
  assert.equal(result.intervals,640);
  assert.equal(result.compressed,true);
  assert.equal(result.bars.length,160);
  assert.equal(result.bars.reduce((sum,bar)=>sum+bar.all,0),640);
  assert.equal(result.bars.reduce((sum,bar)=>sum+bar.error,0),64);
  assert.equal(result.bars[0].start,start);
  assert.equal(result.bars.at(-1).end,start+640*60000);
});
