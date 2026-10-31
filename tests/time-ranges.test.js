import test from 'node:test';
import assert from 'node:assert/strict';
import {leadingTimestamp} from '../src/generic-time.js';
import {summarizeTimeRanges,eventsForYear} from '../src/time-ranges.js';
import {parseBlock} from '../src/parser.js';

test('extracts old ISO timestamps from generic text without assigning dates to undated records',()=>{
  const context={sourceId:'s',offsetMinutes:60,shiftSeconds:0};
  const dated=parseBlock('2016-03-04 12:13:14,123 ERROR old failure','text',context,1,1);
  assert.equal(dated.timestampUtc,'2016-03-04T11:13:14.123Z');
  assert.equal(dated.timestampRaw,'2016-03-04 12:13:14,123');
  assert.equal(dated.message,'ERROR old failure');
  assert.equal(leadingTimestamp('CRITICAL:twisted:Unhandled Error'),null);
  assert.equal(parseBlock('CRITICAL:twisted:Unhandled Error','text',context,2,2).timestampUtc,null);
});

test('summarizes all available years and per-source undated events',()=>{
  const sources=[{id:'a',name:'auth'},{id:'h',name:'haas.log'}];
  const events=[{sourceId:'a',timestampUtc:'2018-01-02T03:04:05.000Z'},{sourceId:'a',timestampUtc:'2026-10-17T22:01:02.717Z'},{sourceId:'h',timestampUtc:null}];
  const result=summarizeTimeRanges(events,sources);
  assert.deepEqual(result.years,[['2018',1],['2026',1]]);
  assert.equal(result.sources[0].first,'2018-01-02T03:04:05.000Z');
  assert.equal(result.sources[1].undated,1);
  assert.deepEqual(eventsForYear(events,'2018'),[events[0]]);
});
