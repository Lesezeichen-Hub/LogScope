import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {detect} from '../src/core.js';
import {parseBlock,parseLines} from '../src/parser.js';
import {analyzePhp,phpRecord} from '../src/php-logs.js';

const context={sourceId:'php',offsetMinutes:60,shiftSeconds:0};
const fixture=name=>readFileSync(new URL('./fixtures/'+name,import.meta.url),'utf8').trim().split(/\r?\n/);

test('PHP error log keeps stack traces, location and timezone',()=>{
  const lines=fixture('synthetic-php-error.log');
  assert.equal(detect(lines.join('\n')).format,'php-error');
  const events=[...parseLines(lines,'php-error',{...context})];
  assert.equal(events.length,5);
  assert.equal(events[0].timestampUtc,'2026-11-01T11:00:00.000Z');
  assert.equal(events[0].severity,'error');
  assert.equal(events[0].normalized.phpKind,'fatal');
  assert.equal(events[0].normalized.phpFile,'/app/index.php');
  assert.equal(events[0].normalized.phpLine,42);
  assert.equal(events[0].normalized.exceptionClass,'TypeError');
  assert.equal(events[0].fields.stackFrames.length,2);
  assert.equal(events[0].lineEnd,5);
  assert.equal(events[1].normalized.phpKind,'warning');
  assert.equal(events[2].normalized.phpKind,'deprecated');
  assert.equal(events[4].normalized.phpKind,'parse');
});

test('PHP-FPM slow and Apache embedded PHP messages enter the same analysis',()=>{
  const fpm=fixture('synthetic-php-fpm.log'),apache=fixture('synthetic-php-apache.log');
  assert.equal(detect(fpm.join('\n')).format,'php-error');
  assert.equal(detect(apache.join('\n')).format,'apache-error');
  const events=[...parseLines(fpm,'php-error',{...context}),...parseLines(apache,'apache-error',{...context})];
  assert.equal(events.length,4);
  assert.equal(events[0].normalized.phpKind,'slow');
  assert.equal(events[0].normalized.durationMs,2500);
  assert.equal(events[0].normalized.phpPool,'www');
  assert.equal(events[1].normalized.phpFile,'/app/slow.php');
  assert.equal(events[3].normalized.phpKind,'fatal');
  assert.equal(phpRecord(events[3]).exceptionClass,'RuntimeException');
  const nginx=parseBlock('2026/11/01 12:08:00 [error] 12#34: *1 FastCGI sent in stderr: "PHP message: PHP Warning: bad input in /app/api.php on line 8"','nginx-error',{...context},1,1);
  assert.equal(nginx.normalized.phpKind,'warning');
  assert.equal(nginx.normalized.phpFile,'/app/api.php');
});

test('PHP aggregation respects source and kind without inventing dates',()=>{
  const direct=[...parseLines(fixture('synthetic-php-error.log'),'php-error',{...context})];
  const fpm=[...parseLines(fixture('synthetic-php-fpm.log'),'php-error',{...context,sourceId:'fpm'})];
  const summary=analyzePhp([...direct,...fpm]);
  assert.equal(summary.total,8);
  assert.equal(summary.counts.fatal,1);
  assert.equal(summary.counts.slow,2);
  assert.equal(summary.stackCount,1);
  assert.equal(summary.fileCount,6);
  assert.equal(summary.dated,8);
  assert.equal(summary.slowest[0].durationMs,2500);
  assert.equal(analyzePhp([...direct,...fpm],{source:'fpm',kind:'slow'}).total,2);
  const undated=parseBlock('PHP Warning: no timestamp in /app/file.php on line 2','php-error',{...context},1,1);
  assert.equal(undated.timestampUtc,null);
  assert.equal(analyzePhp([undated]).undated,1);
});
