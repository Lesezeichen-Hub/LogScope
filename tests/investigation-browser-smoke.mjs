import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
const require=createRequire(process.env.LOGSCOPE_PLAYWRIGHT_ROOT?path.join(process.env.LOGSCOPE_PLAYWRIGHT_ROOT,'package.json'):import.meta.url);
const {chromium}=require('playwright');
const root=path.resolve(process.env.LOGSCOPE_STATIC_ROOT||'.'),screenshots=fs.mkdtempSync(path.join(os.tmpdir(),'logscope-investigation-'));
const server=http.createServer((request,response)=>{
  const name=decodeURIComponent(request.url.split('?')[0]).replace(/^\/modules\/demo(?=\/)/,'');
  const file=path.resolve(root,'.'+name);
  if(file!==root&&!file.startsWith(root+path.sep)){response.writeHead(403).end();return}
  fs.readFile(file,(error,data)=>{
    if(error){response.writeHead(404).end();return}
    response.setHeader('Content-Type',file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':'text/html');response.end(data);
  });
});
await new Promise(resolve=>server.listen(8769,'127.0.0.1',resolve));
let browser;
try{
  browser=await chromium.launch({headless:true,executablePath:process.env.LOGSCOPE_BROWSER_PATH||undefined});
  const page=await browser.newPage({viewport:{width:1440,height:900}}),errors=[];
  page.on('pageerror',error=>errors.push(error.message));
  page.on('request',request=>{if(!request.url().startsWith('http://127.0.0.1:8769/'))errors.push('External request: '+request.url())});
  page.on('dialog',dialog=>dialog.accept());
  await page.goto('http://127.0.0.1:8769/modules/demo/index.html');
  const auth=[
    '<34>1 2026-10-31T10:00:00Z host sshd 42 ID - Failed password for admin from 192.0.2.9 port 22 ssh2',
    '<86>1 2026-10-31T10:01:00Z host sshd 42 ID - Accepted publickey for admin from 192.0.2.10 port 22 ssh2',
    '<30>1 2026-10-31T10:02:00Z host kernel - - - Out of memory: Killed process 123',
    '<86>1 2026-10-31T10:03:00Z host sudo 50 ID - admin : TTY=pts/0 ; USER=root ; COMMAND=/usr/bin/id'
  ].join('\n');
  const slow=['# Time: 2026-10-31T10:00:00Z','# Query_time: 2.5 Lock_time: 0 Rows_sent: 1 Rows_examined: 500','SELECT * FROM orders WHERE id=42;','# Time: 2026-10-31T10:01:00Z','# Query_time: 0.1 Lock_time: 0 Rows_sent: 1 Rows_examined: 1','SELECT * FROM orders WHERE id=1;'].join('\n');
  const mongo=JSON.stringify({t:{$date:'2026-10-31T10:00:00Z'},s:'I',c:'COMMAND',msg:'Slow query',attr:{ns:'shop.orders',durationMillis:1500,queryHash:'shape'}});
  const db2='2026-10-31-10.00.00.123456+000 I123E456 LEVEL: Error\nPID : 42 PROC : db2sysc\nINSTANCE : db2inst1 DB : SAMPLE\nMESSAGE : ADM5501E SQLCODE=-911 SQLSTATE=40001';
  const cloud=JSON.stringify({Records:[{eventVersion:'1.0',eventSource:'s3.amazonaws.com',eventName:'First',eventTime:'2026-10-31T10:00:00Z'},{eventVersion:'1.0',eventSource:'s3.amazonaws.com',eventName:'Second',eventTime:'2026-10-31T10:01:00Z'}]});
  await page.locator('#fileInput').setInputFiles([['auth.log',auth],['mysql-slow.log',slow],['mongo.jsonl',mongo],['db2diag.log',db2],['cloud.json',cloud]].map(([name,value])=>({name,mimeType:'text/plain',buffer:Buffer.from(value)})));
  await page.locator('#startImport').click();
  await page.locator('.file-row').nth(4).getByText('Abgeschlossen').waitFor({timeout:20000});
  await page.locator('[data-view="Berichte"]').click();
  const exported=page.waitForEvent('download');await page.locator('#exportJson').click();
  const payload=JSON.parse(fs.readFileSync(await (await exported).path(),'utf8'));
  assert.equal(payload.events.length,10);
  assert.equal(new Set(payload.events.map(event=>event.id)).size,10);
  assert.equal(payload.events.filter(event=>event.parserId==='aws-cloudtrail'&&event.lineStart===1).length,2);
  await page.locator('[data-view="System & Sicherheit"]').click();
  await page.getByRole('heading',{name:'System- und Sicherheitsereignisse',exact:true}).waitFor();
  await page.screenshot({path:path.join(screenshots,'system-desktop.png'),fullPage:true});
  await page.getByRole('button',{name:'192.0.2.9',exact:true}).click();
  await page.getByText('1 von 10 Ereignissen',{exact:true}).waitFor();
  await page.locator('.virtual-row').first().click();
  assert.match(await page.locator('#detail').innerText(),/Failed password/);
  await page.locator('#resetScope').click();
  await page.locator('[data-view="Datenbank-Analyse"]').click();
  assert.equal(await page.locator('.stat').filter({has:page.getByText('DB-Ereignisse',{exact:true})}).locator('strong').innerText(),'4');
  await page.screenshot({path:path.join(screenshots,'database-desktop.png'),fullPage:true});
  await page.getByRole('button',{name:'mysql',exact:true}).click();
  await page.getByText('2 von 10 Ereignissen',{exact:true}).waitFor();
  await page.locator('#resetScope').click();
  await page.locator('[data-view="Suche & Filter"]').click();
  await page.locator('#analysisPreset').selectOption('slow-database');
  assert.match(await page.locator('#groupResults').innerText(),/2 Ereignisse/);
  await page.locator('[data-group-dimension="1"]').selectOption('database');
  await page.locator('#groupMetric').selectOption('average');
  await page.locator('#applyGrouping').click();
  assert.match(await page.locator('#groupResults').innerText(),/2\.500/);
  await page.locator('#analysisName').fill('Slow operations');await page.locator('#saveAnalysis').click();
  await page.locator('[data-view="Einstellungen"]').click();await page.locator('#saveProject').click();
  await page.getByText('Projekt gespeichert.',{exact:true}).waitFor();
  await page.reload();
  await page.locator('[data-view="Einstellungen"]').click();await page.locator('#loadProject').click();
  await page.getByText('Projekt geöffnet.',{exact:true}).waitFor();
  await page.locator('[data-view="Suche & Filter"]').click();
  assert.match(await page.locator('#groupResults').innerText(),/2 Ereignisse/);
  await page.locator('#clearConditions').click();await page.locator('#savedAnalysis').selectOption('0');
  assert.match(await page.locator('#groupResults').innerText(),/2 Ereignisse/);
  await page.locator('#deleteAnalysis').click();assert.equal(await page.locator('#savedAnalysis option').count(),1);
  await page.locator('#groupResults tr').filter({hasText:'mongodb'}).getByRole('button').click();
  await page.getByText('1 von 10 Ereignissen',{exact:true}).waitFor();
  await page.locator('[data-view="Dashboard"]').click();
  assert.equal(await page.locator('.stat').filter({has:page.getByText('EREIGNISSE',{exact:true})}).locator('strong').innerText(),'1');
  await page.locator('[data-view="Berichte"]').click();
  assert.match(await page.locator('#reportPreview').innerText(),/- Ereignisse: 1\b/);
  const filtered=page.waitForEvent('download');await page.locator('#exportJson').click();
  assert.equal(JSON.parse(fs.readFileSync(await (await filtered).path(),'utf8')).events.length,1);
  await page.locator('#resetScope').click();
  await page.locator('[data-view="Suche & Filter"]').click();
  await page.locator('#conditionMode').selectOption('any');
  await page.locator('#addCondition').click();
  await page.locator('[data-condition-field]').selectOption('durationMs');
  await page.locator('[data-condition-op]').selectOption('gte');await page.locator('[data-condition-value]').fill('1000');
  await page.locator('#applyConditions').click();
  assert.match(await page.locator('#groupResults').innerText(),/2 Ereignisse/);
  await page.setViewportSize({width:390,height:844});
  await page.screenshot({path:path.join(screenshots,'filters-mobile.png'),fullPage:true});
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,'Page overflows mobile viewport');
  await page.locator('#resetScope').click();
  await page.locator('[data-view="Datenbank-Analyse"]').click();
  await page.screenshot({path:path.join(screenshots,'database-mobile.png'),fullPage:true});
  await page.locator('#theme').click();
  await page.screenshot({path:path.join(screenshots,'database-mobile-light.png'),fullPage:true});
  assert.deepEqual(errors,[]);
  console.log('Investigation browser smoke passed; screenshots: '+screenshots);
}finally{await browser?.close();server.close()}