import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import {createRequire} from 'node:module';

const root=path.resolve('.'),staticRoot=path.resolve(process.env.LOGSCOPE_STATIC_ROOT||'.');
const require=createRequire(process.env.LOGSCOPE_PLAYWRIGHT_ROOT?path.join(process.env.LOGSCOPE_PLAYWRIGHT_ROOT,'package.json'):import.meta.url);
const {chromium}=require('playwright');
const server=http.createServer((req,res)=>{
  const name=decodeURIComponent(req.url.split('?')[0]).replace(/^\/modules\/demo(?=\/)/,'');
  const file=path.resolve(staticRoot,'.'+name);
  if(!file.startsWith(staticRoot)){res.writeHead(403).end();return}
  fs.readFile(file,(error,data)=>{if(error){res.writeHead(404).end();return}res.setHeader('Content-Type',file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':'text/html');res.end(data)})
});
await new Promise(resolve=>server.listen(8767,'127.0.0.1',resolve));
let browser;
try{
  browser=await chromium.launch({headless:true,executablePath:process.env.LOGSCOPE_BROWSER_PATH||undefined});
  const page=await browser.newPage(),errors=[];
  page.on('pageerror',error=>errors.push(error.message));
  await page.goto('http://127.0.0.1:8767/modules/demo/index.html');
  const auth=Array.from({length:5000},(_,i)=>`2020-10-18T00:00:00.123456+02:00 web01 CRON[${i}]: session opened for user root`).join('\n');
  const haas=Array.from({length:300},()=>`CRITICAL:twisted:Unhandled Error\nTraceback (most recent call last):\n  File "/srv/demo.py", line 4, in call\nbuiltins.ValueError: synthetic failure`).join('\n');
  await page.locator('#fileInput').setInputFiles([{name:'auth.log',mimeType:'text/plain',buffer:Buffer.from(auth)},{name:'haas.log',mimeType:'text/plain',buffer:Buffer.from(haas)}]);
  const detected=await page.locator('[data-format]').evaluateAll(els=>els.map(el=>el.value));
  if(!['syslog','journal-text'].includes(detected[0])||detected[1]!=='twisted')throw Error('Format detection: '+detected.join(','));
  await page.locator('#startImport').click();
  await page.locator('.file-row').nth(1).getByText('Abgeschlossen').waitFor({timeout:20000});
  await page.locator('[data-view=Dashboard]').click();
  const dashboardBar=await page.locator('.chart button').first().evaluate(el=>el.getBoundingClientRect().height);
  if(dashboardBar<20)throw Error('Dashboard chart bars are invisible');
  await page.locator('[data-view=Logviewer]').click();
  await page.getByText('5.300 von 5.300 Ereignissen').waitFor();
  if(await page.locator('.virtual-row').count()===0)throw Error('Viewer has no visible rows');
  await page.locator('#quickSearch').fill('unmatched-search');
  await page.getByText('0 von 5.300 Ereignissen').waitFor();
  if(!(await page.locator('.scope-controls').innerText()).includes('unmatched-search'))throw Error('Global filter summary is stale');
  await page.locator('#resetViewerFilters').click();
  await page.getByText('5.300 von 5.300 Ereignissen').waitFor();
  const scroll=await page.locator('#virtualViewport').evaluate(el=>{el.scrollTop=el.scrollHeight;return {top:el.scrollTop,height:el.scrollHeight,client:el.clientHeight}});
  await page.waitForTimeout(100);
  const rendered=await page.locator('.virtual-row').count();
  if(scroll.top===0||scroll.client>=scroll.height||rendered>100)throw Error('Virtual scroll did not reach last events: '+JSON.stringify({scroll,rendered}));
  await page.locator('[data-view=Timeline]').click();
  const years=await page.locator('#timelineYear option').allTextContents();
  if(!years.some(s=>s.includes('2020 (5.000)')))throw Error('Old year missing: '+years);
  const info=await page.locator('#content').innerText();
  if(!info.includes('5.000 datierte und 300 undatierte Ereignisse')||!info.includes('haas.log'))throw Error('Time availability missing');
  await page.locator('#timelineYear').selectOption('2020');
  if(await page.locator('#timelineChart .chart button').count()===0)throw Error('Historic chart empty');
  const timelineBar=await page.locator('#timelineChart .chart button').first().evaluate(el=>el.getBoundingClientRect().height);
  if(timelineBar<20)throw Error('Timeline chart bars are invisible');
  await page.locator('#interval').selectOption('3600000');
  await page.locator('#timelineChart [data-time]').first().click();
  await page.locator('#searchFrom').waitFor();
  if(!await page.locator('#searchFrom').inputValue()||!await page.locator('#searchTo').inputValue())throw Error('Changed interval lost chart drilldown');
  await page.locator('[data-view=Logviewer]').click();
  await page.locator('#quickSearch').fill('unmatched-search');
  await page.locator('#importTop').click();
  await page.locator('#fileInput').setInputFiles({name:'new.log',mimeType:'text/plain',buffer:Buffer.from('2026-10-31T12:00:00Z INFO new event')});
  await page.locator('#startImport').click();
  await page.locator('.file-row').nth(2).getByText('Abgeschlossen').waitFor({timeout:10000});
  await page.locator('[data-view=Logviewer]').click();
  await page.getByText('5.301 von 5.301 Ereignissen').waitFor();
  if(errors.length)throw Error(errors.join('\n'));
  console.log('Timeline browser smoke passed');
}finally{await browser?.close();server.close()}
