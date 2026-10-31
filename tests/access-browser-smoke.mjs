import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import {createRequire} from 'node:module';
const root=path.resolve('.'),staticRoot=path.resolve(process.env.LOGSCOPE_STATIC_ROOT||'.');
const require=createRequire(process.env.LOGSCOPE_PLAYWRIGHT_ROOT?path.join(process.env.LOGSCOPE_PLAYWRIGHT_ROOT,'package.json'):import.meta.url);
const {chromium}=require('playwright');
const server=http.createServer((req,res)=>{
  const pathname=decodeURIComponent(req.url.split('?')[0]).replace(/^\/modules\/demo(?=\/)/,'');
  const file=path.resolve(staticRoot,'.'+pathname);
  if(!file.startsWith(staticRoot)){res.writeHead(403).end();return}
  fs.readFile(file,(error,data)=>{if(error){res.writeHead(404).end();return}res.setHeader('Content-Type',file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':'text/html');res.end(data)})
});
await new Promise(resolve=>server.listen(8768,'127.0.0.1',resolve));
let browser;
try{
  browser=await chromium.launch({headless:true,executablePath:process.env.LOGSCOPE_BROWSER_PATH||undefined});
  const page=await browser.newPage({viewport:{width:1440,height:900}}),errors=[];
  page.on('pageerror',error=>errors.push(error.message));
  page.on('request',request=>{if(!request.url().startsWith('http://127.0.0.1:8768/'))errors.push('External request: '+request.url())});
  await page.goto('http://127.0.0.1:8768/modules/demo/index.html');
  await page.locator('[data-view="Access-Analyse"]').click();
  await page.getByRole('heading',{name:'HTTP-Zugriffe auswerten'}).waitFor();
  const apache='203.0.113.10 - - [31/Oct/2026:12:10:00 +0100] "GET /article?token=x HTTP/1.1" 200 250 "https://example.test/page" "browser"\n203.0.113.11 - - [31/Oct/2026:12:11:00 +0100] "POST /login HTTP/1.1" 403 90 "-" "curl/8.0"';
  await page.locator('#fileInput').setInputFiles([
    {name:'synthetic-nginx-access.log',mimeType:'text/plain',buffer:fs.readFileSync(path.join(root,'tests/fixtures/synthetic-nginx-access.log'))},
    {name:'synthetic-caddy.jsonl',mimeType:'application/json',buffer:fs.readFileSync(path.join(root,'tests/fixtures/synthetic-caddy.jsonl'))},
    {name:'httpd-access.log',mimeType:'text/plain',buffer:Buffer.from(apache)}
  ]);
  await page.locator('#startImport').click();
  await page.locator('.file-row').nth(2).getByText('Abgeschlossen').waitFor({timeout:10000});
  await page.locator('[data-view="Access-Analyse"]').click();
  await page.getByRole('heading',{name:'Zugriffe im Überblick'}).waitFor();
  const content=await page.locator('#content').innerText();
  if(!content.includes('6 protokollierte Requests')||!content.includes('Statusklassen')||!content.includes('Pfade mit 4xx / 5xx'))throw Error('Access overview incomplete');
  if(await page.locator('.access-heatmap span').count()!==168)throw Error('Week heatmap incomplete');
  const visual=await page.locator('#content').evaluate(root=>({bar:[...root.querySelectorAll('.access-statusbar span')].map(el=>el.getBoundingClientRect().width),heat:[...root.querySelectorAll('.access-heatmap span')].map(el=>Number(getComputedStyle(el).opacity))}));
  if(visual.bar.some(width=>width<=0)||Math.max(...visual.heat)===Math.min(...visual.heat))throw Error('Access charts have no visual scale');
  await page.locator('#accessSource').selectOption({label:'synthetic-caddy.jsonl'});
  await page.getByText('2 protokollierte Requests').waitFor();
  await page.locator('#accessBucket').selectOption('hour');
  if(await page.locator('.access-flow-col').count()!==1)throw Error('Hourly trend incomplete');
  const target=page.getByRole('heading',{name:'Häufigste Pfade'}).locator('..').getByRole('button',{name:'/api'});
  await target.click();
  await page.locator('#quickSearch').waitFor();
  if(await page.locator('#quickSearch').inputValue()!=='/api')throw Error('Access drilldown failed');
  if(errors.length)throw Error(errors.join('\n'));
  if(process.env.LOGSCOPE_ACCESS_SCREENSHOT){
    await page.locator('[data-view="Access-Analyse"]').click();
    await page.locator('#accessSource').selectOption('all');
    await page.screenshot({path:process.env.LOGSCOPE_ACCESS_SCREENSHOT,fullPage:true});
  }
  console.log('Access browser smoke passed');
}finally{await browser?.close();server.close()}
