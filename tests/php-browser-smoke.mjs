import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import {createRequire} from 'node:module';

const root=path.resolve('.'),staticRoot=path.resolve(process.env.LOGSCOPE_STATIC_ROOT||'.');
const require=createRequire(process.env.LOGSCOPE_PLAYWRIGHT_ROOT?path.join(process.env.LOGSCOPE_PLAYWRIGHT_ROOT,'package.json'):import.meta.url);
const {chromium}=require('playwright');
const server=http.createServer((request,response)=>{
  const pathname=decodeURIComponent(request.url.split('?')[0]).replace(/^\/modules\/demo(?=\/)/,'');
  const file=path.resolve(staticRoot,'.'+pathname);
  if(!file.startsWith(staticRoot)){response.writeHead(403).end();return}
  fs.readFile(file,(error,data)=>{if(error){response.writeHead(404).end();return}response.setHeader('Content-Type',file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':'text/html');response.end(data)});
});
await new Promise(resolve=>server.listen(8769,'127.0.0.1',resolve));
let browser;
try{
  browser=await chromium.launch({headless:true,executablePath:process.env.LOGSCOPE_BROWSER_PATH||undefined});
  const page=await browser.newPage({viewport:{width:1440,height:900}}),errors=[];
  page.on('pageerror',error=>errors.push(error.message));
  page.on('request',request=>{if(!request.url().startsWith('http://127.0.0.1:8769/'))errors.push('External request: '+request.url())});
  await page.goto('http://127.0.0.1:8769/modules/demo/index.html');
  await page.locator('[data-view="PHP-Analyse"]').click();
  await page.getByRole('heading',{name:'PHP-Logs auswerten'}).waitFor();
  const names=['synthetic-php-error.log','synthetic-php-fpm.log','synthetic-php-apache.log'];
  await page.locator('#fileInput').setInputFiles(names.map(name=>path.join(root,'tests/fixtures',name)));
  await page.locator('#previews [data-format]').nth(2).waitFor();
  const formats=await page.locator('#previews [data-format]').evaluateAll(elements=>elements.map(element=>element.value));
  if(JSON.stringify(formats)!==JSON.stringify(['php-error','php-error','apache-error']))throw Error('PHP format detection: '+formats.join(','));
  await page.locator('#startImport').click();
  await page.locator('.file-row').nth(2).getByText('Abgeschlossen').waitFor({timeout:15000});
  await page.locator('[data-view="PHP-Analyse"]').click();
  await page.getByRole('heading',{name:'PHP im Überblick'}).waitFor();
  if(!(await page.locator('.php-hero').innerText()).includes('9 Meldungen'))throw Error('PHP summary incomplete');
  await page.locator('[data-view="Berichte"]').click();
  if(!(await page.locator('#reportPreview').innerText()).includes('## PHP-Analyse'))throw Error('PHP report section missing');
  await page.locator('[data-view="PHP-Analyse"]').click();
  if(await page.locator('.php-heat i').count()!==168)throw Error('PHP heatmap incomplete');
  if(await page.locator('.php-flow button').count()<1)throw Error('PHP timeline missing');
  if(!(await page.getByRole('heading',{name:'Langsame PHP-Requests'}).locator('..').innerText()).includes('2,5 s'))throw Error('PHP slow request table missing');
  const chart=await page.locator('.php-donut').evaluate(element=>getComputedStyle(element).backgroundImage);
  if(!chart.includes('conic-gradient'))throw Error('PHP distribution not rendered');
  await page.locator('#phpKind').selectOption('fatal');
  if(!(await page.locator('.php-hero').innerText()).includes('2 Meldungen'))throw Error('PHP kind filter failed');
  await page.locator('#phpSource').selectOption({label:'synthetic-php-error.log'});
  if(!(await page.locator('.php-hero').innerText()).includes('1 Meldungen'))throw Error('PHP source filter failed');
  await page.locator('#phpKind').selectOption('all');
  await page.locator('[data-php-field="phpFile"][data-php-value="/app/index.php"]').click();
  await page.locator('#viewerCount').waitFor();
  if(!(await page.locator('#viewerCount').innerText()).startsWith('1 von'))throw Error('PHP file drilldown failed');
  await page.locator('#resetScope').click();
  await page.locator('[data-view="PHP-Analyse"]').click();
  await page.locator('#phpSource').selectOption('all');
  await page.setViewportSize({width:390,height:844});
  if(await page.evaluate(()=>document.documentElement.scrollWidth>window.innerWidth+1))throw Error('PHP mobile layout overflows the page');
  if(errors.length)throw Error(errors.join('\n'));
  if(process.env.LOGSCOPE_PHP_SCREENSHOT)await page.screenshot({path:process.env.LOGSCOPE_PHP_SCREENSHOT,fullPage:true});
  console.log('PHP browser smoke passed');
}finally{await browser?.close();server.close()}
