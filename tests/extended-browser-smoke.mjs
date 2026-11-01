import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import {createRequire} from 'node:module';

const root=path.resolve('.'),staticRoot=path.resolve(process.env.LOGSCOPE_STATIC_ROOT||'.');
const require=createRequire(process.env.LOGSCOPE_PLAYWRIGHT_ROOT?path.join(process.env.LOGSCOPE_PLAYWRIGHT_ROOT,'package.json'):import.meta.url);
const {chromium}=require('playwright');
const mime={'.html':'text/html','.js':'text/javascript','.css':'text/css','.json':'application/json','.log':'text/plain'};
const server=http.createServer((req,res)=>{
  const pathname=decodeURIComponent(req.url.split('?')[0]).replace(/^\/modules\/demo(?=\/)/,'');
  const file=path.resolve(staticRoot,'.'+pathname);
  if(!file.startsWith(staticRoot)){res.writeHead(403).end();return}
  fs.readFile(file,(error,data)=>{if(error){res.writeHead(404).end();return}res.setHeader('Content-Type',mime[path.extname(file)]||'application/octet-stream');res.end(data)})
});
await new Promise(resolve=>server.listen(8766,'127.0.0.1',resolve));
let browser;
try{
  browser=await chromium.launch({headless:true,executablePath:process.env.LOGSCOPE_BROWSER_PATH||undefined});
  const page=await browser.newPage(),errors=[];
  page.on('pageerror',error=>errors.push(error.message));
  page.on('request',request=>{if(!request.url().startsWith('http://127.0.0.1:8766/'))errors.push('External request: '+request.url())});
  await page.goto('http://127.0.0.1:8766/modules/demo/index.html');
  const names=['synthetic-nginx-access.log','synthetic-mongodb.jsonl','synthetic-db2diag.log','synthetic-aws-cloudtrail.json','synthetic-aws-alb.log','synthetic-aws-vpc.log','synthetic-k8s-cri.log','synthetic-aws-cloudfront.log','synthetic-aws-s3.log','synthetic-aws-ecs.jsonl','synthetic-postgresql.csv','synthetic-k8s-eventlist.json','synthetic-k8s-klog.log','synthetic-aws-cloudwatch.json','synthetic-redis.log','synthetic-mixed.log'];
  await page.locator('#fileInput').setInputFiles(names.map(name=>path.join(root,'tests/fixtures',name)));
  const selects=page.locator('#previews [data-format]');
  const expected=['web-access','mongodb-json','db2diag','aws-cloudtrail','aws-alb','aws-vpc','k8s-cri','aws-cloudfront','aws-s3','aws-ecs','postgresql-csv','k8s-event-json','k8s-klog','aws-cloudwatch','redis','web-access'];
  for(let i=0;i<expected.length;i++)if(await selects.nth(i).inputValue()!==expected[i])throw Error(`Detection ${names[i]}: ${await selects.nth(i).inputValue()}`);
  await page.locator('#startImport').click();
  await page.locator('.file-row').nth(names.length-1).getByText('Abgeschlossen').waitFor({timeout:15000});
  const rows=page.locator('.file-row');
  for(let i=0;i<names.length;i++){
    const text=await rows.nth(i).innerText();
    if(!text.includes(expected[i])||!text.includes('Abgeschlossen'))throw Error(`Import ${names[i]}: ${text}`);
  }
  await page.locator('[data-view=Dashboard]').click();
  if(!await page.getByText('30',{exact:true}).count())throw Error('Unexpected event count');
  if(errors.length)throw Error(errors.join('\n'));
  console.log('Extended browser smoke passed');
}finally{await browser?.close();server.close()}
