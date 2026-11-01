import {analyzePhp,phpRecord} from './php-logs.js';

const esc=value=>String(value??'').replace(/[&<>"']/g,char=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
const num=value=>Number(value).toLocaleString('de-DE');
const labels={fatal:'Fatal',parse:'Syntax',error:'Fehler',warning:'Warnung',deprecated:'Veraltet',notice:'Hinweis',slow:'Langsam',info:'Info'};
const kinds=['fatal','parse','error','warning','deprecated','notice','slow','info'];

function metric(label,value,hint){return `<div class="php-metric"><span>${esc(label)}</span><strong>${esc(value)}</strong><small>${esc(hint)}</small></div>`}
function ranking(title,rows,total,field,empty='Keine Angaben protokolliert.'){
  const max=rows[0]?.count??1;
  return `<section class="php-panel"><h2>${esc(title)}</h2>${rows.length?`<div class="php-ranks">${rows.map(row=>`<div class="php-rank">${field?`<button type="button" data-php-field="${esc(field)}" data-php-value="${esc(row.label)}" title="Im Logviewer öffnen: ${esc(row.label)}">${esc(row.label)}</button>`:`<span title="${esc(row.label)}">${esc(row.label)}</span>`}<div class="php-rank-track"><i data-ratio="${Math.max(3,row.count/max*100)}"></i></div><strong>${num(row.count)}</strong><small>${total?num(row.count/total*100)+' %':''}</small></div>`).join('')}</div>`:`<p class="muted">${esc(empty)}</p>`}</section>`;
}
function buckets(days){
  if(!days.length)return [];
  const dayMs=86400000,first=Date.parse(days[0].label+'T00:00:00Z'),last=Date.parse(days.at(-1).label+'T00:00:00Z');
  const step=Math.max(1,Math.ceil(((last-first)/dayMs+1)/36)),count=Math.ceil(((last-first)/dayMs+1)/step);
  const result=Array.from({length:count},(_,i)=>({start:first+i*step*dayMs,end:first+(i+1)*step*dayMs,count:0}));
  for(const day of days)result[Math.floor((Date.parse(day.label+'T00:00:00Z')-first)/(step*dayMs))].count+=day.count;
  return result;
}
function timeline(data){
  const rows=buckets(data.days),max=Math.max(1,...rows.map(row=>row.count));
  if(!rows.length)return '<p class="muted">Keine datierten PHP-Meldungen. Für lokale Zeitstempel einen Zeitzonenoffset beim Import angeben.</p>';
  return `<div class="php-flow" role="group" aria-label="PHP-Meldungen im Zeitverlauf">${rows.map(row=>`<button type="button" data-time="${row.start}" data-end="${row.end}" data-ratio="${Math.max(2,row.count/max*100)}" title="${esc(new Date(row.start).toISOString().slice(0,10))}: ${num(row.count)} Meldungen" aria-label="${esc(new Date(row.start).toISOString().slice(0,10))}: ${num(row.count)} Meldungen"></button>`).join('')}</div><div class="php-flow-axis"><span>${esc(data.days[0].label)} UTC</span><span>${esc(data.days.at(-1).label)} UTC</span></div>`;
}
function heatmap(data){
  const max=Math.max(1,...data.hours.flat()),days=['Mo','Di','Mi','Do','Fr','Sa','So'];
  return `<div class="php-heat" role="img" aria-label="PHP-Meldungen nach Wochentag und Stunde in UTC"><span></span>${Array.from({length:24},(_,h)=>`<small>${String(h).padStart(2,'0')}</small>`).join('')}${data.hours.map((row,d)=>`<strong>${days[d]}</strong>${row.map((count,h)=>`<i data-intensity="${count/max}" title="${days[d]} ${String(h).padStart(2,'0')}:00 UTC: ${num(count)}"></i>`).join('')}`).join('')}</div>`;
}
function recent(data,sources){
  return `<section class="php-panel php-wide"><h2>Letzte Meldungen</h2>${data.recent.length?`<div class="table-wrap"><table><thead><tr><th>Zeit UTC</th><th>Typ</th><th>Datei</th><th>Quelle</th><th>Meldung</th></tr></thead><tbody>${data.recent.map(record=>`<tr data-id="${esc(record.event.id)}"><td class="mono nowrap">${esc(record.event.timestampUtc?.slice(0,19).replace('T',' ')??'—')}</td><td><span class="php-kind php-${esc(record.kind)}">${esc(labels[record.kind]??record.kind)}</span></td><td class="php-file" title="${esc(record.file??'')}">${esc(record.file??'—')}${record.line?':'+record.line:''}</td><td>${esc(sources.find(source=>source.id===record.event.sourceId)?.name??record.event.sourceId)}</td><td class="php-message" title="${esc(record.description)}">${esc(record.description)}</td></tr>`).join('')}</tbody></table></div>`:'<p class="muted">Keine Meldungen.</p>'}</section>`;
}
function slowRequests(data){
  if(!data.slowest.length)return '';
  return `<section class="php-panel"><h2>Langsame PHP-Requests</h2><div class="table-wrap"><table><thead><tr><th>Dauer</th><th>Script</th><th>Request</th><th>Pool</th><th>Zeit UTC</th></tr></thead><tbody>${data.slowest.map(record=>`<tr data-id="${esc(record.event.id)}"><td class="mono nowrap">${(record.durationMs/1000).toLocaleString('de-DE',{maximumFractionDigits:3})} s</td><td>${esc(record.file??'—')}</td><td>${esc([record.requestMethod,record.requestPath].filter(Boolean).join(' ')||'—')}</td><td>${esc(record.pool??'—')}</td><td class="mono nowrap">${esc(record.event.timestampUtc?.slice(0,19).replace('T',' ')??'—')}</td></tr>`).join('')}</tbody></table></div></section>`;
}

export function renderPhpView(events,sources,selection){
  const all=events.filter(event=>phpRecord(event)),sourceIds=new Set(all.map(event=>event.sourceId));
  const eligible=sources.filter(source=>sourceIds.has(source.id));
  const source=eligible.some(item=>item.id===selection.source)?selection.source:'all';
  const kind=kinds.includes(selection.kind)?selection.kind:'all';
  const data=analyzePhp(events,{source,kind});
  if(!all.length)return `<section class="php-intro"><span class="php-symbol">&lt;?php</span><h2>PHP-Logs auswerten</h2><p>PHP-Fehlerlogs, PHP-FPM-Meldungen und Slowlogs importieren. Auch PHP-Meldungen in Apache- oder Nginx-Fehlerlogs werden berücksichtigt.</p></section>`;
  const critical=(data.counts.fatal??0)+(data.counts.parse??0)+(data.counts.error??0),warnings=(data.counts.warning??0)+(data.counts.slow??0);
  const breakdown=kinds.map(key=>({key,count:data.counts[key]??0})).filter(item=>item.count);
  return `<div class="php-hero"><div><span class="eyebrow">PHP / OFFLINE-DIAGNOSE</span><h2>PHP im Überblick</h2><p>${num(data.total)} Meldungen aus ${num(data.sourceCount)} ${data.sourceCount===1?'Quelle':'Quellen'} im aktuellen Filterbereich.</p></div><div class="php-controls"><label>Quelle<select id="phpSource"><option value="all">Alle PHP-Quellen</option>${eligible.map(item=>`<option value="${esc(item.id)}" ${source===item.id?'selected':''}>${esc(item.name)}</option>`).join('')}</select></label><label>Typ<select id="phpKind"><option value="all">Alle Typen</option>${kinds.map(value=>`<option value="${value}" ${kind===value?'selected':''}>${esc(labels[value])}</option>`).join('')}</select></label></div></div>
  <div class="php-metrics">${metric('Meldungen',num(data.total),'gefilterter Bestand')}${metric('Kritisch',num(critical),'Fatal, Syntax, Fehler')}${metric('Warnung / Slow',num(warnings),'protokollierte Hinweise')}${metric('Veraltet',num(data.counts.deprecated??0),'Deprecated')}${metric('Dateien',num(data.fileCount),'betroffene Dateien')}${metric('Stacktraces',num(data.stackCount),'mit Frames')}</div>
  <div class="php-grid"><section class="php-panel"><h2>Fehlertypen</h2><div class="php-distribution"><div class="php-donut" data-critical="${critical}" data-warning="${warnings}" data-deprecated="${data.counts.deprecated??0}" data-other="${Math.max(0,data.total-critical-warnings-(data.counts.deprecated??0))}" role="img" aria-label="Verteilung der PHP-Meldungen"><span>${num(data.total)}<small>gesamt</small></span></div><div class="php-legend">${breakdown.map(item=>`<button type="button" data-php-kind="${item.key}"><i class="php-dot php-dot-${item.key}"></i><span>${esc(labels[item.key])}</span><strong>${num(item.count)}</strong></button>`).join('')}</div></div></section><section class="php-panel"><h2>Aktivität nach Wochentag und Stunde</h2>${heatmap(data)}<p class="muted">UTC · ${num(data.dated)} datiert · ${num(data.undated)} ohne vergleichbare Zeit</p></section><section class="php-panel php-wide"><div class="section-head"><h2>Meldungen im Zeitverlauf</h2><span>Tagesabschnitte · UTC</span></div>${timeline(data)}</section></div>
  <div class="php-grid">${ranking('Betroffene Dateien',data.files,data.total,'phpFile')}${ranking('Wiederkehrende Fehler',data.signatures,data.total,null)}${ranking('Ausnahmeklassen',data.exceptions,data.total,'exceptionClass')}${ranking('PHP-FPM-Pools',data.pools,data.total,'phpPool')}</div>${slowRequests(data)}${recent(data,sources)}<p class="muted">Die Ansicht zeigt ausschließlich protokollierte Meldungen. Ein fehlender Eintrag beweist weder Fehlerfreiheit noch einen aktuellen Serverzustand. Für Details und Stacktraces eine Meldung öffnen.</p>`;
}

export function stylePhpView(root=document){
  root.querySelectorAll('.php-rank-track i').forEach(bar=>bar.style.width=bar.dataset.ratio+'%');
  root.querySelectorAll('.php-flow button').forEach(bar=>bar.style.height=bar.dataset.ratio+'%');
  root.querySelectorAll('.php-heat i').forEach(cell=>cell.style.opacity=String(.12+Number(cell.dataset.intensity)*.88));
  const donut=root.querySelector('.php-donut');if(!donut)return;
  const parts=['critical','warning','deprecated','other'].map(key=>Number(donut.dataset[key]||0)),total=parts.reduce((sum,value)=>sum+value,0)||1;
  const colors=['var(--red)','var(--orange)','#ac91ee','var(--blue)'];let progress=0;
  donut.style.background='conic-gradient('+parts.map((value,index)=>{const start=progress;progress+=value/total*100;return `${colors[index]} ${start}% ${progress}%`}).join(',')+')';
}
