import {formats,detect,groupErrors,compare,percentile,redact,redactValue} from './core.js';
import {previewHead,sampleFingerprint} from './compression.js';
import {summarizeTimeRanges,eventsForYear} from './time-ranges.js';
import {timelineBars} from './timeline-chart.js';
import {renderAccessView,styleAccessView} from './access-view.js';
import {upgradeEvents} from './event-model.js';
import {compileFilter} from './query.js';
import {newInvestigation,renderInvestigationTools,bindInvestigationTools,renderDomainView,describeCondition} from './investigation-view.js';
const $=s=>document.querySelector(s),esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const state={sources:[],events:[],view:'Dashboard',selected:null,query:'',regex:false,level:'all',source:'all',from:'',to:'',theme:localStorage.getItem('logscope-theme')||'dark',project:'Neue Analyse',pending:[],worker:null,visible:[],rowHeight:35,reportMask:true,timelineYear:'all',timelineInterval:60000,access:{source:'all',year:'all',bucket:'month'}};
state.investigation=newInvestigation();
const nav=['Dashboard','Dateien','Logviewer','System & Sicherheit','Access-Analyse','Datenbank-Analyse','Suche & Filter','Timeline','Fehleranalyse','Systemkorrelation','Vergleich','Spezialanalysen','Berichte','Einstellungen','Hilfe'];
document.documentElement.dataset.theme=state.theme;
$('#app').innerHTML=`<header><div class="brand"><span class="mark">◉</span><div><strong>LogScope</strong><small>OFFLINE LOG ANALYSIS · v1.4.0</small></div></div><div class="top-actions"><span id="privacy">● Nur lokal</span><button id="theme" title="Theme wechseln">◐</button><button id="importTop" class="primary">＋ Dateien importieren</button></div></header><div class="shell"><aside><div class="side-label">ARBEITSBEREICH</div><nav id="nav"></nav><div class="side-label">PROJEKT</div><div id="projectName"></div><div class="side-label">QUELLEN</div><div id="sources"></div><div class="side-label">AKTIVE FILTER</div><div id="activeFilters">Keine</div></aside><main><div class="page-title"><div><div class="eyebrow">LOGSCOPE / <span id="breadcrumb">DASHBOARD</span></div><h1 id="title">Dashboard</h1><p id="subtitle">Lokale Protokolle untersuchen und Zusammenhänge erkennen.</p></div><div id="pageActions"></div></div><div id="content"></div></main></div><dialog id="importDialog"><form method="dialog"><div class="dialog-head"><h2>Importvorschau</h2><button value="cancel" aria-label="Schließen">✕</button></div><p>Dateien bleiben auf diesem Gerät. Zeitangaben ohne Zeitzone werden nur mit Ihrer Angabe vergleichbar.</p><div id="previews"></div><div class="dialog-actions"><button value="cancel">Abbrechen</button><button type="button" id="startImport" class="primary">Import starten</button></div></form></dialog><input id="fileInput" type="file" multiple hidden accept=".log,.txt,.json,.jsonl,.ndjson,.out,.err,.csv,.gz,.zip">`;
function setView(v){state.view=v;state.selected=null;render();$('main').scrollTop=0}
function renderNav(){$('#nav').innerHTML=nav.map(v=>`<button class="nav-item ${state.view===v?'active':''}" data-view="${esc(v)}">${icon(v)}<span>${esc(v)}</span></button>`).join('');$('#nav').querySelectorAll('button').forEach(b=>b.onclick=()=>setView(b.dataset.view))}
function icon(v){return {'Dashboard':'▦','Dateien':'▤','Logviewer':'≡','System & Sicherheit':'⚑','Datenbank-Analyse':'▤','Access-Analyse':'▣','Suche & Filter':'⌕','Timeline':'▥','Fehleranalyse':'⚑','Systemkorrelation':'⌁','Vergleich':'⇄','Spezialanalysen':'◈','Berichte':'▧','Einstellungen':'⚙','Hilfe':'?'}[v]}
function renderSidebar(){
  $('#projectName').textContent=state.project;
  $('#sources').innerHTML=state.sources.length?state.sources.map(source=>`<button class="source-item" data-source="${esc(source.id)}"><i></i><span title="${esc(source.name)}">${esc(source.name)}</span><small>${source.count.toLocaleString('de-DE')}</small></button>`).join(''):'<div class="muted pad">Noch keine Dateien</div>';
  $('#sources').querySelectorAll('button').forEach(button=>button.onclick=()=>{state.source=button.dataset.source;setView('Logviewer')});
  $('#activeFilters').textContent=scopeLabels().join(' · ')||'Keine';
}
function sourceName(id){return state.sources.find(s=>s.id===id)?.name||id}
function filterEvents(){
  const query=state.query.toLowerCase(),sources=new Set(state.investigation.sources);
  const match=compileFilter({op:'all',conditions:[{op:state.investigation.conditions.length?state.investigation.mode:'all',conditions:state.investigation.conditions},...state.investigation.constraints]});
  let expression=null;
  if(state.regex&&query){try{if(query.length>180)throw Error('Ausdruck zu lang');expression=new RegExp(state.query,'i')}catch{return []}}
  const from=state.from?new Date(state.from.endsWith('Z')?state.from:state.from+'Z').toISOString():null;
  const to=state.to?new Date(state.to.endsWith('Z')?state.to:state.to+'Z').toISOString():null;
  return state.events.filter(event=>{
    if(state.source!=='all'&&event.sourceId!==state.source)return false;
    if(sources.size&&!sources.has(event.sourceId))return false;
    if(state.level!=='all'&&event.severity!==state.level)return false;
    if(from&&(!event.timestampUtc||event.timestampUtc<from))return false;
    if(to&&(!event.timestampUtc||event.timestampUtc>=to))return false;
    if(!match(event))return false;
    if(query){const text=event.message+' '+event.raw+' '+JSON.stringify(event.fields);if(expression?!expression.test(text):!text.toLowerCase().includes(query))return false}
    return true;
  });
}
function stats(events){let times=events.map(e=>e.timestampUtc).filter(Boolean).sort();return {total:events.length,error:events.filter(e=>e.severity==='error').length,warn:events.filter(e=>e.severity==='warn').length,unknown:events.filter(e=>!e.severity).length,first:times[0],last:times.at(-1)}}
function card(label,value,sub=''){return `<div class="stat"><div>${esc(label)}</div><strong>${esc(value)}</strong><small>${esc(sub)}</small></div>`}
function chart(events,interval=60000){
  const {bars,intervals,compressed}=timelineBars(events,interval);
  if(!bars.length)return '<div class="empty">Keine vergleichbaren Zeitstempel vorhanden.</div>';
  const max=Math.max(...bars.map(bar=>bar.all));
  const columns=bars.map(bar=>`<button type="button" title="${new Date(bar.start).toLocaleString('de-DE')} – ${new Date(bar.end).toLocaleString('de-DE')}: ${bar.all} Ereignisse, ${bar.error} Fehler" data-time="${bar.start}" data-end="${bar.end}" data-height="${Math.max(2,Math.round(bar.all/max*100))}" class="${bar.error?'has-error':''}"></button>`).join('');
  const note=compressed?`<p class="muted">${intervals.toLocaleString('de-DE')} aktive Intervalle zu ${bars.length} Balken zusammengefasst; alle Ereignisse sind enthalten.</p>`:'';
  return `<div class="chart" role="img" aria-label="Ereignisse über Zeit">${columns}</div><div class="axis"><span>${new Date(bars[0].start).toLocaleString('de-DE')}</span><span>${new Date(bars.at(-1).end).toLocaleString('de-DE')}</span></div>${note}`;
}
function styleCharts(){document.querySelectorAll('.chart [data-height]').forEach(button=>button.style.height=button.dataset.height+'%')}
function openChartBin(button){
  const start=Number(button.dataset.time),end=Number(button.dataset.end);
  state.from=new Date(start).toISOString().slice(0,23);
  state.to=new Date(end).toISOString().slice(0,23);
  setView('Suche & Filter');
}
function table(events,limit=100){return `<div class="table-wrap"><table><thead><tr><th>Zeit</th><th>Level</th><th>Quelle</th><th>Dienst</th><th>Kategorie</th><th>Nachricht</th></tr></thead><tbody>${events.slice(0,limit).map(e=>`<tr data-id="${esc(e.id)}"><td class="mono nowrap">${esc(e.timestampUtc?.replace('T',' ').replace('Z','')||'—')}</td><td><span class="badge ${esc(e.severity||'unknown')}">${esc(e.severity||'unbekannt')}</span></td><td>${esc(sourceName(e.sourceId))}</td><td>${esc(e.service||'—')}</td><td>${esc(e.category||'—')}</td><td class="message" title="${esc(e.message)}">${esc(e.message)}</td></tr>`).join('')}</tbody></table></div>${events.length>limit?`<p class="muted">${limit.toLocaleString('de-DE')} von ${events.length.toLocaleString('de-DE')} Treffern angezeigt.</p>`:''}`}
function detail(e){if(!e)return '<div class="empty">Ein Ereignis auswählen, um die Originaldaten zu sehen.</div>';let neighbors=state.events.filter(x=>x.timestampUtc&&e.timestampUtc&&Math.abs(Date.parse(x.timestampUtc)-Date.parse(e.timestampUtc))<=30000&&x.id!==e.id).slice(0,12);return `<div class="detail-head"><h3>Ereignisdetail</h3><button id="closeDetail">✕</button></div><div class="detail-meta"><b>Quelle</b><span>${esc(sourceName(e.sourceId))}</span><b>Zeilen</b><span>${e.lineStart}–${e.lineEnd}</span><b>Zeit roh</b><span>${esc(e.timestampRaw||'unbekannt')}</span><b>Zeit UTC</b><span>${esc(e.timestampUtc||'nicht vergleichbar')}</span><b>Parser</b><span>${esc(e.parserId)}</span></div><h4>Nachricht</h4><pre>${esc(e.message)}</pre><h4>Originaltext</h4><pre>${esc(e.raw)}</pre><h4>Felder</h4><pre>${esc(JSON.stringify(e.fields,null,2))}</pre>${e.parseWarnings.length?`<p class="warning">${esc(e.parseWarnings.join('; '))}</p>`:''}<h4>Zeitliches Umfeld ±30 s</h4>${neighbors.length?neighbors.map(x=>`<button class="neighbor" data-id="${esc(x.id)}">${esc(sourceName(x.sourceId))}: ${esc(x.message.slice(0,100))}</button>`).join(''):'<p class="muted">Keine weiteren Ereignisse mit vergleichbarer Zeit.</p>'}<label>Notiz<textarea id="note">${esc(e.note||'')}</textarea></label><button id="copyEvent">Ereignis kopieren</button>`}
function renderDashboard(){
  const events=filterEvents(),summary=stats(events),groups=groupErrors(events);
  return `${state.sources.some(source=>source.incomplete||source.error)?'<p class="warning">Mindestens eine Quelle ist unvollstaendig. Kennzahlen zeigen nur eingelesene Ereignisse.</p>':''}<div class="stats">${card('QUELLEN',new Set(events.map(event=>event.sourceId)).size)}${card('EREIGNISSE',summary.total.toLocaleString('de-DE'))}${card('FEHLER',summary.error.toLocaleString('de-DE'))}${card('WARNUNGEN',summary.warn.toLocaleString('de-DE'))}${card('FEHLERGRUPPEN',groups.length)}</div><div class="grid2"><section><div class="section-head"><h2>Ereignisse über Zeit</h2><span>1 Minute</span></div>${chart(events)}</section><section><h2>Analysezeitraum</h2><div class="range"><strong>${esc(summary.first?new Date(summary.first).toLocaleString('de-DE'):'Unbekannt')}</strong><span>bis</span><strong>${esc(summary.last?new Date(summary.last).toLocaleString('de-DE'):'Unbekannt')}</strong></div><p class="muted">${summary.unknown} Ereignisse ohne klassifizierten Schweregrad.</p></section></div><section><div class="section-head"><h2>Häufigste Fehlergruppen</h2><button data-go="Fehleranalyse">Alle ansehen →</button></div>${groups.slice(0,8).map(group=>`<div class="group-line"><b>${group.count}</b><span>${esc(group.example.slice(0,180))}</span></div>`).join('')||'<div class="empty">Keine Fehlergruppen.</div>'}</section><section><h2>Letzte Ereignisse</h2>${table(events.slice(-12).reverse(),12)}</section>`;
}
function renderFiles(){return `<section><div class="section-head"><h2>Importierte Dateien</h2><button id="addFiles" class="primary">＋ Weitere Dateien</button></div>${state.sources.length?`<div class="file-list">${state.sources.map(s=>`<div class="file-row"><div><strong>${esc(s.name)}</strong><small>${esc(s.originalName)} · ${(s.size/1024/1024).toFixed(2)} MB · ${esc(s.format)} · ${s.count.toLocaleString('de-DE')} Ereignisse</small><small>${s.done?'Abgeschlossen':s.error?'Fehler: '+esc(s.error):'Import läuft: '+s.bytes.toLocaleString('de-DE')+' Bytes verarbeitet'}</small></div><div><button data-rename="${esc(s.id)}">Umbenennen</button><button data-remove="${esc(s.id)}">Entfernen</button></div></div>`).join('')}</div>`:'<div class="empty">Ziehen Sie Logdateien hierher oder wählen Sie sie über „Dateien importieren“ aus.</div>'}</section><section><h2>Verarbeitung</h2><p>Importierte Rohlogs werden standardmäßig nur im Arbeitsspeicher gehalten. Ein Projekt wird erst durch „Projekt speichern“ dauerhaft in diesem Browser abgelegt.</p></section>`}
function renderViewer(){
  const events=filterEvents();state.visible=events;
  const active=!!(state.query||state.level!=='all'||state.source!=='all'||state.from||state.to||state.investigation.conditions.length||state.investigation.constraints.length||state.investigation.sources.length);
  return `<div class="viewer-tools"><input id="quickSearch" placeholder="Nachricht oder Rohtext durchsuchen" value="${esc(state.query)}"><select id="quickLevel"><option value="all">Alle Level</option><option value="error">Fehler</option><option value="warn">Warnungen</option><option value="info">Info</option></select><select id="quickSource"><option value="all">Alle Quellen</option>${state.sources.map(s=>`<option value="${esc(s.id)}">${esc(s.name)}</option>`).join('')}</select><button id="resetViewerFilters" type="button" ${active?'':'hidden'}>Filter zurücksetzen</button><span id="viewerCount">${events.length.toLocaleString('de-DE')} von ${state.events.length.toLocaleString('de-DE')} Ereignissen</span></div><div class="viewer-layout"><section class="viewer-section"><div id="viewerEmpty" class="empty" ${events.length?'hidden':''}>${state.events.length?'Keine Treffer für die aktuellen Filter. Filter zurücksetzen oder Suche anpassen.':'Noch keine Ereignisse importiert.'}</div><div id="virtualViewport" ${events.length?'':'hidden'}><div id="virtualInner"></div></div></section><section class="detail" id="detail">${detail(state.selected)}</section></div>`;
}
function updateViewer(){
  state.visible=filterEvents();const count=$('#viewerCount'),empty=$('#viewerEmpty'),viewport=$('#virtualViewport'),reset=$('#resetViewerFilters');
  count.textContent=state.visible.length.toLocaleString('de-DE')+' von '+state.events.length.toLocaleString('de-DE')+' Ereignissen';
  empty.hidden=state.visible.length>0;viewport.hidden=state.visible.length===0;
  empty.textContent=state.events.length?'Keine Treffer für die aktuellen Filter. Filter zurücksetzen oder Suche anpassen.':'Noch keine Ereignisse importiert.';
  reset.hidden=!(state.query||state.level!=='all'||state.source!=='all'||state.from||state.to||state.investigation.conditions.length||state.investigation.constraints.length||state.investigation.sources.length);
  viewport.scrollTop=0;renderVirtual();renderSidebar();
  $('.scope-controls').outerHTML=renderScopeControls();bindScopeButtons();
}
function renderVirtual(){let vp=$('#virtualViewport'),inner=$('#virtualInner');if(!vp||!inner)return;let events=state.visible,top=Math.floor(vp.scrollTop/state.rowHeight),count=Math.ceil(vp.clientHeight/state.rowHeight)+12,start=Math.max(0,top-6),end=Math.min(events.length,start+count);inner.style.height=events.length*state.rowHeight+'px';inner.innerHTML=`<div class="virtual-rows" style="transform:translateY(${start*state.rowHeight}px)">${events.slice(start,end).map(e=>`<button class="virtual-row ${state.selected?.id===e.id?'selected':''}" data-id="${esc(e.id)}"><span class="mono">${esc(e.timestampUtc?.slice(0,19).replace('T',' ')||'—')}</span><span class="badge ${esc(e.severity||'unknown')}">${esc(e.severity||'—')}</span><span>${esc(sourceName(e.sourceId))}</span><span class="truncate">${esc(e.message)}</span></button>`).join('')}</div>`;inner.querySelectorAll('button').forEach(b=>b.onclick=()=>selectEvent(b.dataset.id))}
function renderSearch(){return `<section><h2>Suche & Filter</h2><div class="form-grid"><label>Suchbegriff<input id="searchText" value="${esc(state.query)}" placeholder="Freitext oder Regex"></label><label>Suchmodus<select id="searchMode"><option value="text">Freitext</option><option value="regex">Regex</option></select></label><label>Schweregrad<select id="searchLevel"><option value="all">Alle</option><option value="error">Fehler</option><option value="warn">Warnung</option><option value="info">Info</option></select></label><label>Quelle<select id="searchSource"><option value="all">Alle</option>${state.sources.map(source=>`<option value="${esc(source.id)}">${esc(source.name)}</option>`).join('')}</select></label><label>Ab UTC<input type="datetime-local" step="0.001" id="searchFrom" value="${esc(state.from)}"></label><label>Bis UTC (exklusiv)<input type="datetime-local" step="0.001" id="searchTo" value="${esc(state.to)}"></label></div><div class="dialog-actions"><button id="clearFilter">Zurücksetzen</button><button id="applyFilter" class="primary">Filter anwenden</button></div><p id="searchError" class="warning" role="alert"></p></section>`}
function renderTimeline(correlation=false){
  const events=filterEvents(),ranges=summarizeTimeRanges(events,state.sources);
  if(state.timelineYear!=='all'&&!ranges.years.some(([year])=>year===state.timelineYear))state.timelineYear='all';
  const ev=eventsForYear(events,state.timelineYear).sort((a,b)=>a.timestampUtc.localeCompare(b.timestampUtc));
  const years=ranges.years.map(([year,count])=>`<option value="${year}" ${state.timelineYear===year?'selected':''}>${year} (${count.toLocaleString('de-DE')})</option>`).join('');
  const sourceRows=ranges.sources.map(s=>`<tr><td>${esc(s.name)}</td><td>${s.first?esc(new Date(s.first).toLocaleString('de-DE')):'—'}</td><td>${s.last?esc(new Date(s.last).toLocaleString('de-DE')):'—'}</td><td>${s.dated.toLocaleString('de-DE')}</td><td>${s.undated.toLocaleString('de-DE')}</td></tr>`).join('');
  return `<section><div class="section-head"><h2>${correlation?'Quellenübergreifende Ereignisse':'Gemeinsame Timeline'}</h2><div class="timeline-controls"><label>Zeitraum <select id="timelineYear"><option value="all">Alle Jahre</option>${years}</select></label><label>Intervall <select id="interval"><option value="60000">1 Minute</option><option value="10000">10 Sekunden</option><option value="300000">5 Minuten</option><option value="3600000">1 Stunde</option></select></label></div></div><div id="timelineChart">${chart(ev,state.timelineInterval)}</div><p class="muted">${ranges.dated.toLocaleString('de-DE')} datierte und ${ranges.undated.toLocaleString('de-DE')} undatierte Ereignisse. Undatierte Ereignisse bleiben im Logviewer sichtbar; ohne Zeitstempel können sie nicht zeitlich eingeordnet werden.</p><p class="muted">Nur Ereignisse mit eindeutigem UTC-Zeitstempel werden zeitlich korreliert. Nähe in der Zeit belegt keine Ursache.</p></section><section><h2>Vorhandene Zeiträume je Datei</h2><div class="table-wrap"><table><thead><tr><th>Datei</th><th>Erstes Ereignis</th><th>Letztes Ereignis</th><th>Datiert</th><th>Undatiert</th></tr></thead><tbody>${sourceRows}</tbody></table></div></section><section><h2>${correlation?'Zeitlich sortierte Belege':'Ereignisse im Zeitverlauf'}</h2>${table(ev,150)}</section>`;
}
function renderErrors(){
  const events=filterEvents(),groups=groupErrors(events);
  return `<div class="stats">${card('FEHLERGRUPPEN',groups.length)}${card('FEHLER',stats(events).error)}${card('BETROFFENE QUELLEN',new Set(events.filter(event=>event.severity==='error').map(event=>event.sourceId)).size)}</div><section><h2>Wiederkehrende Muster</h2><div class="table-wrap"><table><thead><tr><th>Anzahl</th><th>Muster</th><th>Erste Sichtung</th><th>Letzte Sichtung</th><th>Quellen</th></tr></thead><tbody>${groups.map(group=>`<tr><td>${group.count}</td><td><button data-error-key="${esc(group.key)}">${esc(group.example)}</button></td><td>${esc(group.first||'—')}</td><td>${esc(group.last||'—')}</td><td>${group.sources.size}</td></tr>`).join('')}</tbody></table></div><p class="muted">Textmuster sind Hinweise, keine Ursachenfeststellung.</p></section>`;
}
function metricSet(ev){let s=stats(ev),t=ev.map(e=>e.timestampUtc).filter(Boolean).sort(),hours=t.length>1?(Date.parse(t.at(-1))-Date.parse(t[0]))/3600000:null;return {s,hours,perHour:hours>0?s.error/hours:null}}
function renderCompare(){
  const events=filterEvents(),left=new Set(state.sources.filter(source=>source.side==='A').map(source=>source.id)),right=new Set(state.sources.filter(source=>source.side==='B').map(source=>source.id));
  const reference=events.filter(event=>left.has(event.sourceId)),comparison=events.filter(event=>right.has(event.sourceId)),difference=compare(reference,comparison);
  const summary=(name,scope)=>{const metrics=metricSet(scope);return `<section><h2>${name}</h2>${card('Ereignisse',metrics.s.total)}${card('Fehler',metrics.s.error)}${card('Fehler pro Stunde',metrics.perHour?.toFixed(2)??'n/a',metrics.hours?metrics.hours.toFixed(2)+' h':'Zeitraum fehlt')}</section>`};
  return `<section><h2>Bestände zuordnen</h2><div class="compare-sources">${state.sources.map(source=>`<label>${esc(source.name)}<select data-side="${esc(source.id)}"><option value="">Nicht zugeordnet</option><option value="A" ${source.side==='A'?'selected':''}>A · Referenz</option><option value="B" ${source.side==='B'?'selected':''}>B · Vergleich</option></select></label>`).join('')}</div></section><div class="grid2">${summary('A · Referenz',reference)}${summary('B · Vergleich',comparison)}</div><section><h2>Fehlergruppen im Vergleich</h2><div class="table-wrap"><table><thead><tr><th>Muster</th><th>A</th><th>B</th><th>Differenz absolut</th></tr></thead><tbody>${difference.map(group=>`<tr><td>${esc(group.key)}</td><td>${group.a}</td><td>${group.b}</td><td>${group.b-group.a}</td></tr>`).join('')}</tbody></table></div><p class="muted">Fehlende Ereignisse belegen keine Behebung. Beide Bestaende verwenden die aktiven Filter.</p></section>`;
}
function renderSpecial(){
  const events=filterEvents(),requests=events.filter(event=>event.normalized?.domain==='web'&&event.normalized.status!==null);
  const latencies=requests.map(event=>event.normalized.durationMs).filter(value=>value!==null),slow=events.filter(event=>['mysql-slow','mariadb-slow'].includes(event.parserId));
  const durations=slow.map(event=>event.normalized.durationMs).filter(value=>value!==null),first=events.find(event=>event.parserId==='jenkins'&&(event.severity==='error'||event.fields.exitCode>0));
  return `<div class="grid2"><section><h2>HTTP</h2><div class="stats compact">${card('Requests',requests.length)}${card('4xx',requests.filter(event=>event.normalized.status>=400&&event.normalized.status<500).length)}${card('5xx',requests.filter(event=>event.normalized.status>=500).length)}${card('P95 Latenz',latencies.length?percentile(latencies,.95).toFixed(1)+' ms':'n/a')}</div></section><section><h2>MySQL / MariaDB · Slow Queries</h2><div class="stats compact">${card('Abfragen',slow.length)}${card('Median',durations.length?percentile(durations,.5).toFixed(1)+' ms':'n/a')}${card('P95',durations.length?percentile(durations,.95).toFixed(1)+' ms':'n/a')}${card('Replikationsmeldungen',events.filter(event=>event.category==='Replikation').length)}</div></section></div><section><h2>Jenkins · erstes Fehlersignal</h2>${first?`<p>${esc(first.message)}</p><p class="muted">Quelle: ${esc(sourceName(first.sourceId))}, Zeile ${first.lineStart}. Hinweis, keine gesicherte Ursache.</p>`:'<div class="empty">Kein Fehlersignal erkannt.</div>'}</section><section><h2>Langsame SQL-Muster</h2><div class="table-wrap"><table><thead><tr><th>Zeit UTC</th><th>Dauer (ms)</th><th>Rows Examined</th><th>Muster</th></tr></thead><tbody>${[...slow].sort((left,right)=>(right.normalized.durationMs??0)-(left.normalized.durationMs??0)).slice(0,25).map(event=>`<tr data-id="${esc(event.id)}"><td>${esc(event.timestampUtc||'—')}</td><td>${esc(event.normalized.durationMs??'—')}</td><td>${esc(event.normalized.rowsExamined??'—')}</td><td>${esc(event.normalized.queryPattern||'—')}</td></tr>`).join('')}</tbody></table></div></section>`;
}
function reportText(mask=state.reportMask){
  const events=filterEvents(),summary=stats(events),groups=groupErrors(events);
  const text=`# ${state.project}\n\nLogScope-Bericht · ${new Date().toISOString()}\n\nExport: ${mask?'maskiert':'unmaskiert'}\n\n## Analysefilter\n${JSON.stringify({query:state.query,regex:state.regex,source:state.source,level:state.level,from:state.from,toExclusive:state.to,fields:{mode:state.investigation.mode,conditions:state.investigation.conditions,constraints:state.investigation.constraints,sources:state.investigation.sources}},null,2)}\n\n## Quellen\n${state.sources.map(source=>`- ${source.name}: ${events.filter(event=>event.sourceId===source.id).length} Ereignisse im Filter, ${source.format}`).join('\n')}\n\n## Datenqualität\n- Unvollstaendige Quellen: ${state.sources.filter(source=>source.incomplete||source.error).length}\n\n## Kennzahlen\n- Ereignisse: ${summary.total}\n- Fehler: ${summary.error}\n- Warnungen: ${summary.warn}\n- Zeitraum: ${summary.first||'unbekannt'} bis ${summary.last||'unbekannt'}\n\n## Fehlergruppen\n${groups.map(group=>`- ${group.count} × ${group.example}`).join('\n')}\n\n## Hinweis\nZeitliche Naehe und Textmuster beweisen keine Ursache.\n`;
  return mask?redact(text):text;
}
function renderReports(){return `<section><h2>Berichtsvorschau</h2><label class="check"><input id="maskReport" type="checkbox" ${state.reportMask?'checked':''}> Sensible Werte im Export maskieren</label><pre id="reportPreview" class="report-preview">${esc(reportText())}</pre><div class="dialog-actions"><button id="exportMd" class="primary">Markdown herunterladen</button><button id="exportHtml">HTML herunterladen</button><button id="exportJson">JSON herunterladen</button><button id="exportCsv">CSV herunterladen</button><button id="printReport">Drucken / PDF</button></div></section>`}
function renderSettings(){return `<section><h2>Analyseprojekt</h2><div class="form-grid"><label>Projektname<input id="projectInput" value="${esc(state.project)}"></label><label>Theme<select id="themeSelect"><option value="dark">Dunkel</option><option value="light">Hell</option></select></label></div><p class="muted">„Projekt speichern“ legt Quellen, Ereignisse und gemerkte Feldauswertungen in IndexedDB dieser Browser-Origin ab. Rohlogs koennen vertrauliche Inhalte enthalten. Das Speichern erfolgt nur auf Ihren Klick.</p><div class="dialog-actions"><button id="saveProject" class="primary">Projekt speichern</button><button id="loadProject">Gespeichertes Projekt öffnen</button><button id="deleteProject">Gespeichertes Projekt löschen</button></div><p id="storageMessage" class="muted"></p></section><section><h2>Speichergrenze</h2><p>Die Sitzung haelt Ereignisse im Arbeitsspeicher. Bei insgesamt 250.000 Ereignissen stoppt der Import und kennzeichnet betroffene Quellen als unvollstaendig. Blockweise lokale Archivierung, Hintergrundabfragen und der Betrieb mit mehreren Millionen Ereignissen sind noch nicht implementiert.</p></section>`}
function renderHelp(){return `<section><h2>LogScope verwenden</h2><p>Dateien per Schaltfläche oder Drag-and-drop importieren. Nach der Vorschau Format, Bezugsjahr und Zeitzonenoffset kontrollieren. Anschließend Dashboard, Logviewer und Vergleich nutzen.</p><h3>Logformate</h3><p>Syslog, Journald, Caddy, MariaDB, MySQL, MongoDB, Db2, PostgreSQL, Nginx/Apache, AWS CloudTrail/CloudWatch/ALB/VPC/WAF/S3/CloudFront/ECS/Lambda, Kubernetes CRI/klog/Docker/Audit/Event, Jenkins sowie generischer Text/JSONL. Native .journal- und Binlog-Dateien sind nicht lesbar.</p><h3>Exportbefehle</h3><pre>journalctl --output=json &gt; journal.jsonl\njournalctl -u caddy --output=short-iso-precise &gt; caddy-journal.log\njournalctl -u mariadb --output=json &gt; mariadb-journal.jsonl</pre><p>Diese Befehle dienen nur als Vorlage und werden nicht ausgeführt.</p><h3>Datenschutz</h3><p>Der Browser erhält ausschließlich Zugriff auf ausdrücklich ausgewählte Dateien. Es finden keine Netzwerkabfragen oder Uploads statt. Projekte werden nur nach Klick auf „Projekt speichern“ dauerhaft abgelegt.</p></section>`}
function render(){
  renderNav();renderSidebar();$('#title').textContent=state.view;$('#breadcrumb').textContent=state.view.toUpperCase();
  const views={'Dashboard':renderDashboard,'Dateien':renderFiles,'Logviewer':renderViewer,
    'System & Sicherheit':()=>renderDomainView(filterEvents(),'system'),
    'Datenbank-Analyse':()=>renderDomainView(filterEvents(),'database'),
    'Access-Analyse':()=>renderAccessView(filterEvents(),state.sources,state.access),
    'Suche & Filter':()=>renderSearch()+renderInvestigationTools(state.investigation,filterEvents(),state.sources)+`<section><h2>Treffer</h2>${table(filterEvents(),100)}</section>`,
    'Timeline':()=>renderTimeline(false),'Fehleranalyse':renderErrors,'Systemkorrelation':()=>renderTimeline(true),
    'Vergleich':renderCompare,'Spezialanalysen':renderSpecial,'Berichte':renderReports,'Einstellungen':renderSettings,'Hilfe':renderHelp};
  $('#content').innerHTML=renderScopeControls()+views[state.view]();bind();bindScopeControls();styleCharts();
}
function resetScope(){
  Object.assign(state,{query:'',regex:false,level:'all',source:'all',from:'',to:''});
  Object.assign(state.investigation,{conditions:[],constraints:[],sources:[],mode:'all'});
}
function scopeLabels(){
  const analysis=state.investigation;
  return [state.query&&`Suche: ${state.query}`,state.level!=='all'&&`Level: ${state.level}`,state.source!=='all'&&sourceName(state.source),state.from&&`Ab UTC: ${state.from}`,state.to&&`Bis UTC (exklusiv): ${state.to}`,analysis.sources.length&&`${analysis.sources.length} Quellen`,analysis.conditions.length&&describeCondition({op:analysis.mode,conditions:analysis.conditions}),...analysis.constraints.map(condition=>'Drilldown: '+describeCondition(condition))].filter(Boolean);
}
function renderScopeControls(){
  const labels=scopeLabels();
  return `<div class="scope-controls"><span>${labels.length?esc(labels.join(' · ')):'Alle Ereignisse · kein Filter'}</span><button type="button" id="editScope">Filter</button>${labels.length?'<button type="button" id="resetScope">Zurücksetzen</button>':''}</div>`;
}
function drillConditions(conditions){
  state.investigation={...state.investigation,constraints:[...state.investigation.constraints,...conditions]};
  setView('Logviewer');
}
function bindScopeButtons(){
  $('#editScope').onclick=()=>setView('Suche & Filter');
  if($('#resetScope'))$('#resetScope').onclick=()=>{resetScope();render()};
}
function bindScopeControls(){
  bindScopeButtons();
  bindInvestigationTools($('#content'),state.investigation,filterEvents(),{
    apply:analysis=>{compileFilter({op:analysis.mode,conditions:analysis.conditions});state.investigation=analysis;render()},
    drill:drillConditions
  });
  document.querySelectorAll('[data-domain-field]').forEach(button=>button.onclick=()=>drillConditions([
    {field:'domain',op:'eq',value:state.view==='Datenbank-Analyse'?'database':'system'},
    {field:button.dataset.domainField,op:button.dataset.domainMissing?'missing':'eq',value:button.dataset.domainValue}
  ]));
  document.querySelectorAll('[data-error-key]').forEach(button=>button.onclick=()=>drillConditions([
    {field:'fingerprint',op:'exact',value:button.dataset.errorKey},
    {op:'any',conditions:[{field:'severity',op:'eq',value:'error'},{field:'status',op:'gte',value:500}]}
  ]));
}
function selectEvent(id){state.selected=state.events.find(e=>e.id===id);if(state.view==='Logviewer'){$('#detail').innerHTML=detail(state.selected);bindDetail();renderVirtual()}else{state.view='Logviewer';render();$('main').scrollTop=0}}
function bindDetail(){let e=state.selected;if(!e)return;$('#closeDetail')?.addEventListener('click',()=>{state.selected=null;$('#detail').innerHTML=detail(null);renderVirtual()});$('#note')?.addEventListener('input',x=>e.note=x.target.value);$('#copyEvent')?.addEventListener('click',()=>navigator.clipboard.writeText(e.raw));document.querySelectorAll('.neighbor').forEach(b=>b.onclick=()=>selectEvent(b.dataset.id))}
function bindAccess(){
  if(state.view!=='Access-Analyse')return;
  styleAccessView($('#content'));
  for(const [id,key] of [['accessSource','source'],['accessYear','year'],['accessBucket','bucket']]){
    const select=$('#'+id);if(select)select.onchange=()=>{state.access[key]=select.value;render()};
  }
  document.querySelectorAll('[data-access-query]').forEach(button=>button.onclick=()=>{
    const source=$('#accessSource')?.value||'all',year=$('#accessYear')?.value||'all',field=button.dataset.accessField;
    const conditions=[{field:'domain',op:'eq',value:'web'},{field:field==='failedPath'?'path':field,op:field==='status'?'eq':'exact',value:button.dataset.accessQuery}];
    if(field==='failedPath')conditions.push({field:'status',op:'gte',value:400},{field:'status',op:'lt',value:600});
    if(source!=='all')conditions.push({field:'sourceId',op:'exact',value:source});
    if(year!=='all')conditions.push({field:'timestampUtc',op:'gte',value:year+'-01-01T00:00:00Z'},{field:'timestampUtc',op:'lt',value:(Number(year)+1)+'-01-01T00:00:00Z'});
    drillConditions(conditions);
  });
}
function bind(){
  bindAccess();
  document.querySelectorAll('[data-go]').forEach(button=>button.onclick=()=>setView(button.dataset.go));
  document.querySelectorAll('tr[data-id]').forEach(row=>row.onclick=()=>selectEvent(row.dataset.id));
  document.querySelectorAll('[data-time]').forEach(button=>button.onclick=()=>openChartBin(button));
  $('#addFiles')?.addEventListener('click',()=>$('#fileInput').click());
  document.querySelectorAll('[data-remove]').forEach(button=>button.onclick=()=>{
    if(!confirm('Quelle und alle zugehoerigen Ereignisse aus der Sitzung entfernen?'))return;
    state.sources.find(source=>source.id===button.dataset.remove)?.worker?.terminate();
    state.sources=state.sources.filter(source=>source.id!==button.dataset.remove);
    state.events=state.events.filter(event=>event.sourceId!==button.dataset.remove);
    state.investigation.sources=state.investigation.sources.filter(id=>id!==button.dataset.remove);
    if(state.source===button.dataset.remove)state.source='all';
    state.selected=null;render();
  });
  document.querySelectorAll('[data-rename]').forEach(button=>button.onclick=()=>{
    const source=state.sources.find(entry=>entry.id===button.dataset.rename),name=prompt('Anzeigename',source.name);
    if(name?.trim()){source.name=name.trim();render()}
  });
  if(state.view==='Logviewer'){
    $('#quickLevel').value=state.level;$('#quickSource').value=state.source;
    $('#quickSearch').oninput=event=>{state.query=event.target.value;state.regex=false;updateViewer()};
    $('#quickLevel').onchange=event=>{state.level=event.target.value;updateViewer()};
    $('#quickSource').onchange=event=>{state.source=event.target.value;updateViewer()};
    $('#resetViewerFilters').onclick=()=>{resetScope();render()};
    $('#virtualViewport').onscroll=renderVirtual;renderVirtual();bindDetail();
  }
  if(state.view==='Suche & Filter'){
    $('#searchMode').value=state.regex?'regex':'text';$('#searchLevel').value=state.level;$('#searchSource').value=state.source;
    $('#applyFilter').onclick=()=>{
      const query=$('#searchText').value,regex=$('#searchMode').value==='regex';
      if(regex){try{if(query.length>180)throw Error('Regex zu lang');new RegExp(query)}catch(error){$('#searchError').textContent='Ungueltiger Regex: '+error.message;return}}
      const from=$('#searchFrom').value,to=$('#searchTo').value;
      if(from&&to&&from>=to){$('#searchError').textContent='Das Ende muss nach dem Beginn liegen.';return}
      Object.assign(state,{query,regex,level:$('#searchLevel').value,source:$('#searchSource').value,from,to});render();
    };
    $('#clearFilter').onclick=()=>{resetScope();render()};
  }
  if(state.view==='Timeline'||state.view==='Systemkorrelation'){
    $('#interval').value=String(state.timelineInterval);
    $('#interval').onchange=event=>{state.timelineInterval=Number(event.target.value);render()};
    $('#timelineYear').onchange=event=>{state.timelineYear=event.target.value;render()};
  }
  if(state.view==='Vergleich')document.querySelectorAll('[data-side]').forEach(select=>select.onchange=()=>{
    state.sources.find(source=>source.id===select.dataset.side).side=select.value;render();
  });
  if(state.view==='Berichte'){
    $('#maskReport').onchange=event=>{state.reportMask=event.target.checked;$('#reportPreview').textContent=reportText()};
    $('#exportMd').onclick=()=>download('logscope-bericht.md',reportText(),'text/markdown');
    $('#exportHtml').onclick=()=>download('logscope-bericht.html','<!doctype html><html lang="de"><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src &apos;none&apos;"><title>LogScope-Bericht</title><pre>'+esc(reportText())+'</pre></html>','text/html');
    $('#exportJson').onclick=()=>{
      const sources=state.sources.map(({worker,...source})=>source),events=filterEvents();
      const payload={project:state.project,sources,events,scope:{query:state.query,regex:state.regex,source:state.source,level:state.level,from:state.from,toExclusive:state.to,investigation:state.investigation}};
      download('logscope-bericht.json',JSON.stringify(state.reportMask?redactValue(payload):payload,null,2),'application/json');
    };
    $('#exportCsv').onclick=()=>{
      const rows=['zeit,level,quelle,dienst,nachricht',...filterEvents().map(event=>{
        const values=[event.timestampUtc,event.severity,sourceName(event.sourceId),event.service,event.message];
        return (state.reportMask?values.map(value=>redact(value??'')):values).map(csvCell).join(',');
      })];
      download('logscope-ereignisse.csv',rows.join('\r\n'),'text/csv');
    };
    $('#printReport').onclick=()=>window.print();
  }
  if(state.view==='Einstellungen'){
    $('#themeSelect').value=state.theme;
    $('#projectInput').onchange=event=>{state.project=event.target.value||'Neue Analyse';renderSidebar()};
    $('#themeSelect').onchange=event=>setTheme(event.target.value);
    $('#saveProject').onclick=saveProject;$('#loadProject').onclick=loadProject;$('#deleteProject').onclick=deleteProject;
  }
}
function csvCell(v){let value=String(v??'');if(/^[=+@-]/.test(value))value="'"+value;return '"'+value.replaceAll('"','""')+'"'}
function download(name,content,type){let a=document.createElement('a'),url=URL.createObjectURL(new Blob([content],{type:type+';charset=utf-8'}));a.href=url;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(url),60000)}
function setTheme(v){state.theme=v;document.documentElement.dataset.theme=v;localStorage.setItem('logscope-theme',v)}
$('#theme').onclick=()=>{setTheme(state.theme==='dark'?'light':'dark');render()};$('#importTop').onclick=()=>$('#fileInput').click();$('#fileInput').onchange=e=>preview([...e.target.files]);document.body.ondragover=e=>{e.preventDefault();document.body.classList.add('dragging')};document.body.ondragleave=()=>document.body.classList.remove('dragging');document.body.ondrop=e=>{e.preventDefault();document.body.classList.remove('dragging');preview([...e.dataTransfer.files])};
async function preview(files){state.pending=[];for(let file of files){let head=await previewHead(file),encoding=head.includes('�')?'windows-1252':'utf-8';if(encoding!=='utf-8')head=await previewHead(file,encoding);let d=detect(head);if(/mysql/i.test(file.name)&&d.format.startsWith('mariadb-'))d.format=d.format.replace('mariadb-','mysql-');let unsupported=/\.zip$/i.test(file.name),binary=head.includes('\0');state.pending.push({file,format:d.format,confidence:d.confidence,head,encoding,fingerprint:await sampleFingerprint(file),unsupported,binary})}$('#previews').innerHTML=state.pending.map((p,i)=>`<div class="preview"><div><strong>${esc(p.file.name)}</strong><small>${(p.file.size/1024/1024).toFixed(2)} MB · ${esc(p.encoding)} · Vertrauen ${Math.round(p.confidence*100)} %</small></div>${p.unsupported||p.binary?`<p class="warning">${p.unsupported?'Komprimierte Archive werden derzeit nicht unterstützt. Bitte lokal entpacken.':'Binärinhalt erkannt; Import nicht möglich.'}</p>`:''}<label>Kodierung<select data-encoding="${i}"><option value="utf-8" ${p.encoding==='utf-8'?'selected':''}>UTF-8</option><option value="windows-1252" ${p.encoding==='windows-1252'?'selected':''}>Windows-1252</option><option value="iso-8859-1">ISO-8859-1</option></select></label><label>Format<select data-format="${i}">${formats.filter(x=>x!=='auto').map(f=>`<option value="${f}" ${f===p.format?'selected':''}>${f}</option>`).join('')}</select></label><label>Bezugsjahr (Syslog/klog)<input data-year="${i}" type="number" min="1970" max="2100" placeholder="z. B. 2026"></label><label>Zeitzonenoffset in Minuten (z. B. Berlin Winter +60)<input data-offset="${i}" type="number" min="-840" max="840" placeholder="unbekannt"></label><label>Zeitkorrektur in Sekunden<input data-shift="${i}" type="number" value="0"></label><pre>${esc(p.head.split(/\r?\n/).slice(0,3).join('\n').slice(0,600))}</pre></div>`).join('');$('#importDialog').showModal();$('#startImport').onclick=()=>{let imports=state.pending.map((p,i)=>({...p,format:$(`[data-format="${i}"]`).value,encoding:$(`[data-encoding="${i}"]`).value,year:Number($(`[data-year="${i}"]`).value)||null,offsetMinutes:$(`[data-offset="${i}"]`).value===''?null:Number($(`[data-offset="${i}"]`).value),shiftSeconds:Number($(`[data-shift="${i}"]`).value)||0}));$('#importDialog').close();for(let p of imports)if(!p.unsupported&&!p.binary)startImport(p);setView('Dateien')}}
function startImport(p){Object.assign(state,{query:'',regex:false,level:'all',source:'all',from:'',to:''});let id=crypto.randomUUID(),s={id,name:p.file.name,originalName:p.file.name,size:p.file.size,format:p.format,encoding:p.encoding,sampleFingerprint:p.fingerprint,importedAt:new Date().toISOString(),count:0,bytes:0,done:false,year:p.year,offsetMinutes:p.offsetMinutes,shiftSeconds:p.shiftSeconds};state.sources.push(s);let worker=new Worker(new URL('./worker.js',import.meta.url),{type:'module'});s.worker=worker;worker.onmessage=({data})=>{if(data.type==='batch'){if(state.events.length+data.events.length>250000){s.incomplete=true;s.done=true;s.error='Speichergrenze von 250.000 Ereignissen erreicht; Analyse unvollständig';worker.terminate()}else{state.events.push(...data.events);s.count+=data.events.length}}else if(data.type==='progress'){s.bytes=data.bytes}else if(data.type==='format')s.format=data.format;else if(data.type==='done'){s.done=true;s.bytes=data.bytes;worker.terminate()}else if(data.type==='error'){s.error=data.error;s.incomplete=true;worker.terminate()}if(state.view==='Dateien')render()};worker.postMessage({type:'import',file:p.file,sourceId:id,format:p.format,encoding:p.encoding,year:p.year,offsetMinutes:p.offsetMinutes,shiftSeconds:p.shiftSeconds,cloudWatchLogGroup:p.format==='aws-cloudwatch'?p.head.match(/"logGroupName"\s*:\s*"([^"]+)"/)?.[1]??null:null,recordArrayKey:p.format==='aws-cloudtrail'&&/"Records"\s*:\s*\[/.test(p.head)?'Records':p.format==='aws-cloudwatch'&&/"logEvents"\s*:\s*\[/.test(p.head)?'logEvents':p.format==='k8s-event-json'&&/"items"\s*:\s*\[/.test(p.head)?'items':null})}
function db(){return new Promise((resolve,reject)=>{let req=indexedDB.open('logscope',1);req.onupgradeneeded=()=>req.result.createObjectStore('projects',{keyPath:'id'});req.onsuccess=()=>resolve(req.result);req.onerror=()=>reject(req.error)})}
async function saveProject(){
  const size=new Blob([JSON.stringify(state.events)]).size;
  if(!confirm(`Projekt mit ca. ${(size/1024/1024).toFixed(1)} MB analysierten Daten lokal im Browser speichern?`))return;
  try{
    const database=await db(),transaction=database.transaction('projects','readwrite');
    transaction.objectStore('projects').put({id:'current',name:state.project,sources:state.sources.map(({worker,...source})=>source),events:state.events,investigation:state.investigation,saved:new Date().toISOString()});
    transaction.oncomplete=()=>{if($('#storageMessage'))$('#storageMessage').textContent='Projekt gespeichert.';database.close()};
    transaction.onabort=()=>{if($('#storageMessage'))$('#storageMessage').textContent='Speichern fehlgeschlagen: '+transaction.error;database.close()};
  }catch(error){if($('#storageMessage'))$('#storageMessage').textContent='Speichern fehlgeschlagen: '+error.message}
}
async function loadProject(){
  try{
    const database=await db(),transaction=database.transaction('projects'),request=transaction.objectStore('projects').get('current');
    request.onerror=()=>{if($('#storageMessage'))$('#storageMessage').textContent='Laden fehlgeschlagen: '+request.error;database.close()};
    request.onsuccess=()=>{
      database.close();
      if(!request.result){if($('#storageMessage'))$('#storageMessage').textContent='Kein gespeichertes Projekt vorhanden.';return}
      try{
        const project=request.result,events=upgradeEvents(project.events),investigation={...newInvestigation(),...project.investigation};
        compileFilter({op:'all',conditions:[{op:investigation.mode,conditions:investigation.conditions},...investigation.constraints]});
        for(const source of state.sources)source.worker?.terminate();
        resetScope();state.project=project.name;state.sources=project.sources;state.events=events;state.investigation=investigation;state.selected=null;
        render();if($('#storageMessage'))$('#storageMessage').textContent='Projekt geöffnet.';
      }catch(error){if($('#storageMessage'))$('#storageMessage').textContent='Projekt konnte nicht geoeffnet werden: '+error.message}
    };
  }catch(error){if($('#storageMessage'))$('#storageMessage').textContent='Laden fehlgeschlagen: '+error.message}
}
async function deleteProject(){if(!confirm('Gespeichertes Projekt dauerhaft aus diesem Browser löschen?'))return;let database=await db(),tx=database.transaction('projects','readwrite');tx.objectStore('projects').delete('current');tx.oncomplete=()=>{$('#storageMessage').textContent='Gespeichertes Projekt gelöscht.';database.close()}}
render();
