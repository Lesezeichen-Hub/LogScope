import {fieldCatalog,operators,aggregateEvents,analysisPresets} from './query.js';

const escape=value=>String(value??'').replace(/[&<>"']/g,character=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[character]));
const operatorNames={eq:'ist',exact:'ist (exakt)',neq:'ist nicht',contains:'enthält',notContains:'enthält nicht',startsWith:'beginnt mit',gt:'größer als',gte:'mindestens',lt:'kleiner als',lte:'höchstens',exists:'vorhanden',missing:'fehlt'};
const metricNames={count:'Anzahl',sum:'Summe',average:'Mittelwert',min:'Minimum',max:'Maximum'};
const number=value=>value===null?'—':Number(value).toLocaleString('de-DE',{maximumFractionDigits:2});

export function newInvestigation(){
  return {mode:'all',conditions:[],constraints:[],sources:[],group:{dimensions:['product'],metric:'count',field:'durationMs'},saved:[]};
}

function options(items,value){return items.map(([key,label])=>`<option value="${escape(key)}" ${key===value?'selected':''}>${escape(label)}</option>`).join('')}
function fieldOptions(value,numeric=false){return options(fieldCatalog.filter(field=>!numeric||field.type==='number').map(field=>[field.key,field.label]),value)}

export function renderInvestigationTools(analysis,events,sources){
  const rows=analysis.conditions.map((condition,index)=>{
    const definition=fieldCatalog.find(field=>field.key===condition.field)||fieldCatalog[0];
    return `<div class="condition-row" data-condition="${index}"><select data-condition-field aria-label="Filterfeld ${index+1}">${fieldOptions(condition.field)}</select><select data-condition-op aria-label="Vergleich ${index+1}">${options(operators[definition.type].map(operator=>[operator,operatorNames[operator]]),condition.op)}</select><input data-condition-value aria-label="Filterwert ${index+1}" type="${definition.type==='number'?'number':definition.type==='time'?'datetime-local':'text'}" ${definition.type==='number'?'step="any"':''} value="${escape(definition.type==='time'?String(condition.value??'').replace(/Z$/,''):condition.value??'')}" ${['exists','missing'].includes(condition.op)?'disabled':''}><button type="button" data-condition-remove="${index}" title="Bedingung entfernen" aria-label="Bedingung ${index+1} entfernen">×</button></div>`;
  }).join('');
  const sourceChoices=sources.map(source=>`<label class="source-choice"><input type="checkbox" data-analysis-source="${escape(source.id)}" ${analysis.sources.includes(source.id)?'checked':''}><span>${escape(source.name)}</span></label>`).join('');
  let groups;
  try{
    const result=aggregateEvents(events,analysis.group);
    groups=`<p class="muted">${number(result.total)} Ereignisse · ${number(result.groupCount)} Gruppen${result.groupCount>result.rows.length?` · erste ${result.rows.length}`:''}</p><div class="table-wrap"><table><thead><tr>${analysis.group.dimensions.map(key=>`<th>${escape(fieldCatalog.find(field=>field.key===key)?.label)}</th>`).join('')}<th>${metricNames[analysis.group.metric]}${analysis.group.metric!=='count'?' · '+escape(fieldCatalog.find(field=>field.key===analysis.group.field)?.label):''}</th><th>Ereignisse</th><th>Messwerte</th><th></th></tr></thead><tbody>${result.rows.map((group,index)=>`<tr>${group.values.map(value=>`<td class="group-value">${escape(value??'—')}</td>`).join('')}<td>${number(group.value)}</td><td>${number(group.count)}</td><td>${analysis.group.metric==='count'?'—':number(group.measured)}</td><td><button type="button" data-group-open="${index}" aria-label="Ereignisse dieser Gruppe oeffnen" title="Ereignisse dieser Gruppe oeffnen">↗</button></td></tr>`).join('')}</tbody></table></div>`;
  }catch(error){groups=`<p class="warning" role="alert">${escape(error.message)}</p>`}
  return `<section class="investigation"><div class="section-head"><h2>Feldbedingungen</h2><button type="button" id="addCondition" title="Bedingung hinzufuegen" aria-label="Bedingung hinzufuegen">+</button></div><div class="analysis-presets"><label>Analysevorlage<select id="analysisPreset"><option value="">Auswaehlen</option>${analysisPresets.map(preset=>`<option value="${preset.id}">${escape(preset.label)}</option>`).join('')}</select></label><label>Verknuepfung<select id="conditionMode">${options([['all','Alle Bedingungen (UND)'],['any','Mindestens eine (ODER)']],analysis.mode)}</select></label></div><fieldset class="source-choices"><legend>Quellenmehrfachauswahl</legend>${sourceChoices||'<span class="muted">Keine Quellen</span>'}</fieldset><div id="conditionRows">${rows||'<p class="muted">Keine zusaetzlichen Feldbedingungen.</p>'}</div><p id="conditionError" class="warning" role="alert"></p><div class="dialog-actions"><button type="button" id="clearConditions">Feldfilter zuruecksetzen</button><button type="button" id="applyConditions" class="primary">Feldfilter anwenden</button></div><div class="saved-analyses"><label>Gespeicherte Auswertung<select id="savedAnalysis"><option value="">Auswaehlen</option>${analysis.saved.map((entry,index)=>`<option value="${index}">${escape(entry.name)}</option>`).join('')}</select></label><input id="analysisName" aria-label="Name der Auswertung" placeholder="Name"><button type="button" id="saveAnalysis">Auswertung merken</button><button type="button" id="deleteAnalysis" title="Auswertung entfernen" aria-label="Auswertung entfernen">×</button></div></section><section><h2>Gruppierte Auswertung</h2><div class="group-controls">${[0,1,2].map(index=>`<label>Gruppierung ${index+1}<select data-group-dimension="${index}">${index?'<option value="">Keine</option>':''}${fieldOptions(analysis.group.dimensions[index])}</select></label>`).join('')}<label>Kennzahl<select id="groupMetric">${options(Object.entries(metricNames),analysis.group.metric)}</select></label><label>Messfeld<select id="groupField" ${analysis.group.metric==='count'?'disabled':''}>${fieldOptions(analysis.group.field,true)}</select></label><button type="button" id="applyGrouping">Auswerten</button></div><div id="groupResults">${groups}</div></section>`;
}

export function bindInvestigationTools(root,analysis,events,{apply,drill}){
  const select=selector=>root.querySelector(selector);
  if(!select('#addCondition'))return;
  const collect=()=>({...analysis,mode:select('#conditionMode').value,sources:[...root.querySelectorAll('[data-analysis-source]:checked')].map(input=>input.dataset.analysisSource),conditions:[...root.querySelectorAll('[data-condition]')].map(row=>{
    const field=row.querySelector('[data-condition-field]').value;
    let value=row.querySelector('[data-condition-value]').value;
    if(field==='timestampUtc'&&value)value+='Z';
    return {field,op:row.querySelector('[data-condition-op]').value,value};
  })});
  const attempt=next=>{try{apply(next)}catch(error){select('#conditionError').textContent=error.message}};
  select('#addCondition').onclick=()=>attempt({...collect(),conditions:[...collect().conditions,{field:'host',op:'exists',value:''}]});
  root.querySelectorAll('[data-condition-remove]').forEach(button=>button.onclick=()=>attempt({...collect(),conditions:collect().conditions.filter((condition,index)=>index!==Number(button.dataset.conditionRemove))}));
  root.querySelectorAll('[data-condition-field]').forEach(input=>input.onchange=()=>{
    const next=collect(),index=Number(input.closest('[data-condition]').dataset.condition);
    next.conditions[index]={field:input.value,op:'exists',value:''};attempt(next);
  });
  root.querySelectorAll('[data-condition-op]').forEach(input=>input.onchange=()=>{
    const row=input.closest('[data-condition]');
    row.querySelector('[data-condition-value]').disabled=['exists','missing'].includes(input.value);
  });
  select('#applyConditions').onclick=()=>attempt(collect());
  select('#clearConditions').onclick=()=>apply({...analysis,conditions:[],constraints:[],sources:[],mode:'all'});
  select('#analysisPreset').onchange=event=>{
    const preset=analysisPresets.find(item=>item.id===event.target.value);
    if(preset)attempt({...analysis,conditions:structuredClone(preset.conditions),constraints:[],mode:'all'});
  };
  select('#applyGrouping').onclick=()=>{
    const dimensions=[...root.querySelectorAll('[data-group-dimension]')].map(input=>input.value).filter(Boolean);
    attempt({...collect(),group:{dimensions:[...new Set(dimensions)],metric:select('#groupMetric').value,field:select('#groupField').value}});
  };
  select('#groupMetric').onchange=event=>select('#groupField').disabled=event.target.value==='count';
  select('#saveAnalysis').onclick=()=>{
    const name=select('#analysisName').value.trim();
    if(!name){select('#conditionError').textContent='Bitte einen Namen eingeben.';return}
    const next=collect();
    const {saved,...definition}=next;
    attempt({...next,saved:[...saved.filter(entry=>entry.name!==name),{name,definition:structuredClone(definition)}].slice(-50)});
  };
  select('#savedAnalysis').onchange=event=>{
    const index=event.target.value,entry=analysis.saved[Number(index)];
    if(index!==''&&entry){attempt({...structuredClone(entry.definition),saved:analysis.saved});select('#savedAnalysis').value=index;select('#analysisName').value=entry.name}
  };
  select('#deleteAnalysis').onclick=()=>{
    const value=select('#savedAnalysis').value;
    if(value!=='')attempt({...analysis,saved:analysis.saved.filter((entry,index)=>index!==Number(value))});
  };
  if(root.querySelector('[data-group-open]')){
    const result=aggregateEvents(events,analysis.group);
    root.querySelectorAll('[data-group-open]').forEach(button=>button.onclick=()=>{
      const group=result.rows[Number(button.dataset.groupOpen)];
      drill(analysis.group.dimensions.map((field,index)=>({field,op:group.values[index]===null?'missing':'eq',value:group.values[index]})));
    });
  }
}

function ranking(events,field,label){
  let result;
  try{result=aggregateEvents(events,{dimensions:[field],limit:15})}
  catch(error){return `<section><h2>${escape(label)}</h2><p class="warning">${escape(error.message)}</p></section>`}
  return `<section><h2>${escape(label)}</h2><div class="table-wrap"><table><thead><tr><th>${escape(fieldCatalog.find(item=>item.key===field)?.label)}</th><th>Anzahl</th></tr></thead><tbody>${result.rows.map(row=>`<tr><td><button class="domain-drill" data-domain-field="${escape(field)}" ${row.values[0]===null?'data-domain-missing="true"':`data-domain-value="${escape(row.values[0])}"`}>${escape(row.values[0]??'Nicht erfasst')}</button></td><td>${number(row.count)}</td></tr>`).join('')}</tbody></table></div></section>`;
}

export function renderDomainView(events,domain){
  const scope=events.filter(event=>event.normalized?.domain===domain);
  const database=domain==='database',measured=scope.filter(event=>event.normalized.durationMs!==null);
  const metric=(label,value)=>`<div class="stat"><div>${escape(label)}</div><strong>${number(value)}</strong></div>`;
  const counts=database?
    metric('DB-Ereignisse',scope.length)+metric('Mit Laufzeit',measured.length)+metric('Ab 1 Sekunde',measured.filter(event=>event.normalized.durationMs>=1000).length)+metric('Fehler',scope.filter(event=>event.severity==='error').length):
    metric('Systemereignisse',scope.length)+metric('Fehlgeschlagene Anmeldungen',scope.filter(event=>event.normalized.eventType==='login'&&event.normalized.outcome==='failure').length)+metric('sudo',scope.filter(event=>event.normalized.eventType==='sudo').length)+metric('OOM-Meldungen',scope.filter(event=>event.normalized.eventType==='oom').length);
  return `<div class="stats">${counts}</div>${!scope.length?'<p class="empty">Keine passenden Ereignisse im aktuellen Filterbereich.</p>':''}<div class="domain-columns">${database?ranking(scope,'product','Datenbanksysteme')+ranking(scope,'database','Datenbanken und Namespaces')+ranking(scope,'diagnosticCode','Diagnosecodes')+ranking(scope,'queryPattern','Abfragemuster'):ranking(scope,'host','Betroffene Hosts')+ranking(scope,'eventType','System- und Sicherheitsereignisse')+ranking(scope,'user','Benutzer')+ranking(scope,'clientIp','Client-Adressen')}</div><p class="muted">${database?'Laufzeiten, Diagnosecodes und Abfragemuster stammen nur aus protokollierten Feldern. Fehlende Messwerte bleiben unbekannt.':'Klassifizierungen beruhen auf erkannten Meldungsmustern. Nicht klassifizierte Ereignisse bleiben in den Originaldaten erhalten.'} Historische Meldungen belegen keinen aktuellen Systemzustand.</p>`;
}

export function describeCondition(condition){
  if(condition.op==='all'||condition.op==='any')return '('+condition.conditions.map(describeCondition).join(condition.op==='all'?' UND ':' ODER ')+')';
  if(condition.op==='not')return 'NICHT '+describeCondition(condition.condition);
  return `${fieldCatalog.find(field=>field.key===condition.field)?.label||condition.field} ${operatorNames[condition.op]||condition.op}${['exists','missing'].includes(condition.op)?'':' '+String(condition.value??'')}`;
}