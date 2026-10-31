export const fieldCatalog=[
  ['timestampUtc','Zeit UTC','time'],['sourceId','Quelle','text'],['host','Host','text'],
  ['service','Dienst','text'],['process','Prozess','text'],['severity','Schweregrad','text'],
  ['category','Kategorie','text'],['parserId','Format','text'],['message','Nachricht','text'],['fingerprint','Fehlermuster','text'],
  ['domain','Bereich','text'],['product','Produkt','text'],['eventType','Ereignistyp','text'],
  ['user','Benutzer','text'],['clientIp','Client-IP','text'],['outcome','Ergebnis','text'],
  ['database','Datenbank / Namespace','text'],['instance','Instanz / Kontext','text'],
  ['operation','Operation','text'],['durationMs','Dauer (ms)','number'],
  ['lockMs','Lock-Zeit (ms)','number'],['rowsExamined','Untersuchte Zeilen / Dokumente','number'],
  ['status','HTTP-Status','number'],['method','HTTP-Methode','text'],['path','Request-Pfad','text'],
  ['httpHost','HTTP-Host','text'],['userAgent','User Agent','text'],['referrer','Referrer-Domain','text'],['protocol','Protokoll','text'],
  ['bytes','Bytes','number'],['diagnosticCode','Diagnosecode','text'],['queryPattern','Abfragemuster','text']
].map(([key,label,type])=>({key,label,type}));

const definitions=new Map(fieldCatalog.map(field=>[field.key,field]));
export const operators={text:['eq','exact','neq','contains','notContains','startsWith','exists','missing'],number:['eq','neq','gt','gte','lt','lte','exists','missing'],time:['eq','gt','gte','lt','lte','exists','missing']};

export function fieldValue(event,key){
  if(definitions.has(key))return Object.hasOwn(event.normalized||{},key)?event.normalized[key]:event[key];
  if(!key.startsWith('fields.'))return undefined;
  let value=event.fields;
  for(const part of key.slice(7).split('.')){
    if(['__proto__','prototype','constructor'].includes(part)||!value||!Object.hasOwn(value,part))return undefined;
    value=value[part];
  }
  return value;
}

function typedValue(value,type){
  if(value===null||value===undefined||typeof value==='string'&&!value.trim())return null;
  if(type==='number'){
    if(typeof value==='boolean'||typeof value==='object')return null;
    const number=Number(value);
    return Number.isFinite(number)?number:null;
  }
  if(type==='time'){
    const number=Date.parse(String(value));
    return Number.isFinite(number)?number:null;
  }
  return typeof value==='object'?null:String(value).toLocaleLowerCase('de-DE');
}

export function compileFilter(filter){
  let conditions=0;
  function compile(node,depth=0){
    if(depth>8||++conditions>100)throw Error('Zu viele Filterbedingungen');
    if(!node||typeof node!=='object')throw Error('Filter fehlt');
    if(node.op==='all'||node.op==='any'){
      if(!Array.isArray(node.conditions))throw Error('Filtergruppe ist unvollstaendig');
      const children=node.conditions.map(child=>compile(child,depth+1));
      return event=>node.op==='all'?children.every(match=>match(event)):children.some(match=>match(event));
    }
    if(node.op==='not'){
      const child=compile(node.condition,depth+1);
      return event=>!child(event);
    }
    const definition=definitions.get(node.field);
    if(!definition&&!/^fields\.[A-Za-z0-9_.-]+$/.test(node.field||''))throw Error('Unbekanntes Filterfeld');
    const type=definition?.type||node.type||'text';
    if(!operators[type]?.includes(node.op))throw Error('Operator passt nicht zum Feldtyp');
    const expected=typedValue(node.value,type);
    if(!['exists','missing'].includes(node.op)&&expected===null)throw Error('Filterwert fehlt oder ist ungueltig');
    return event=>{
      const value=typedValue(fieldValue(event,node.field),type);
      if(node.op==='exists')return value!==null;
      if(node.op==='missing')return value===null;
      if(value===null)return false;
      if(node.op==='exact')return String(fieldValue(event,node.field))===String(node.value);
      switch(node.op){
        case 'eq':return value===expected;
        case 'neq':return value!==expected;
        case 'contains':return value.includes(expected);
        case 'notContains':return !value.includes(expected);
        case 'startsWith':return value.startsWith(expected);
        case 'gt':return value>expected;
        case 'gte':return value>=expected;
        case 'lt':return value<expected;
        case 'lte':return value<=expected;
        default:return false;
      }
    };
  }
  return compile(filter||{op:'all',conditions:[]});
}

export function aggregateEvents(events,{dimensions=['product'],metric='count',field='durationMs',limit=100,maxGroups=20000}={}){
  if(!Array.isArray(dimensions)||dimensions.length<1||dimensions.length>3||dimensions.some(key=>!definitions.has(key)))throw Error('Eine bis drei bekannte Gruppierungen waehlen');
  if(!['count','sum','average','min','max'].includes(metric))throw Error('Unbekannte Kennzahl');
  if(metric!=='count'&&definitions.get(field)?.type!=='number')throw Error('Kennzahl benoetigt ein Zahlenfeld');
  const groups=new Map();
  let total=0;
  for(const event of events){
    const values=dimensions.map(key=>{
      const value=fieldValue(event,key);
      return typedValue(value,definitions.get(key).type)===null?null:value;
    }),key=JSON.stringify(values.map((value,index)=>typedValue(value,definitions.get(dimensions[index]).type)));
    let group=groups.get(key);
    if(!group){
      if(groups.size>=maxGroups)throw Error('Zu viele Gruppen. Zeitraum oder Filter eingrenzen.');
      group={values,count:0,measured:0,sum:0,min:null,max:null};groups.set(key,group);
    }
    group.count++;total++;
    if(metric!=='count'){
      const value=typedValue(fieldValue(event,field),'number');
      if(value!==null){group.measured++;group.sum+=value;group.min=group.min===null?value:Math.min(group.min,value);group.max=group.max===null?value:Math.max(group.max,value)}
    }
  }
  const rows=[...groups.values()].map(group=>({...group,value:metric==='count'?group.count:!group.measured?null:metric==='average'?group.sum/group.measured:group[metric]}));
  rows.sort((left,right)=>(right.value??-Infinity)-(left.value??-Infinity)||JSON.stringify(left.values).localeCompare(JSON.stringify(right.values)));
  return {total,groupCount:rows.length,rows:rows.slice(0,Math.max(1,Math.min(500,limit)))};
}

export const analysisPresets=[
  {id:'ssh-failures',label:'Fehlgeschlagene Anmeldungen',conditions:[{field:'domain',op:'eq',value:'system'},{field:'eventType',op:'eq',value:'login'},{field:'outcome',op:'eq',value:'failure'}]},
  {id:'sudo',label:'sudo-Ereignisse',conditions:[{field:'eventType',op:'eq',value:'sudo'}]},
  {id:'oom',label:'Speicher / OOM',conditions:[{field:'eventType',op:'eq',value:'oom'}]},
  {id:'services',label:'Fehlgeschlagene Dienste',conditions:[{field:'eventType',op:'eq',value:'service'},{field:'outcome',op:'eq',value:'failure'}]},
  {id:'http-errors',label:'HTTP 4xx / 5xx',conditions:[{field:'domain',op:'eq',value:'web'},{field:'status',op:'gte',value:400},{field:'status',op:'lt',value:600}]},
  {id:'slow-database',label:'DB-Operationen ab 1 Sekunde',conditions:[{field:'domain',op:'eq',value:'database'},{field:'durationMs',op:'gte',value:1000}]},
  {id:'locks',label:'DB Lock-Meldungen',conditions:[{field:'domain',op:'eq',value:'database'},{field:'eventType',op:'eq',value:'lock'}]},
  {id:'replication',label:'DB Replikationsmeldungen',conditions:[{field:'domain',op:'eq',value:'database'},{field:'eventType',op:'eq',value:'replication'}]}
];