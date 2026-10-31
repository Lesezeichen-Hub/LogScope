export function summarizeTimeRanges(events,sources=[]){
  const bySource=new Map(sources.map(s=>[s.id,{id:s.id,name:s.name,first:null,last:null,dated:0,undated:0}]));
  const years=new Map();let first=null,last=null,dated=0,undated=0;
  for(const event of events){
    let source=bySource.get(event.sourceId);
    if(!source){source={id:event.sourceId,name:event.sourceId,first:null,last:null,dated:0,undated:0};bySource.set(event.sourceId,source)}
    const stamp=event.timestampUtc;
    if(!stamp||!Number.isFinite(Date.parse(stamp))){undated++;source.undated++;continue}
    dated++;source.dated++;
    if(!first||stamp<first)first=stamp;
    if(!last||stamp>last)last=stamp;
    if(!source.first||stamp<source.first)source.first=stamp;
    if(!source.last||stamp>source.last)source.last=stamp;
    const year=stamp.slice(0,4);years.set(year,(years.get(year)||0)+1);
  }
  return {first,last,dated,undated,years:[...years].sort((a,b)=>a[0].localeCompare(b[0])),sources:[...bySource.values()]};
}
export function eventsForYear(events,year){return events.filter(e=>e.timestampUtc&&(year==='all'||e.timestampUtc.startsWith(year+'-')))}
