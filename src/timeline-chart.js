// Aggregate dated events without dropping intervals when a chart is narrowed to 160 bars.
export function timelineBars(events,interval=60000,maxBars=160){
  const bins=new Map();
  for(const event of events){
    if(!event.timestampUtc)continue;
    const stamp=Date.parse(event.timestampUtc);
    if(!Number.isFinite(stamp))continue;
    const start=Math.floor(stamp/interval)*interval;
    let bin=bins.get(start);
    if(!bin){bin={start,end:start+interval,all:0,error:0,warn:0};bins.set(start,bin)}
    bin.all++;
    if(event.severity==='error')bin.error++;
    if(event.severity==='warn')bin.warn++;
  }
  const rows=[...bins.values()].sort((a,b)=>a.start-b.start);
  if(rows.length<=maxBars)return {bars:rows,intervals:rows.length,compressed:false};
  const stride=Math.ceil(rows.length/maxBars),bars=[];
  for(let i=0;i<rows.length;i+=stride){
    const group=rows.slice(i,i+stride),last=group.at(-1);
    bars.push({start:group[0].start,end:last.end,all:group.reduce((sum,row)=>sum+row.all,0),error:group.reduce((sum,row)=>sum+row.error,0),warn:group.reduce((sum,row)=>sum+row.warn,0)});
  }
  return {bars,intervals:rows.length,compressed:true};
}
