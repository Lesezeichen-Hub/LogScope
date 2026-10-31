// Conservative leading timestamp extraction for otherwise unknown text logs.
export function leadingTimestamp(line){
  const match=line.match(/^(\d{4}[-/]\d{2}[-/]\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)(?:\s+|\s*[-|]\s*)(.*)$/);
  if(!match)return null;
  return {raw:match[1],normalized:match[1].replaceAll('/','-').replace(',','.'),message:match[2],pattern:'leading-iso'};
}
