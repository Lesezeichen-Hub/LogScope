// Extract JSON objects from a named top-level array without loading the document.
export class JsonRecordStream {
  constructor(key,onRecord){this.key=key;this.onRecord=onRecord;this.seek='';this.found=false;this.closed=false;this.line=1;this.start=1;this.depth=0;this.quoted=false;this.escaped=false;this.record=''}
  feed(text){
    if(this.closed)return;
    if(!this.found){
      this.seek+=text;
      if(this.seek.length>1_000_000)throw Error(`JSON-Feld ${this.key} nicht im ersten MB gefunden`);
      const pattern=new RegExp('"'+this.key+'"\\s*:\\s*\\['),match=pattern.exec(this.seek);
      if(!match)return;
      const before=this.seek.slice(0,match.index+match[0].length);
      this.line+=(before.match(/\n/g)||[]).length;
      text=this.seek.slice(match.index+match[0].length);
      this.seek='';this.found=true;
    }
    for(const c of text){
      if(c==='\n')this.line++;
      if(this.depth===0){
        if(c===']'){this.closed=true;break}
        if(c==='{'){this.depth=1;this.record='{';this.start=this.line}
        continue;
      }
      this.record+=c;
      if(this.record.length>2_000_000)throw Error('JSON-Eintrag überschreitet 2 MB');
      if(this.escaped){this.escaped=false;continue}
      if(c==='\\'&&this.quoted){this.escaped=true;continue}
      if(c==='"'){this.quoted=!this.quoted;continue}
      if(!this.quoted){
        if(c==='{')this.depth++;
        else if(c==='}'){
          this.depth--;
          if(this.depth===0){this.onRecord(this.record,this.start,this.line);this.record=''}
        }
      }
    }
  }
  finish(){if(!this.found||!this.closed||this.depth!==0)throw Error(`JSON-Array ${this.key} unvollständig`)}
}
