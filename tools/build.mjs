import {cp,mkdir,rm,copyFile} from 'node:fs/promises';
await rm('dist',{recursive:true,force:true});
await mkdir('dist',{recursive:true});
await copyFile('index.html','dist/index.html');
await copyFile('version.json','dist/version.json');
await cp('src','dist/src',{recursive:true});
console.log('Statischer Build in dist/ erstellt.');
