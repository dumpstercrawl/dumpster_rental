import { mkdir, copyFile } from 'node:fs/promises';
await mkdir('public',{recursive:true});
await copyFile('index.html','public/index.html');
