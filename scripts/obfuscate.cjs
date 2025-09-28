// scripts/obfuscate.cjs
const fs = require('fs');
const path = require('path');
const obfuscator = require('javascript-obfuscator');

const srcPath = path.resolve(__dirname, '../src/worker.js'); // esbuild 输出
const outPath = path.resolve(__dirname, '../dist/worker.js');

const code = fs.readFileSync(srcPath, 'utf8');

const result = obfuscator.obfuscate(code, {
    compact: true,
    controlFlowFlattening: true,
    controlFlowFlatteningThreshold: 0.8,
    deadCodeInjection: true,
    deadCodeInjectionThreshold: 0.5,
    stringArray: true,
    stringArrayEncoding: ['base64'],
    stringArrayThreshold: 0.8,
    renameGlobals: true,
    identifierNamesGenerator: 'hexadecimal',
    numbersToExpressions: true,
    splitStrings: true,
    splitStringsChunkLength: 10,
    transformObjectKeys: true,
    selfDefending: true,
    debugProtection: true
});


// 写出混淆后的代码
fs.writeFileSync(outPath, result.getObfuscatedCode(), 'utf8');
console.log(`[obfuscate] wrote ${outPath}`);
