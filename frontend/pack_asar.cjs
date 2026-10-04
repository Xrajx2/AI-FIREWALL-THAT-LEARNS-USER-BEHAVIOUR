const asar = require('@electron/asar');
const src  = process.argv[2];
const dest = process.argv[3];
console.log('Packing', src, '->', dest);
asar.createPackage(src, dest).then(() => console.log('Done!')).catch(e => { console.error(e); process.exit(1); });
