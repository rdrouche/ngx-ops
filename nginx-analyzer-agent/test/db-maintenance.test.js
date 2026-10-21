'use strict';
const assert=require('assert'), fs=require('fs'), os=require('os'), path=require('path');
const { Store }=require('../lib/store');
const dm=require('../lib/db-maintenance');
let pass=0,fail=0;
const check=(n,f)=>{try{f();console.log('  PASS  '+n);pass++}catch(e){console.log('  FAIL  '+n+'\n        '+e.message);fail++}};

console.log('\nmaintenance SQLite');
const tmp=fs.mkdtempSync(path.join(os.tmpdir(),'dbm-'));
const s=new Store(path.join(tmp,'s.db'));
check('nouvelle base en auto_vacuum incremental', ()=>assert.strictEqual(dm.freeStats(s.db).autoVacuum,2));
s.db.exec('CREATE TABLE junk(x TEXT)');
const ins=s.db.prepare('INSERT INTO junk VALUES (?)');
s.db.exec('BEGIN'); for(let i=0;i<20000;i++) ins.run('x'.repeat(500)+i); s.db.exec('COMMIT');
s.db.exec('DELETE FROM junk');
check('apres DELETE : pages libres', ()=>assert.ok(dm.freeStats(s.db).freePct>50));
check('off : ne fait rien', ()=>assert.strictEqual(dm.compactIfNeeded(s.db,{mode:'off',log(){}}).ran,false));
check('seuil non atteint : ne fait rien', ()=>assert.strictEqual(dm.compactIfNeeded(s.db,{minFreeMb:9999,log(){}}).ran,false));
check('maintain (incremental_vacuum) reduit les pages libres', ()=>{
  const b=dm.freeStats(s.db).freePages; dm.maintain(s.db,{pages:100000});
  assert.ok(dm.freeStats(s.db).freePages<b);
});
s.db.exec('BEGIN'); for(let i=0;i<20000;i++) ins.run('y'.repeat(500)+i); s.db.exec('COMMIT');
s.db.exec('DELETE FROM junk');
check('auto : VACUUM et fichier reduit', ()=>{
  const r=s.compactOnStart({mode:'auto',minFreeMb:1,minFreePct:10});
  assert.strictEqual(r.ran,true); assert.ok(r.after.sizeBytes<r.before.sizeBytes);
  assert.strictEqual(dm.freeStats(s.db).freePages,0);
});
check('always force', ()=>assert.strictEqual(s.compactOnStart({mode:'always'}).ran,true));
s.close();

console.log('\nbaseline donnees (octets)');
const { Baseline }=require('../lib/baseline');
check('pic de volume detecte sur un vhost, plancher en octets', ()=>{
  const b=new Baseline({learningDays:0,sigmaThreshold:6,minAbsoluteRequests:50*1048576});
  const base=Date.parse('2026-08-03T10:00:00Z');
  for(let w=0;w<5;w++){ const h=base+w*7*86400000; b.observe('v',h,{requests:100*1048576+w*1000,errors:0,distinctIps:5,distinctPaths:5}); }
  const r=b.check('v',base+5*7*86400000,{requests:5000*1048576,errors:0,distinctIps:5,distinctPaths:5});
  assert.ok(r&&r.anomaly);
  assert.strictEqual(b.check('v',base+5*7*86400000,{requests:10*1048576,errors:0,distinctIps:5,distinctPaths:5}),null);
});
console.log('\nhourlyBytes (amorcage baseline data)');
check('octets agreges par heure et vhost (minute + hour)', ()=>{
  const st=new Store(path.join(tmp,'h.db'));
  st.db.exec("INSERT INTO traffic (bucket,grain,vhost,country,status,method,requests,bytes) VALUES (7200,'minute','a','FR',2,'GET',1,100),(7260,'minute','a','FR',2,'GET',1,50),(3600,'hour','a','FR',2,'GET',5,1000),(7200,'minute','b','FR',2,'GET',1,7)");
  const m={}; for(const r of st.hourlyBytes(0,1e10)) m[r.vhost+'@'+r.hourMs/3600000]=r.bytes;
  assert.deepStrictEqual(m,{'a@2':150,'a@1':1000,'b@2':7});
  st.close();
});
console.log(`\n${pass} ok, ${fail} ko`); process.exit(fail?1:0);
