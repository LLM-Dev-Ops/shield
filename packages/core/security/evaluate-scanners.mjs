import {execFileSync,spawnSync} from 'node:child_process';
import {readFileSync,writeFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import path from 'node:path';
const [root,parent,head,tools,out]=process.argv.slice(2);
if(![root,parent,head,tools,out].every(Boolean))throw Error('root parent head tools output required');
const fw=await import(path.join(tools,'node_modules/@metaharness/flywheel/dist/index.js'));
const git=(...a)=>execFileSync('git',a,{cwd:root,encoding:'utf8'}).trim();
for(const file of ['packages/core/package-lock.json','packages/core/security/probe-scanners.mjs','packages/core/tests/unit/scanner-validation.test.ts']){
 if(git('show',parent+':'+file)!==git('show',head+':'+file))throw Error('fixture/resolution changed: '+file);
}
const probe=git('show',head+':packages/core/security/probe-scanners.mjs');
const inverse=git('show',parent+':packages/core/src/shield.ts');
const core=path.join(root,'packages/core');
const env={...process.env,CARGO_TARGET_DIR:'/tmp/shield-oct29b-target',CARGO_INCREMENTAL:'0',CARGO_PROFILE_DEV_DEBUG:'0',CARGO_PROFILE_TEST_DEBUG:'0'};
const run=(c,a,s,cwd=core)=>{const r=spawnSync('timeout',['--kill-after=5',String(s),c,...a],{cwd,env,encoding:'utf8',timeout:(s+10)*1000,maxBuffer:3000000});return{exit:r.status,output:(r.stdout||'')+(r.stderr||'')};};
const measurements={};
const evaluator=async(policy,suite)=>{
 if(![parent,head].includes(policy.revision))throw Error('unexpected revision');
 if(!measurements[policy.revision]){
  git('switch','--detach',policy.revision);
  const start=performance.now();
  const build=run('npm',['run','build:rollup'],60),types=run('npm',['run','build:types'],60);
  if(build.exit!==0||types.exit!==0)throw Error('built wrapper unavailable');
  const p=run('node',['--input-type=module','-e',probe,'probe',core],20);
  if(p.exit!==0)throw Error('probe failed: '+p.output);
  const observed=JSON.parse(p.output);
  const unit=run('npm',['run','test:unit'],60),integration=run('npm',['run','test:integration'],60);
  const lint=run('npm',['run','lint'],30),typecheck=run('npm',['run','typecheck'],30);
  const coverage=run('npm',['run','test:coverage'],60),audit=run('npm',['audit','--json'],30),prodAudit=run('npm',['audit','--omit=dev','--json'],30);
  const rust=run('cargo',['test','--locked','--offline','-p','llm-shield-core','-j','2'],120,root);
  measurements[policy.revision]={...observed,build,types,unit,integration,lint,typecheck,coverage,audit,prodAudit,rust,elapsedSeconds:(performance.now()-start)/1000};
  writeFileSync(out+'.checkpoint',JSON.stringify(measurements,null,2)+'\n');
 }
 const m=measurements[policy.revision],items=suite.id==='anchors'?m.anchors:m.holdout,wins=items.filter(Boolean).length;
 return{primary:wins/items.length,noopRate:1-wins/items.length,costPerWin:m.elapsedSeconds/Math.max(1,wins),itemWins:items,
 regressed:!m.anchors.every(Boolean)||['build','types','unit','integration','lint','typecheck','coverage','audit','prodAudit','rust'].some(k=>m[k].exit!==0)};
};
try{
 const r=await fw.runFlywheelGenerations({rootPolicy:{revision:parent},proposer:async()=>({value:head,summary:'Fail closed on invalid runtime scanner selection',inverse:{path:'packages/core/src/shield.ts',parentBytes:inverse,hash:createHash('sha256').update(inverse).digest('hex')}}),
 evaluator,promotionRule:fw.meetsPromotionRule,holdout:{id:'holdouts',items:[0,1,2,3,4,5]},anchor:{id:'anchors',items:[0,1,2,3,4,5]},mutationTargets:['revision'],maxGenerations:1,signer:fw.makeSigner(),dataSource:'LIVE'});
 const replay=fw.verifyReplayBundle(r.replayBundle,{pinnedGateFingerprint:fw.gateFingerprint(fw.meetsPromotionRule)});
 writeFileSync(out,JSON.stringify({parent,head,measurements,finalPolicy:r.finalPolicy,replay,replayBundle:r.replayBundle},null,2)+'\n');
 console.log(JSON.stringify({replay:replay.pass,verdict:r.replayBundle.all_commits.map(c=>({verdict:c.verdict,reasons:c.failureReasons}))}));
}finally{git('switch','--detach',head);}
