import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { resolve } from 'node:path';
const [baseline, candidate, tools, output] = process.argv.slice(2).map(p=>resolve(p));
const fw = await import(resolve(tools,'node_modules/@metaharness/flywheel/dist/index.js'));
const baselineSHA='f0c74aec78b0df4e4760562dfcfb12c8abc4368a';
const r=spawnSync('git',['rev-parse','HEAD'],{cwd:candidate,encoding:'utf8'});
if(r.status!==0)throw Error('Cannot resolve exact candidate');
const candidateSHA=r.stdout.trim();
const probe=resolve(candidate,'security/probe-constructor.mjs');
const observations=[],trials=[];
function run(root){
  const start=performance.now(),p=spawnSync(process.execPath,[probe,root],{encoding:'utf8',timeout:15000});
  if(p.status!==0)throw Error(p.stderr||'Probe unavailable');
  const data=JSON.parse(p.stdout);
  if(data.holdout.length!==5||data.anchor.length!==8)throw Error('Frozen suite changed');
  return {...data,ms:performance.now()-start};
}
for(let i=0;i<5;i++)for(const root of i%2?[candidate,baseline]:[baseline,candidate])trials.push({trial:i,root,...run(root)});
const parent=spawnSync('git',['show',baselineSHA+':packages/core/src/shield.ts'],{cwd:candidate,encoding:'utf8'});
if(parent.status!==0)throw Error('Parent rollback bytes unavailable');
const result=await fw.runFlywheelGenerations({
  rootPolicy:{revision:baselineSHA},mutationTargets:['revision'],maxGenerations:1,
  holdout:{id:'constructor-holdout',items:['null','false','0','empty-string','NaN']},
  anchor:{id:'constructor-anchor',items:['default','undefined','empty-array','known-scanner']},
  proposer:async()=>({value:candidateSHA,summary:'Reject explicitly malformed falsy scanner configuration',inverse:{path:'packages/core/src/shield.ts',parentBytes:parent.stdout,hash:createHash('sha256').update(parent.stdout).digest('hex')}}),
  evaluator:async(policy,suite)=>{
    const root=policy.revision===baselineSHA?baseline:candidate;
    const observed=run(root);observations.push({revision:policy.revision,suite:suite.id,...observed});
    const bits=suite.id==='constructor-holdout'?observed.holdout:observed.anchor;
    return {primary:bits.filter(Boolean).length/bits.length,noopRate:0,costPerWin:0,
      // Full acceptance is unknown/red: coverage, security, full workspace and real Ruflo execution.
      // Fail closed rather than promoting a component-only result.
      regressed:true};
  },signer:fw.makeSigner(),promotionRule:fw.meetsPromotionRule,dataSource:'LIVE',now:g=>`2026-11-03-evening-generation-${g}`
});
const replay=fw.verifyReplayBundle(result.replayBundle,{pinnedGateFingerprint:fw.gateFingerprint(fw.meetsPromotionRule),promotionRule:fw.meetsPromotionRule});
const benchmark=Object.fromEntries([baseline,candidate].map(root=>{const rows=trials.filter(x=>x.root===root);return[root,{medianMs:rows.map(x=>x.ms).sort((a,b)=>a-b)[2],holdouts:rows.flatMap(x=>x.holdout).filter(Boolean).length,anchors:rows.flatMap(x=>x.anchor).filter(Boolean).length}]}));
writeFileSync(output,JSON.stringify({scope:'Actual built wrapper, not Rust/WASM detection efficacy. Full acceptance fail-closed. Cost axes neutral, unmeasured; no speedup claim.',baselineSHA,candidateSHA,observations,trials,benchmark,replay,bundle:result.replayBundle},null,2)+'\n');
console.log(JSON.stringify({benchmark,replay,verifiedImprovements:result.replayBundle.verified_improvements}));
if(!replay.pass)process.exitCode=1;
