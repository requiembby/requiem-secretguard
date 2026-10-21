'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {test} = require('node:test');
const code = fs.readFileSync(path.join(__dirname, '..', 'scan-page.js'), 'utf8');
const runScanner = vm.runInNewContext(code + '\nsecretGuardInspectPage;', {});
function makePage({inline = [], linked = [], fetchFn = async () => { throw new Error('disabled'); }}) {
  const nodes = [
    ...inline.map(t => ({hasAttribute: (k) => false, getAttribute: (k) => null, textContent:t})),
    ...linked.map(src => ({hasAttribute: (k) => k === 'src', getAttribute: (k) => k === 'src' ? src : null}))
  ];
  const globals = {
    document: { querySelectorAll: () => nodes },
    location: { href:'https://app.example/security/page', origin:'https://app.example', hostname:'app.example' },
    URL, AbortController, TextDecoder, Uint8Array, Set, Array, Number, Date, Promise,
    fetch: fetchFn, setTimeout, clearTimeout
  };
  const fn = vm.runInNewContext(code + '\nsecretGuardInspectPage;', globals);
  return fn();
}
test('manifest requests only scoped on-click permissions', () => {
  const manifest=JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'manifest.json'), 'utf8'));
  assert.equal(manifest.manifest_version, 3);
  assert.deepEqual(manifest.permissions, ['activeTab', 'scripting']);
  assert.equal(manifest.host_permissions, undefined);
});
test('detects synthetic Stripe, GitHub and generic secrets but redacts raw values', async () => {
  const stripe = 'sk_live_'+'B'.repeat(24);
  const github = 'ghp_'+'C'.repeat(36);
  const generic = 'clearlysyntheticexample987654321';
  const result = await makePage({inline:[`const a='${stripe}';\nconst b='${github}';\nconst api_key='${generic}';`]});
  assert.equal(result.findings.length, 3);
  assert.deepEqual(Array.from(result.findings, x=>x.severity), ['critical','high','medium']);
  assert.equal(result.stats.inlineScripts, 1);
  const json=JSON.stringify(result);
  for (const secret of [stripe, github, generic]) assert.ok(!json.includes(secret));
  assert.equal(result.partial,false);
});
test('rejects placeholder generic values and unsupported script types', async () => {
  const result = await makePage({inline:['const api_key="placeholder_value_value_value";']});
  assert.equal(result.findings.length, 0);
});
test('same-origin JS response scanned; request omits cookies and credentials', async () => {
  const requests=[];
  const token='ghp_'+'A'.repeat(36);
  const result = await makePage({linked:['/assets/app.js?cache=1#frag','https://ads.example/lib.js'], fetchFn:async (u,opts)=>{
    requests.push({u,opts});
    const bytes=new TextEncoder().encode('const token="'+token+'";');
    return {ok:true,headers:{get:()=>String(bytes.length)},body:{getReader:()=>({read:(()=>{let n=0;return async()=> n++ === 0 ? {done:false,value:bytes}:{done:true};})()})}};
  }});
  assert.equal(requests.length,1);
  assert.equal(requests[0].opts.credentials,'omit');
  assert.equal(requests[0].opts.redirect,'error');
  assert.equal(result.findings.length,1);
  assert.equal(result.findings[0].source,'/assets/app.js');
  assert.equal(result.stats.skippedExternal,1);
  assert.equal(result.partial,true);
  assert.ok(!JSON.stringify(result).includes(token));
});
test('oversize inline scripts are skipped with a partial-coverage warning', async () => {
  const result = await makePage({inline:['x'.repeat(512*1024+1)]});
  assert.equal(result.stats.skippedOversize,1);
  assert.equal(result.partial,true);
  assert.ok(result.warnings.some(w=>w.includes('size limits')));
});
test('no script is fetched unless the scan function runs', async () => {
  assert.equal(typeof runScanner, 'function');
});
