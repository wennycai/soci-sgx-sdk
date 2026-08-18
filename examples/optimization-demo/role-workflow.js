const $=s=>document.querySelector(s),$$=s=>[...document.querySelectorAll(s)],te=new TextEncoder(),td=new TextDecoder();
const esc=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&apos;'}[c]));
function bytes(v){return v instanceof Uint8Array?v:new Uint8Array(v)}function b64(v){let s='';for(const x of bytes(v))s+=String.fromCharCode(x);return btoa(s)}function unb64(s){return Uint8Array.from(atob(s),c=>c.charCodeAt(0))}
function crc32(data){let c=0xffffffff;for(const b of data){c^=b;for(let k=0;k<8;k++)c=(c>>>1)^((c&1)?0xedb88320:0)}return(c^0xffffffff)>>>0}function u16(a,o,v){a[o]=v&255;a[o+1]=v>>>8&255}function u32(a,o,v){u16(a,o,v);u16(a,o+2,v>>>16)}function concat(parts){const n=parts.reduce((s,p)=>s+p.length,0),out=new Uint8Array(n);let o=0;for(const p of parts){out.set(p,o);o+=p.length}return out}
function zip(entries){const local=[],central=[];let offset=0;for(const [name,value] of entries){const n=te.encode(name),d=bytes(value),crc=crc32(d),h=new Uint8Array(30);u32(h,0,0x04034b50);u16(h,4,20);u16(h,6,0x800);u16(h,8,0);u32(h,14,crc);u32(h,18,d.length);u32(h,22,d.length);u16(h,26,n.length);local.push(h,n,d);const c=new Uint8Array(46);u32(c,0,0x02014b50);u16(c,4,20);u16(c,6,20);u16(c,8,0x800);u32(c,16,crc);u32(c,20,d.length);u32(c,24,d.length);u16(c,28,n.length);u32(c,42,offset);central.push(c,n);offset+=h.length+n.length+d.length}const cd=concat(central),end=new Uint8Array(22);u32(end,0,0x06054b50);u16(end,8,entries.length);u16(end,10,entries.length);u32(end,12,cd.length);u32(end,16,offset);return concat([...local,cd,end])}
async function unzip(input){const a=bytes(input),dv=new DataView(a.buffer,a.byteOffset,a.byteLength);let e=-1;for(let i=a.length-22;i>=Math.max(0,a.length-65557);i--)if(dv.getUint32(i,true)===0x06054b50){e=i;break}if(e<0)throw Error('不是有效的 ZIP/XLSX/ENC 文件');const count=dv.getUint16(e+10,true),cd=dv.getUint32(e+16,true),out={};let p=cd;for(let i=0;i<count;i++){if(dv.getUint32(p,true)!==0x02014b50)throw Error('ZIP 目录损坏');const method=dv.getUint16(p+10,true),cs=dv.getUint32(p+20,true),nl=dv.getUint16(p+28,true),xl=dv.getUint16(p+30,true),cl=dv.getUint16(p+32,true),off=dv.getUint32(p+42,true),name=td.decode(a.slice(p+46,p+46+nl)),ln=dv.getUint16(off+26,true),lx=dv.getUint16(off+28,true),raw=a.slice(off+30+ln+lx,off+30+ln+lx+cs);if(method===0)out[name]=raw;else if(method===8){const stream=new Blob([raw]).stream().pipeThrough(new DecompressionStream('deflate-raw'));out[name]=new Uint8Array(await new Response(stream).arrayBuffer())}else throw Error(`不支持 ZIP 压缩方法 ${method}`);p+=46+nl+xl+cl}return out}
function colName(n){let s='';for(n++;n;n=Math.floor((n-1)/26))s=String.fromCharCode(65+(n-1)%26)+s;return s}function xlsx(rows){const sheet=rows.map((row,r)=>`<row r="${r+1}">${row.map((v,c)=>`<c r="${colName(c)}${r+1}" t="inlineStr"><is><t>${esc(v??'')}</t></is></c>`).join('')}</row>`).join('');return zip([['[Content_Types].xml',te.encode(`<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>`)],['_rels/.rels',te.encode(`<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>`)],['xl/workbook.xml',te.encode(`<?xml version="1.0"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="EncryptedData" sheetId="1" r:id="rId1"/></sheets></workbook>`)],['xl/_rels/workbook.xml.rels',te.encode(`<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="xl/worksheets/sheet1.xml"/></Relationships>`)],['xl/worksheets/sheet1.xml',te.encode(`<?xml version="1.0"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>${sheet}</sheetData></worksheet>`)]])}
async function readXlsx(buffer){const z=await unzip(buffer),sheet=z['xl/worksheets/sheet1.xml'];if(!sheet)throw Error('Excel 中找不到第一个工作表');let shared=[];if(z['xl/sharedStrings.xml']){const d=new DOMParser().parseFromString(td.decode(z['xl/sharedStrings.xml']),'text/xml');shared=[...d.querySelectorAll('si')].map(x=>[...x.querySelectorAll('t')].map(t=>t.textContent).join(''))}const doc=new DOMParser().parseFromString(td.decode(sheet),'text/xml'),rows=[];for(const row of doc.querySelectorAll('row')){const values=[];for(const c of row.querySelectorAll('c')){const ref=c.getAttribute('r')||'A1',col=[...ref.match(/^[A-Z]+/)[0]].reduce((n,x)=>n*26+x.charCodeAt(0)-64,0)-1,type=c.getAttribute('t'),v=c.querySelector('v')?.textContent??'',inline=[...c.querySelectorAll('is t')].map(x=>x.textContent).join('');values[col]=type==='s'?shared[Number(v)]:(type==='inlineStr'||type==='str'?inline||v:v)}rows.push(values)}return rows}
function parseCosts(rows){const out=[];for(let i=1;i<rows.length;i++){if(!rows[i]||rows[i].every(x=>x==null||x===''))continue;const costs=[1,2,3].map(j=>{const raw=rows[i][j];if(raw==null||String(raw).trim()==='')return null;const text=String(raw).trim();if(!/^\d+(?:\.\d{1,6})?$/.test(text))throw Error(`第 ${i+1} 行成本必须是非负且最多六位小数`);const v=Number(text);if(!Number.isFinite(v))throw Error(`第 ${i+1} 行成本超出有效范围`);return v});if(costs.every(v=>v==null))throw Error(`第 ${i+1} 行没有可用方式`);out.push({id:String(rows[i][0]||`M${i}`),costs})}if(!out.length)throw Error('Excel 没有有效数据');return out}
function wire(items,task){return `${task.threshold}\t${task.strategy}\t${task.grid}\n`+items.map(x=>[x.id,...x.costs.map(v=>v==null?'':v)].join('\t')).join('\n')}
async function api(path,body){const r=await fetch(path,{method:'POST',headers:{'Content-Type':'text/plain;charset=utf-8'},body}),d=await r.json();if(!r.ok)throw Error(d.error||'SOCI 后端调用失败');return d}
function download(data,name,type='application/octet-stream'){const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([data],{type}));a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(a.href),1000)}
function makeEnc(manifest,rows){return zip([['encrypted-data.xlsx',xlsx(rows)],['manifest.json',te.encode(JSON.stringify(manifest,null,2))]])}
async function readPkg(file){if(!file.name.toLowerCase().endsWith('.enc'))throw Error('请选择 .enc 文件');const raw=new Uint8Array(await file.arrayBuffer());const z=await unzip(raw);if(!z['manifest.json']||!z['encrypted-data.xlsx'])throw Error('加密包结构不完整');const m=JSON.parse(td.decode(z['manifest.json']));if(m.format!=='SOCI-ROLE-ENC'||m.version!==1)throw Error('不支持的加密包');return{manifest:m,bytes:raw}}
async function repack(buf,manifest){const z=await unzip(buf);z['manifest.json']=te.encode(JSON.stringify(manifest,null,2));return zip(Object.entries(z))}
function wireDrop(zone,input,handler){zone.onclick=e=>{if(e.target.tagName!=='BUTTON')input.click()};zone.querySelector('button').onclick=e=>{e.stopPropagation();input.click()};zone.ondragover=e=>{e.preventDefault();zone.classList.add('drag')};zone.ondragleave=()=>zone.classList.remove('drag');zone.ondrop=e=>{e.preventDefault();zone.classList.remove('drag');if(e.dataTransfer.files[0])handler(e.dataTransfer.files[0]).catch(showError)};input.onchange=()=>input.files[0]&&handler(input.files[0]).catch(showError)}
function showError(e){alert(e.message);console.error(e)}

// ---- 业务流程状态机:A 发起 → C 加密 → A 委托 → B 计算 → B 返回 → A 提交 → C 授权 → A 接收 ----
const STORE='soci-role-flow-v1';
const freshFlow=()=>({task:null,cipher:null,delegation:null,computed:null,returned:false,submitted:null,authorized:null,final:false});
let flow=freshFlow(),plainRows=null,plainName='',computing=false;
const STEPS=[
  {role:'user',done:f=>!!f.task},
  {role:'owner',done:f=>!!f.cipher},
  {role:'user',done:f=>!!f.delegation},
  {role:'compute',done:f=>!!f.computed},
  {role:'compute',done:f=>!!f.returned},
  {role:'user',done:f=>!!f.submitted},
  {role:'owner',done:f=>!!f.authorized},
  {role:'user',done:f=>!!f.final},
];
function persist(){try{sessionStorage.setItem(STORE,JSON.stringify(flow))}catch(e){}}
function restore(){try{const s=sessionStorage.getItem(STORE);if(s){const f=JSON.parse(s);if(f&&typeof f==='object')flow={...freshFlow(),...f}}}catch(e){}}
function goto(role){$$('[data-role]').forEach(x=>x.classList.toggle('active',x.dataset.role===role));$('#userPanel').classList.toggle('hidden',role!=='user');$('#ownerPanel').classList.toggle('hidden',role!=='owner');$('#computePanel').classList.toggle('hidden',role!=='compute')}
function setCard(sel,open,done,text){const c=$(sel);c.classList.toggle('locked',!open);c.classList.toggle('complete',!!done);c.classList.toggle('active',open&&!done);c.querySelector('.stage-state').textContent=text}
function meta(sel,text,badge){const el=$(sel);if(!text){el.classList.add('hidden');return}el.classList.remove('hidden');el.innerHTML=`<span>${esc(text)}</span><b>${esc(badge)}</b>`}
function check(sel,text){const el=$(sel);if(!text){el.classList.add('hidden');return}el.classList.remove('hidden');el.textContent=text}
function renderFinal(el,d){el.innerHTML=`<div class="decrypt-summary"><div><span>最优总成本</span><b>${Number(d.totalCost).toLocaleString('zh-CN',{minimumFractionDigits:2,maximumFractionDigits:2})}</b></div><div><span>最终 ratio</span><b>${(Number(d.ratio)*100).toFixed(4)}%</b></div><div><span>状态</span><b>AUTHORIZED</b></div></div><div class="decrypt-solution">solution = [${d.solution.join(', ')}]</div>`;el.classList.remove('hidden')}
function render(){
  const current=STEPS.findIndex(s=>!s.done(flow));
  $$('#bizSteps button').forEach((b,i)=>{b.classList.toggle('done',STEPS[i].done(flow));b.classList.toggle('current',i===current)});
  $$('[data-todo]').forEach(e=>e.classList.add('hidden'));
  if(current>=0){const badge=$(`[data-todo="${STEPS[current].role}"]`);if(badge)badge.classList.remove('hidden')}
  $('#flowComplete').classList.toggle('hidden',current!==-1);
  setCard('#aTaskCard',true,!!flow.task,flow.task?'任务已发起':'待发起');
  setCard('#cEncryptCard',!!flow.task,!!flow.cipher,!flow.task?'等待 A 发起任务':flow.cipher?'已加密并导出':'可执行');
  setCard('#aDelegateCard',!!flow.task,!!flow.delegation,!flow.task?'等待任务':flow.delegation?'已委托 B':flow.cipher?'可委托':'等待 C 加密');
  setCard('#bComputeCard',!!flow.delegation,!!flow.computed,!flow.delegation?'等待 A 委托':flow.computed?'计算完成':'可计算');
  setCard('#bReturnCard',!!flow.computed,!!flow.returned,!flow.computed?'等待计算完成':flow.returned?'已返回 A':'待返回 A');
  setCard('#aSubmitCard',!!(flow.returned&&flow.computed),!!flow.submitted,!(flow.returned&&flow.computed)?'等待 B 返回':flow.submitted?'已提交 C':'可提交');
  setCard('#cDecryptCard',!!flow.submitted,!!flow.authorized,!flow.submitted?'等待 A 提交':flow.authorized?'已授权':'可授权');
  setCard('#aFinalCard',!!flow.authorized,!!flow.final,flow.authorized?'已完成':'等待 C 授权');
  meta('#aTaskMeta',flow.task&&`✓ 任务 ${flow.task.task_id} · 阈值 ≥ ${flow.task.threshold} · ${flow.task.strategy} · K=${flow.task.grid}`,'PUBLIC 参数');
  meta('#cTaskMeta',flow.task&&`✓ 来自 A 的任务 ${flow.task.task_id} · 阈值 ≥ ${flow.task.threshold} · ${flow.task.strategy} · K=${flow.task.grid}`,'按任务加密');
  check('#aCipherMeta',flow.cipher&&`✓ 已接收 C 的加密文件 · ${flow.cipher.manifest.row_count} 行 · 密文不可读`);
  check('#bTaskMeta',flow.delegation&&`✓ 委托文件校验通过 · ${flow.delegation.manifest.row_count} 行 · B 不可读取成本`);
  check('#aResultMeta',flow.computed&&flow.returned&&`✓ 已接收 B 的密文结果 · ${flow.computed.manifest.mode||''} · ${flow.computed.manifest.strategy||''}`);
  check('#cResultMeta',flow.submitted&&`✓ A 提交的 ${flow.submitted.manifest.mode||''} 计算结果 · ${flow.submitted.manifest.strategy||''} · 等待授权`);
  $('#bParams').innerHTML=flow.delegation?`<span>阈值 ≥ <b>${esc(flow.delegation.manifest.threshold)}</b></span><span>策略 <b>${esc(flow.delegation.manifest.strategy)}</b></span><span><b>K = ${esc(flow.delegation.manifest.grid||3)}</b></span>`:'';
  $('#aStart').firstChild.textContent=flow.task?'重新发起任务（清空后续状态） ':'发起任务并通知 C ';
  $('#cEncrypt').disabled=!(flow.task&&plainRows);
  $('#aDelegate').disabled=!(flow.task&&flow.cipher);
  $('#bCompute').disabled=!flow.delegation||computing;
  $('#bExport').disabled=!flow.computed;
  $('#aSubmit').disabled=!(flow.returned&&flow.computed);
  $('#cDecrypt').disabled=!flow.submitted;
  $('#cExport').classList.toggle('hidden',!flow.authorized);
  if(flow.computed){$('#bStats').classList.remove('hidden');const m=flow.computed.manifest;$('#bStats code').textContent=m.encrypted_result[0];const s=m.stats||{};$('#bStats small').textContent=`${m.mode||''} · ${m.strategy||''} · visited ${s.visited_nodes} · pruned ${s.pruned_nodes} · PRUNE ${s.prune_predicates} · ACCEPT ${s.accept_predicates}`}else{$('#bStats').classList.add('hidden')}
  if(flow.authorized){renderFinal($('#cDecoded'),flow.authorized);renderFinal($('#aFinalResult'),flow.authorized)}else{$('#cDecoded').classList.add('hidden');$('#aFinalResult').classList.add('hidden')}
}

// ---- B 方估算进度条:上限 95%,成功后跳 100%,ETA 随耗时动态修正,不倒退 ----
const HIST='soci-demo-bcompute-ms';
function estimateMs(){try{const h=JSON.parse(localStorage.getItem(HIST)||'[]').filter(x=>x>0);if(h.length){h.sort((a,b)=>a-b);return h[Math.floor(h.length/2)]}}catch(e){}return 30000}
function recordMs(ms){try{const h=JSON.parse(localStorage.getItem(HIST)||'[]').filter(x=>x>0);h.push(Math.round(ms));localStorage.setItem(HIST,JSON.stringify(h.slice(-12)))}catch(e){}}
function fmtDur(s){s=Math.max(0,Math.round(s));return s<60?`${s}s`:`${Math.floor(s/60)}m ${String(s%60).padStart(2,'0')}s`}
let ticker=null;
function startProgress(estMs){stopProgress();const t0=performance.now();let shown=0;$('#bProgress').classList.remove('hidden','done');$('#cpFill').style.width='0%';
  ticker=setInterval(()=>{const t=(performance.now()-t0)/1000,est=estMs/1000;
    shown=Math.max(shown,95*(1-Math.exp(-2.2*t/est)));
    $('#cpFill').style.width=shown.toFixed(1)+'%';$('#cpPct').textContent=Math.floor(shown)+'%';
    $('#cpElapsed').textContent=`已用 ${fmtDur(t)}`;
    const rem=est-t;$('#cpEta').textContent=rem>0.5?`预计剩余 ${fmtDur(rem)}`:'已超过预估，即将完成';
    $('#cpPhase').textContent=shown<25?'密态预处理与任务载入':shown<85?'正在进行密态最优化计算':'PredicateEngine 谓词求值（收尾）';
  },200);return t0}
function stopProgress(){if(ticker){clearInterval(ticker);ticker=null}}
function finishProgress(t0){stopProgress();const t=(performance.now()-t0)/1000;$('#cpFill').style.width='100%';$('#cpPct').textContent='100%';$('#cpElapsed').textContent=`已用 ${fmtDur(t)}`;$('#cpEta').textContent='计算完成';$('#cpPhase').textContent='密态计算完成';$('#bProgress').classList.add('done')}

// ---- 角色动作 ----
$('#aStrategy').onchange=e=>$('#aGrid').disabled=e.target.value!=='lagrangian';
$('#aStart').onclick=()=>{const t=Number($('#aThreshold').value);if(!(t>=0&&t<1))return showError(Error('阈值必须满足 0 ≤ T < 1'));
  flow=freshFlow();flow.task={task_id:'T-'+Math.random().toString(36).slice(2,8).toUpperCase(),threshold:t,strategy:$('#aStrategy').value,grid:Number($('#aGrid').value),created_by:'role-A',created_at:new Date().toISOString()};
  persist();render();goto('owner')};
wireDrop($('#cPlainDrop'),$('#cPlainFile'),async file=>{if(!file.name.toLowerCase().endsWith('.xlsx'))throw Error('C 的明文输入必须是 .xlsx');plainRows=parseCosts(await readXlsx(await file.arrayBuffer()));plainName=file.name;meta('#cPlainMeta',`✓ ${file.name} · ${plainRows.length} 行`,'明文仅 C 可见');render()});
$('#cEncrypt').onclick=async()=>{const btn=$('#cEncrypt');if(!flow.task||!plainRows)return;btn.disabled=true;btn.firstChild.textContent='正在加密… ';
  try{const d=await api('/api/workflow/encrypt',wire(plainRows,flow.task));
    const manifest={format:'SOCI-ROLE-ENC',version:1,stage:'encrypted-input',job_id:d.jobId,row_count:plainRows.length,algorithm:'Paillier-3072',task:flow.task,created_by:'role-C',created_at:new Date().toISOString()};
    const rows=[['MATERIAL_ID','ENC_METHOD_1','ENC_METHOD_2','ENC_METHOD_3'],...plainRows.map((x,i)=>[btoa(unescape(encodeURIComponent(x.id))),...d.rows[i]])];
    const pkg=makeEnc(manifest,rows);flow.cipher={manifest,pkg:b64(pkg)};
    download(pkg,`soci-C-encrypted-${flow.task.task_id}.enc`);persist();render();goto('user');
  }catch(e){showError(e)}finally{btn.firstChild.textContent='按任务加密并导出密文 ';render()}};
wireDrop($('#aCipherDrop'),$('#aCipherFile'),async file=>{const{manifest,bytes:raw}=await readPkg(file);if(manifest.stage!=='encrypted-input')throw Error('请选择角色 C 生成的加密成本文件');flow.cipher={manifest,pkg:b64(raw)};persist();render()});
$('#aDelegate').onclick=async()=>{try{if(!flow.task||!flow.cipher)return;const c=flow.cipher.manifest;
    const manifest={format:'SOCI-ROLE-ENC',version:1,stage:'delegated-task',job_id:c.job_id,row_count:c.row_count,algorithm:c.algorithm,task_id:flow.task.task_id,threshold:flow.task.threshold,strategy:flow.task.strategy,grid:flow.task.grid,delegated_by:'role-A',delegated_at:new Date().toISOString()};
    const pkg=await repack(unb64(flow.cipher.pkg),manifest);flow.delegation={manifest,pkg:b64(pkg)};
    download(pkg,`soci-A-delegate-${flow.task.task_id}.enc`);persist();render();goto('compute');
  }catch(e){showError(e)}};
wireDrop($('#bTaskDrop'),$('#bTaskFile'),async file=>{const{manifest,bytes:raw}=await readPkg(file);if(manifest.stage!=='delegated-task')throw Error('请选择角色 A 生成的委托文件');flow.delegation={manifest,pkg:b64(raw)};persist();render()});
async function runCompute(){const btn=$('#bCompute');if(!flow.delegation||computing)return;const m=flow.delegation.manifest;
  computing=true;btn.disabled=true;$('#bError').classList.add('hidden');
  const t0=startProgress(estimateMs());
  try{const d=await api('/api/workflow/compute',`${m.job_id}\t${m.threshold}\t${m.strategy}\t${m.grid||3}`);
    recordMs(performance.now()-t0);finishProgress(t0);
    const manifest={format:'SOCI-ROLE-ENC',version:1,stage:'computed-result',job_id:m.job_id,result_id:d.resultId,task_id:m.task_id,threshold:m.threshold,strategy:m.strategy,grid:m.grid||3,mode:d.mode,stats:d.stats,encrypted_result:d.ciphertexts,computed_by:'role-B',computed_at:new Date().toISOString()};
    flow.computed={manifest,pkg:b64(makeEnc(manifest,[['RESULT_COLUMN'],...d.ciphertexts.map(x=>[x])]))};
    computing=false;persist();render();$('#bReturnCard').scrollIntoView({behavior:'smooth',block:'center'});
  }catch(e){computing=false;stopProgress();$('#bProgress').classList.add('hidden');$('#bErrorText').textContent=`计算失败:${e.message}`;$('#bError').classList.remove('hidden');render()}}
$('#bCompute').onclick=runCompute;$('#bRetry').onclick=runCompute;
$('#bExport').onclick=()=>{if(!flow.computed)return;download(unb64(flow.computed.pkg),`soci-B-result-${flow.computed.manifest.task_id||'out'}.enc`);flow.returned=true;persist();render();goto('user')};
wireDrop($('#aResultDrop'),$('#aResultFile'),async file=>{const{manifest,bytes:raw}=await readPkg(file);if(manifest.stage!=='computed-result'||!manifest.result_id)throw Error('必须选择 B 返回的计算结果文件');flow.computed={manifest,pkg:b64(raw)};flow.returned=true;persist();render()});
$('#aSubmit').onclick=()=>{if(!flow.computed||!flow.returned)return;flow.submitted=flow.computed;persist();render();goto('owner')};
wireDrop($('#cResultDrop'),$('#cResultFile'),async file=>{const{manifest,bytes:raw}=await readPkg(file);if(manifest.stage!=='computed-result'||!manifest.result_id)throw Error('必须选择 A 提交的计算结果文件');flow.computed=flow.computed||{manifest,pkg:b64(raw)};flow.returned=true;flow.submitted={manifest,pkg:b64(raw)};persist();render()});
$('#cDecrypt').onclick=async()=>{const btn=$('#cDecrypt');if(!flow.submitted)return;btn.disabled=true;
  try{const d=await api('/api/workflow/decrypt',flow.submitted.manifest.result_id);
    flow.authorized={format:'SOCI-AUTHORIZED-RESULT',from:'role-C',to:'role-A',task_id:flow.submitted.manifest.task_id||null,totalCost:d.totalCost,ratio:d.ratio,solution:d.solution,authorized_at:new Date().toISOString()};
    flow.final=true;persist();render();
    download(te.encode(JSON.stringify(flow.authorized,null,2)),`soci-authorized-${flow.authorized.task_id||'result'}.json`,'application/json');goto('user');
  }catch(e){showError(e);btn.disabled=false}};
$('#cExport').onclick=()=>{if(flow.authorized)download(te.encode(JSON.stringify(flow.authorized,null,2)),`soci-authorized-${flow.authorized.task_id||'result'}.json`,'application/json')};
wireDrop($('#aFinalDrop'),$('#aFinalFile'),async file=>{const d=JSON.parse(td.decode(new Uint8Array(await file.arrayBuffer())));if(d.format!=='SOCI-AUTHORIZED-RESULT'||!Array.isArray(d.solution))throw Error('不是 C 签发的授权结果文件');flow.authorized=d;flow.final=true;persist();render()});
$$('[data-role]').forEach(b=>b.onclick=()=>goto(b.dataset.role));
$$('#bizSteps button').forEach(b=>b.onclick=()=>goto(STEPS[Number(b.dataset.biz)].role));
fetch('/api/health').then(r=>r.json()).then(x=>$$('[data-runtime-mode]').forEach(e=>e.textContent=x.mode)).catch(()=>{});
restore();render();
