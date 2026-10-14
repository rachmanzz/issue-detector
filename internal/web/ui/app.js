const $ = id => document.getElementById(id);
let last = null;

function sevClass(s){return ['critical','high','medium','low','info'].includes(s)?s:'info';}

function render(){
  if(!last){return;}
  const rows = $('rows'); rows.innerHTML = '';
  const f = last.findings || [];
  $('summary').textContent = `scan ${last.scan_id} · ${last.summary.findings} findings · ${last.summary.files_enumerated} files · ${last.duration_ms} ms`;
  const ai = last.ai_summary || '';
  $('aisummary').hidden = !ai;
  $('aisummarytext').textContent = ai;
  for(const x of f){
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><span class="sev ${sevClass(x.severity)}">${x.severity}</span></td>
      <td class="score">${(x.priority_score||0).toFixed(1)}<div class="bar"><i style="width:${x.priority_score||0}%"></i></div></td>
      <td><code>${x.rule_id}</code><div class="file">${x.category} · ${x.source}${x.source==='ai'?' <span class="badge ai">AI</span>':''}${x.in_diff?' <span class="badge">in diff</span>':''}</div></td>
      <td class="file">${x.file}:${x.line}</td>
      <td><strong>${x.title}</strong>
        <div>${x.message||''}</div>
        ${x.snippet?`<div><code>${x.snippet}</code></div>`:''}
        ${x.fix_hint?`<div class="fix">fix: ${x.fix_hint}</div>`:''}
        ${x.score_reason?`<details><summary>score breakdown</summary><div class="file">${x.score_reason}</div></details>`:''}
        <button class="ghost" data-rule="${escapeAttr(x.rule_id)}" data-file="${escapeAttr(x.file)}" data-line="${x.line||0}" data-snippet="${escapeAttr(x.snippet||'')}">mark FP / ignore</button>
      </td>`;
    rows.appendChild(tr);
  }
  $('tbl').hidden = f.length === 0;
  for(const b of rows.querySelectorAll('button[data-rule]')){
    b.onclick = () => triage(b);
  }
}

function escapeAttr(s){return String(s).replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/</g,'&lt;');}

function triage(btn){
  btn.disabled = true;
  fetch('/api/triage',{method:'POST',headers:{'Content-Type':'application/json'},
    body: JSON.stringify({
      rule_id: btn.dataset.rule,
      file: btn.dataset.file,
      line: parseInt(btn.dataset.line,10)||0,
      snippet: btn.dataset.snippet
    })})
    .then(r=>r.json()).then(()=>{ btn.closest('tr').style.opacity=.4; btn.textContent='ignored'; });
}

function load(){
  const qs = new URLSearchParams();
  if($('sevmin').value) qs.set('severity_min', $('sevmin').value);
  if($('cat').value) qs.set('category', $('cat').value);
  if($('source').value) qs.set('source', $('source').value);
  if($('indiff').checked) qs.set('in_diff','1');
  fetch('/api/scan?'+qs).then(r=>r.json()).then(d=>{last=d; render();});
}

document.addEventListener('DOMContentLoaded', () => {
  $('scan').onclick = () => {
    $('prog').textContent = 'scanning…';
    const es = new EventSource('/api/events');
    es.addEventListener('progress', e => { const p=JSON.parse(e.data); $('prog').textContent=`scanned ${p.scanned}/${p.total}`; });
    es.addEventListener('result', e => { last = JSON.parse(e.data); render(); });
    es.addEventListener('done', () => { $('prog').textContent='done'; es.close(); });
    es.addEventListener('error', e => { try{$('prog').textContent='error: '+JSON.parse(e.data).error;}catch(_){$('prog').textContent='error';} es.close(); });
  };
  ['sevmin','cat','source','indiff'].forEach(id => $(id).addEventListener('change', load));

  $('labrun').onclick = () => {
    fetch('/api/rules/test',{method:'POST',headers:{'Content-Type':'application/json'},
      body: JSON.stringify({yaml:$('labyaml').value, language:$('lablang').value, code:$('labcode').value})})
      .then(r=>r.json()).then(d=>{ $('labout').textContent = (d.matches||[]).map(m=>`line ${m.line}: ${m.snippet}`).join('\n') || 'no matches'; });
  };

  $('trendq').onclick = () => {
    fetch('/api/trend').then(r=>r.json()).then(snaps => {
      $('trendout').textContent = snaps.map(s=>`${s.time||''} findings=${s.findings} crit=${s.critical} high=${s.high} avg=${s.avg_score}`).join('\n') || 'empty';
    });
  };
});