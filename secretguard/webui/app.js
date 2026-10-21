'use strict';
// Browser-to-localhost only. Credentials never enter exported reports.
const $ = id => document.getElementById(id);
const state = { selected: [], report: null, filter: 'all', busy: false };
const SKIP_DIRS = new Set(['.git','.hg','.svn','.venv','venv','env','node_modules','__pycache__','.pytest_cache','dist','build','coverage','.next']);
const SKIP_EXTS = new Set(['.png','.jpg','.jpeg','.gif','.webp','.pdf','.zip','.gz','.tar','.exe','.dll','.so','.dylib','.mp4','.mp3','.ico','.woff','.woff2','.sqlite','.db']);
if (location.protocol.startsWith('http')) {
  document.querySelector('.top-chip').lastChild.textContent = ` ${location.host}`;
}
const MAX_FILES = 1000;
const MAX_SINGLE_FILE = 1000000;
const MAX_TEXT_TOTAL = 7000000;

function setError(message = '') {
  $('errorBox').hidden = !message;
  $('errorBox').textContent = message;
}
function setBusy(busy, message) {
  state.busy = busy;
  $('scanButton').disabled = busy || !state.selected.length;
  $('selectFolder').disabled = busy;
  $('demoButton').disabled = busy;
  $('folderInput').disabled = busy;
  $('scanButtonText').textContent = busy ? 'Scanning…' : 'Run security scan';
  $('progress').hidden = !busy;
  if (message) $('progressText').textContent = message;
  if (!busy) $('progressBar').style.width = '0%';
}
function validFile(file) {
  const path = file.webkitRelativePath || file.name;
  const pieces = path.split('/');
  if (pieces.slice(0, -1).some(dir => SKIP_DIRS.has(dir))) return false;
  const last = pieces.at(-1) || '';
  const extension = last.includes('.') ? '.' + last.split('.').at(-1).toLowerCase() : '';
  return !SKIP_EXTS.has(extension);
}
function chooseFiles(list) {
  state.selected = Array.from(list).filter(validFile);
  const first = list[0];
  const folder = first ? (first.webkitRelativePath || '').split('/')[0] || 'Selected folder' : '';
  $('folderTitle').textContent = first ? folder : 'No folder selected';
  $('folderDescription').textContent = first
    ? `${state.selected.length.toLocaleString()} in-scope files selected · ${list.length - state.selected.length} excluded by scan scope`
    : 'Choose a folder containing your source code to scan locally.';
  $('scanButton').disabled = !state.selected.length;
  setError('');
}
$('selectFolder').addEventListener('click', () => $('folderInput').click());
$('folderInput').addEventListener('change', event => chooseFiles(event.target.files));
$('scanButton').addEventListener('click', scanSelected);
$('demoButton').addEventListener('click', async () => {
  setError(''); setBusy(true, 'Running synthetic local scan…');
  try { renderReport(await request('/api/demo', {})); }
  catch (error) { setError(error.message); }
  finally { setBusy(false); }
});
for (const button of document.querySelectorAll('.filter')) {
  button.addEventListener('click', () => {
    state.filter = button.dataset.severity;
    for (const other of document.querySelectorAll('.filter')) other.classList.toggle('active', other === button);
    renderFindings();
  });
}
$('searchFindings').addEventListener('input', renderFindings);
$('downloadJson').addEventListener('click', () => {
  if (state.report) download('secretguard-report.json', JSON.stringify(state.report, null, 2) + '\n', 'application/json');
});
$('downloadHtml').addEventListener('click', () => {
  if (state.report) download('secretguard-report.html', buildHtmlReport(state.report), 'text/html');
});
for (const link of document.querySelectorAll('.nav-link')) {
  link.addEventListener('click', () => {
    document.querySelectorAll('.nav-link').forEach(element => element.classList.toggle('active', element === link));
  });
}
async function request(endpoint, payload) {
  const response = await fetch(endpoint, {
    method: 'POST', credentials: 'same-origin',
    headers: {'Content-Type': 'application/json', 'X-SecretGuard-Request': 'local-ui'},
    body: JSON.stringify(payload), cache: 'no-store'
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || `Scan failed (${response.status})`);
  return result;
}
async function scanSelected() {
  if (!state.selected.length || state.busy) return;
  setError('');
  if (state.selected.length > MAX_FILES) {
    setError(`This preview supports up to ${MAX_FILES} in-scope files. For larger projects, use the existing Python CLI, which supports up to 5000.`);
    return;
  }
  setBusy(true, 'Reading selected local files…');
  try {
    const docs = [];
    let totalBytes = 0;
    for (let i = 0; i < state.selected.length; i++) {
      const file = state.selected[i];
      const path = (file.webkitRelativePath || file.name).replaceAll('\\', '/');
      if (file.size > MAX_SINGLE_FILE) {
        docs.push({ path, oversized: true });
      } else {
        totalBytes += file.size;
        if (totalBytes > MAX_TEXT_TOTAL) throw new Error('Selected text exceeds 7 MB. Choose a smaller folder, or scan this repository with the Python CLI. No scan was performed.');
        docs.push({ path, content: await file.text() });
      }
      if (i % 12 === 0 || i === state.selected.length - 1) {
        const percent = Math.round((i + 1) / state.selected.length * 90);
        $('progressBar').style.width = `${percent}%`;
        $('progressText').textContent = `Reading local files ${i + 1} / ${state.selected.length}`;
        await new Promise(resolve => requestAnimationFrame(resolve));
      }
    }
    $('progressBar').style.width = '96%';
    $('progressText').textContent = 'Analyzing patterns with local Python engine…';
    const folder = (state.selected[0].webkitRelativePath || '').split('/')[0] || 'Browser-selected folder';
    const report = await request('/api/scan', { folder, files: docs });
    renderReport(report);
    $('progressBar').style.width = '100%';
  } catch (error) {
    setError(error.message || 'Unexpected scan error');
  } finally { setBusy(false); }
}
function renderReport(report) {
  state.report = report;
  $('filesCount').textContent = report.files_scanned.toLocaleString();
  $('findingsCount').textContent = report.findings_count.toLocaleString();
  $('highCount').textContent = report.severity_counts.high;
  $('criticalCount').textContent = report.severity_counts.critical;
  $('navFindingCount').textContent = report.findings_count;
  $('countAll').textContent = report.findings_count;
  const timestamp = new Date(report.scanned_at);
  $('scanDate').textContent = `SCAN COMPLETE · ${timestamp.toLocaleString()}`;
  $('resultsInfo').textContent = `${report.target} · ${report.files_scanned} files · ${report.verdict}`;
  $('downloadJson').disabled = false;
  $('downloadHtml').disabled = false;
  const coverage = $('coverage');
  coverage.hidden = false;
  coverage.classList.toggle('clean', !report.incomplete);
  coverage.textContent = report.incomplete
    ? `INCOMPLETE COVERAGE — ${report.warnings.join(' · ')}. Do not treat this as a clean result.`
    : `Scope: ${report.scope} Matches are not proof credentials are active.`;
  renderFindings();
  $('findings').scrollIntoView({ behavior: 'smooth', block: 'start' });
}
function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}
function renderFindings() {
  const root = $('resultsList');
  root.replaceChildren();
  const report = state.report;
  if (!report) { renderEmpty(root, 'Ready when you are.', 'Select a folder or use the harmless demo to see how SecretGuard works.'); return; }
  const needle = $('searchFindings').value.toLowerCase().trim();
  const findings = report.findings.filter(f => {
    return (state.filter === 'all' || f.severity === state.filter) &&
      (!needle || [f.description, f.file, f.rule_id, f.recommendation].join(' ').toLowerCase().includes(needle));
  });
  if (!findings.length) {
    renderEmpty(root, report.findings.length ? 'No matching findings.' : 'No patterns detected.',
      report.findings.length ? 'Try a different search or severity filter.' : 'No matches within the scanned scope. This is not a security certification.');
    return;
  }
  const frag = document.createDocumentFragment();
  for (const finding of findings) {
    const card = element('article', 'finding-card');
    const copy = element('div');
    copy.append(element('div','finding-header',finding.description));
    copy.append(element('div','finding-location',`${finding.file}:${finding.line}  ·  ${finding.rule_id}  ·  fp:${finding.fingerprint}`));
    copy.append(element('p','finding-detail',finding.recommendation));
    card.append(copy,element('span',`finding-tag ${finding.severity}`,finding.severity.toUpperCase()));
    frag.append(card);
  }
  root.append(frag);
}
function renderEmpty(root, title, message) {
  const shell = element('div','empty-state');
  shell.append(element('span','empty-orb','◎'),element('h3','',title),element('p','',message));
  root.append(shell);
}
function download(filename, text, type) {
  const link = document.createElement('a');
  const url = URL.createObjectURL(new Blob([text], { type: `${type};charset=utf-8` }));
  link.href = url; link.download = filename;
  document.body.append(link);
  link.click(); link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
}
function buildHtmlReport(report) {
  const lines = report.findings.map(f => `<article class="finding"><span class="severity ${escapeHtml(f.severity)}">${escapeHtml(f.severity.toUpperCase())}</span><h3>${escapeHtml(f.description)}</h3><code>${escapeHtml(f.file)}:${Number(f.line)} · ${escapeHtml(f.rule_id)} · fp:${escapeHtml(f.fingerprint)}</code><p>${escapeHtml(f.recommendation)}</p></article>`).join('');
  const warnings = report.warnings.length ? `<p class="warning">INCOMPLETE COVERAGE: ${escapeHtml(report.warnings.join(' / '))}</p>` : '';
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'"><title>SecretGuard Report</title><style>body{font:15px system-ui,sans-serif;max-width:970px;margin:0 auto;padding:50px 24px;background:radial-gradient(ellipse at top right,#26183e,#0c0917 65%);color:#ece4ff}h1{font-size:40px;letter-spacing:-.04em}.logo{color:#b48cff;letter-spacing:.15em;font-size:12px;font-weight:800}.muted{color:#a99dbe;line-height:1.6}.summary{display:flex;flex-wrap:wrap;gap:10px;margin:28px 0}.stat{min-width:130px;border:1px solid #403150;background:#1c152b;border-radius:12px;padding:19px}.stat b{display:block;font-size:30px}.stat small{font-size:10px;color:#b8a7cc;letter-spacing:.1em}.finding{border:1px solid #3a2d4d;border-radius:12px;background:#1b1429;padding:20px;margin:12px 0}.finding h3{margin:0 0 8px}.finding code{color:#b9a3d9;font-size:12px;overflow-wrap:anywhere}.finding p{color:#c2b5cf;font-size:13px}.severity{float:right;background:#422636;color:#ffa1ba;border-radius:6px;padding:6px;font-size:10px;font-weight:800}.severity.critical{background:#5c2338}.severity.medium{background:#554027;color:#eec78a}.warning{border-left:3px solid orange;padding:15px;background:#342516}footer{border-top:1px solid #332940;margin-top:40px;padding-top:15px;font-size:12px;color:#8f84a5}</style></head><body><div class="logo">REQUIEM / SECRETGUARD</div><h1>Security Overview.</h1><p class="muted">${escapeHtml(report.target)} · ${escapeHtml(report.scanned_at)} · ${escapeHtml(report.verdict)}</p><div class="summary"><div class="stat"><b>${Number(report.files_scanned)}</b><small>FILES SCANNED</small></div><div class="stat"><b>${Number(report.findings_count)}</b><small>FINDINGS</small></div><div class="stat"><b>${Number(report.severity_counts.high)}</b><small>HIGH</small></div><div class="stat"><b>${Number(report.severity_counts.critical)}</b><small>CRITICAL</small></div></div>${warnings}<h2>Security findings</h2>${lines || '<p class="muted">No matches within the scanned scope.</p>'}<footer>Pattern matches, not proof of active credentials. No raw keys included. Scanned locally with REQUIEM SecretGuard ${escapeHtml(report.version)}. Reports contain file paths and should be handled responsibly.</footer></body></html>`;
}
