/* Popup runs locally, shows redacted output and never saves credentials. */
'use strict';
const dom = (id) => document.getElementById(id);
let currentTab = null;
let latestReport = null;
const severityRank = { critical: 4, high: 3, medium: 2, low: 1 };
function setStatus(message) { dom('status').textContent = message; }
function setAllowed() {
  dom('scan').disabled = !(currentTab && dom('authorized').checked);
}
function addFinding(finding) {
  const card = document.createElement('div');
  card.className = 'finding';
  const head = document.createElement('div'); head.className = 'findingHeader';
  const title = document.createElement('strong'); title.textContent = finding.name;
  const severity = document.createElement('span'); severity.className = `sev ${finding.severity}`; severity.textContent = finding.severity.toUpperCase();
  head.append(title, severity); card.append(head);
  const source = document.createElement('div'); source.className = 'ref'; source.textContent = `${finding.source} : line ${finding.line}`;
  const fix = document.createElement('div'); fix.className = 'fix'; fix.textContent = finding.remediation;
  card.append(source, fix); dom('findings').append(card);
}
function showReport(report) {
  latestReport = report;
  dom('results').hidden = false;
  dom('scripts').textContent = String(report.stats.inlineScripts + report.stats.fetchedScripts);
  dom('count').textContent = String(report.findings.length);
  const highest = report.findings.map(f => f.severity).sort((a,b) => severityRank[b]-severityRank[a])[0] || 'none';
  dom('severity').textContent = highest.toUpperCase();
  dom('findings').replaceChildren();
  if (!report.findings.length) {
    const empty = document.createElement('div'); empty.className='empty';
    empty.textContent = 'No supported patterns found in the inspected scripts.';
    dom('findings').append(empty);
  } else report.findings.forEach(addFinding);
  const warningBox = dom('warnings'); warningBox.replaceChildren();
  warningBox.hidden = !report.warnings.length;
  report.warnings.forEach(w => { const p = document.createElement('div'); p.textContent = `• ${w}`; warningBox.append(p); });
  setStatus(report.partial ? 'Scan complete, but coverage was limited. Review warnings.' : 'Scan complete within supported scope. This is not a security certification.');
}
async function init() {
  try {
    const [tab] = await chrome.tabs.query({active:true,currentWindow:true});
    const url = tab?.url ? new URL(tab.url) : null;
    if (!tab?.id || !url || !['https:', 'http:'].includes(url.protocol)) {
      dom('target').textContent = 'Open a normal http(s) web page.';
      setStatus('Chrome internal pages, PDFs and browser stores are not supported.');
      return;
    }
    currentTab = {id: tab.id, url: tab.url};
    dom('target').textContent = url.hostname;
    setStatus('Confirm authorization to enable scanning.');
    setAllowed();
  } catch (e) { setStatus('Unable to access this tab. Try a normal website.'); }
}
dom('authorized').addEventListener('change', setAllowed);
dom('scan').addEventListener('click', async () => {
  if (!currentTab || !dom('authorized').checked) return;
  dom('scan').disabled = true;
  dom('results').hidden = true;
  setStatus('Inspecting supported JavaScript in the active tab…');
  try {
    const current = await chrome.tabs.get(currentTab.id);
    if (current.url !== currentTab.url) throw new Error('The active tab changed since you opened this popup. Reopen the extension.');
    const output = await chrome.scripting.executeScript({
      target: { tabId: currentTab.id }, func: secretGuardInspectPage
    });
    const report = output?.[0]?.result;
    if (!report || !report.stats || !Array.isArray(report.findings) || !Array.isArray(report.warnings)) throw new Error('No scan report was returned.');
    showReport(report);
  } catch (error) {
    setStatus(`Unable to scan: ${error.message || 'unknown error'}. Reload the page and try again.`);
  } finally { setAllowed(); }
});
dom('export').addEventListener('click', () => {
  if (!latestReport) return;
  const data = JSON.stringify(latestReport, null, 2);
  const url = URL.createObjectURL(new Blob([data], {type:'application/json'}));
  const a = document.createElement('a'); a.href = url;
  const safeName = latestReport.hostname.replace(/[^a-z0-9.-]/gi,'_').slice(0,80);
  a.download = `secretguard-${safeName || 'scan'}.json`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});
init();
