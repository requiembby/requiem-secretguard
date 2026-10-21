/* REQUIEM SecretGuard — code injected only after the user presses Scan. */
/* eslint-disable no-undef */
async function secretGuardInspectPage() {
  'use strict';
  // IMPORTANT: This function is serialized by chrome.scripting.executeScript.
  // Keep all helpers inside this function. Nothing leaves the tab except
  // bounded, redacted findings, counts, and coverage warnings.
  const MAX_SCRIPTS = 20;
  const MAX_INLINE_SCRIPTS = 60;
  const MAX_SCRIPT_BYTES = 512 * 1024;
  const MAX_FINDINGS = 75;
  const MAX_TOTAL_BYTES = 5 * 1024 * 1024;
  const rules = [
    { id: 'stripe-live', name: 'Possible Stripe live secret key', severity: 'critical', pattern: /\bsk_live_[A-Za-z0-9]{16,}\b/g, fix: 'Revoke and rotate the exposed secret; use server-side environment variables.' },
    { id: 'github-pat', name: 'Possible GitHub personal access token', severity: 'high', pattern: /\b(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{60,255})\b/g, fix: 'Revoke the token, remove it from code, and review repository history.' },
    { id: 'gitlab-pat', name: 'Possible GitLab access token', severity: 'high', pattern: /\bglpat-[A-Za-z0-9_\-]{18,}\b/g, fix: 'Rotate the token and move it to a protected server-side secret store.' },
    { id: 'slack-token', name: 'Possible Slack token', severity: 'high', pattern: /\bxox[baprs]-[A-Za-z0-9-]{18,}\b/g, fix: 'Rotate the token and remove it from public JavaScript.' },
    { id: 'pem-private-key', name: 'Private key header detected', severity: 'critical', pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g, fix: 'Investigate the full key block; if exposed, revoke and replace the key.' },
    { id: 'aws-key-id', name: 'AWS access-key identifier (not a secret by itself)', severity: 'medium', pattern: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, fix: 'Check whether its secret access key was also exposed; rotate the pair if compromised.' },
    { id: 'generic-hardcoded', name: 'Possible hardcoded secret assignment', severity: 'medium', pattern: /\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|client[_-]?secret)\b\s*[:=]\s*['"]([A-Za-z0-9_\-/.+=]{20,})['"]/gi, fix: 'Review the value; if sensitive, move it to server-side configuration.' }
  ];
  const findings = [];
  const warnings = [];
  const stats = { inlineScripts: 0, fetchedScripts: 0, bytesScanned: 0, skippedExternal: 0, skippedOversize: 0, failedFetches: 0 };
  const placeholder = /^(?:x{8,}|0{8,}|a{12,}|example|changeme|your[_-]?|placeholder|dummy|test[_-]?)/i;
  const scriptTypes = new Set(['', 'module', 'text/javascript', 'application/javascript', 'application/ecmascript', 'text/ecmascript']);

  function safePath(input) {
    try {
      const u = new URL(input, location.href);
      return (u.pathname || '/').slice(0, 180); // drop potentially secret query/fragment
    } catch (_) { return '[unavailable]'; }
  }
  function isAllowedScript(el) {
    const type = (el.getAttribute('type') || '').trim().toLowerCase();
    return scriptTypes.has(type);
  }
  function inspect(text, source) {
    if (stats.bytesScanned + text.length > MAX_TOTAL_BYTES) {
      warnings.push('Total scan byte cap reached; results are incomplete.');
      return false;
    }
    stats.bytesScanned += text.length;
    for (const rule of rules) {
      rule.pattern.lastIndex = 0;
      let match;
      while ((match = rule.pattern.exec(text)) !== null) {
        const candidate = match[1] || match[0];
        if (rule.id === 'generic-hardcoded' && placeholder.test(candidate)) continue;
        // Only source and line are returned, never credential text or surrounding code.
        const position = match.index;
        const before = text.slice(0, position);
        const line = 1 + (before.match(/\n/g) || []).length;
        findings.push({ id: rule.id, name: rule.name, severity: rule.severity, source, line, remediation: rule.fix });
        if (findings.length >= MAX_FINDINGS) {
          warnings.push('Finding cap reached; additional matches were not checked.');
          return false;
        }
      }
    }
    return true;
  }
  // Reading scripts never reads cookies, headers, fetch/XHR traffic, passwords,
  // localStorage or authentication state. Requests omit credentials deliberately.
  const scriptElements = Array.from(document.querySelectorAll('script')).filter(isAllowedScript);
  const inline = scriptElements.filter(s => !s.hasAttribute('src'));
  const linked = scriptElements.filter(s => s.hasAttribute('src'));
  let stopped = false;
  for (let i = 0; i < inline.length; i++) {
    if (i >= MAX_INLINE_SCRIPTS) { warnings.push('Inline script count limit reached.'); break; }
    const code = inline[i].textContent || '';
    if (code.length > MAX_SCRIPT_BYTES) { stats.skippedOversize++; continue; }
    stats.inlineScripts++;
    if (!inspect(code, `inline script #${i + 1}`)) { stopped = true; break; }
  }
  if (!stopped) {
    let uniqueURLs = new Set();
    for (const el of linked) {
      let url;
      try { url = new URL(el.getAttribute('src'), location.href); } catch (_) { continue; }
      if (url.protocol !== 'https:' && url.protocol !== 'http:') continue;
      if (url.origin !== location.origin) { stats.skippedExternal++; continue; }
      url.hash = '';
      if (uniqueURLs.has(url.href)) continue;
      uniqueURLs.add(url.href);
      if (uniqueURLs.size > MAX_SCRIPTS) { warnings.push('Same-origin script count limit reached.'); break; }
      const abort = new AbortController();
      const timer = setTimeout(() => abort.abort(), 4000);
      try {
        const response = await fetch(url.href, { credentials: 'omit', redirect: 'error', signal: abort.signal, cache: 'force-cache' });
        if (!response.ok) { stats.failedFetches++; continue; }
        const contentLength = Number(response.headers.get('content-length') || '0');
        if (contentLength > MAX_SCRIPT_BYTES) { stats.skippedOversize++; continue; }
        if (!response.body) { stats.failedFetches++; continue; }
        const reader = response.body.getReader();
        const pieces = [];
        let count = 0;
        let tooLarge = false;
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          count += value.byteLength;
          if (count > MAX_SCRIPT_BYTES) {
            tooLarge = true;
            await reader.cancel();
            break;
          }
          pieces.push(value);
        }
        if (tooLarge) { stats.skippedOversize++; continue; }
        const bytes = new Uint8Array(count);
        let offset = 0;
        for (const piece of pieces) { bytes.set(piece, offset); offset += piece.byteLength; }
        const code = new TextDecoder().decode(bytes);
        stats.fetchedScripts++;
        if (!inspect(code, safePath(url.href))) { stopped = true; break; }
      } catch (_) { stats.failedFetches++; }
      finally { clearTimeout(timer); }
    }
  }
  if (stats.skippedExternal) warnings.push(`${stats.skippedExternal} cross-origin script references were not examined.`);
  if (stats.skippedOversize) warnings.push(`${stats.skippedOversize} scripts exceeded size limits.`);
  if (stats.failedFetches) warnings.push(`${stats.failedFetches} same-origin script requests could not be inspected.`);
  return {
    version: '0.3.0',
    hostname: location.hostname,
    scannedAt: new Date().toISOString(),
    findings,
    stats,
    warnings,
    partial: warnings.length > 0,
    note: 'Pattern matches are not evidence of valid credentials. No auth state or cross-origin scripts inspected.'
  };
}
