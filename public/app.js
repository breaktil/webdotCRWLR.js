const form = document.getElementById('scan-form');
const urlInput = document.getElementById('site-url');
const scanBtn = document.getElementById('scan-btn');
const progressEl = document.getElementById('progress');
const progressLog = document.getElementById('progress-log');
const resultsEl = document.getElementById('results');

const MAX_LIST = 30;

const PREFIX = {
  critical: { cls: 'crit', label: 'CRIT' },
  high: { cls: 'warn', label: 'WARN' },
  medium: { cls: 'warn', label: 'WARN' },
  low: { cls: 'info', label: 'INFO' },
  info: { cls: 'info', label: 'INFO' },
  good: { cls: 'ok', label: 'OK' },
};

function prefixHtml(severity) {
  const p = PREFIX[severity] || PREFIX.info;
  return `<span class="prefix ${p.cls}">[${p.label}]</span>`;
}

function lineHtml(severity, message, extraClass = '') {
  const sev = severity || 'info';
  return `<p class="line finding ${sev} ${extraClass}">${prefixHtml(sev)}${escapeHtml(message)}</p>`;
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function appendProgress(message, severity = 'info') {
  progressEl.classList.remove('hidden');
  const div = document.createElement('div');
  div.className = 'line log-line';
  div.innerHTML = `${prefixHtml(severity)}${escapeHtml(message)}`;
  progressLog.appendChild(div);
  div.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
}

function clearProgress() {
  progressLog.innerHTML = '';
}

function renderSummary(report) {
  const s = report.summary || {};
  const target = report.target || '—';
  return `
    <p class="line target-line">${prefixHtml('info')}Target: <span class="path">${escapeHtml(target)}</span></p>
    <p class="line">${prefixHtml('info')}Scan window: ${escapeHtml(report.startedAt || '?')} → ${escapeHtml(report.finishedAt || '?')}</p>
    <div class="summary-grid">
      <div class="stat critical"><div class="value">${s.critical || 0}</div><div class="label">CRIT</div></div>
      <div class="stat high"><div class="value">${s.high || 0}</div><div class="label">HIGH</div></div>
      <div class="stat medium"><div class="value">${s.medium || 0}</div><div class="label">MED</div></div>
      <div class="stat low"><div class="value">${s.low || 0}</div><div class="label">LOW</div></div>
      <div class="stat good"><div class="value">${s.good || 0}</div><div class="label">OK</div></div>
    </div>
    <p class="line">${prefixHtml(s.critical > 0 ? 'crit' : s.high > 0 ? 'warn' : 'ok')}Total actionable findings: ${s.totalFindings ?? 0}</p>
  `;
}

function renderFindings(findings, emptyText = 'No issues in this category.') {
  if (!findings || findings.length === 0) {
    return `<p class="line empty-msg">${prefixHtml('info')}${escapeHtml(emptyText)}</p>`;
  }
  return findings
    .map((f) => {
      const sev = f.severity || 'info';
      const msg = f.message || f.label || JSON.stringify(f);
      return lineHtml(sev, msg);
    })
    .join('');
}

function renderWordPress(wp) {
  if (!wp) return lineHtml('info', 'WordPress detection not run.');
  const lines = [
    lineHtml(wp.detected ? 'warn' : 'info', wp.detected ? 'WordPress indicators detected on homepage.' : 'No strong WordPress signals on homepage.'),
  ];
  if (wp.signals?.length) {
    lines.push(`<p class="section-head">${prefixHtml('info')}signals:</p>`);
    lines.push(
      '<ul class="path-list">' +
        wp.signals.map((s) => `<li>${escapeHtml(s)}</li>`).join('') +
        '</ul>',
    );
  }
  return lines.join('');
}

function renderRobots(robots) {
  if (!robots) return lineHtml('info', 'robots.txt not checked.');
  let html = renderFindings(robots.findings, 'No robots.txt findings.');
  if (robots.disallows?.length) {
    html += `<p class="section-head">${prefixHtml('info')}disallow rules (${robots.disallows.length}):</p>`;
    html +=
      '<ul class="path-list">' +
      robots.disallows
        .slice(0, 20)
        .map((d) => `<li>${escapeHtml(d.agent)}: ${escapeHtml(d.path)}</li>`)
        .join('') +
      '</ul>';
  }
  if (robots.raw) {
    html += `<p class="section-head">${prefixHtml('info')}raw (truncated):</p><pre class="raw-snippet">${escapeHtml(robots.raw.slice(0, 800))}</pre>`;
  }
  return html;
}

function renderBackdoors(report) {
  const lines = [];
  if (report.backdoorPaths?.length) {
    lines.push(`<p class="section-head">${prefixHtml('warn')}reachable suspicious paths:</p>`);
    lines.push(
      '<ul class="path-list">' +
        report.backdoorPaths
          .map((b) => {
            const sev = b.patterns?.length ? 'crit' : 'warn';
            const note = b.note ? ` — ${b.note}` : '';
            return `<li>${prefixHtml(sev)}${escapeHtml(b.path)} [${b.status}]${escapeHtml(note)}</li>`;
          })
          .join('') +
        '</ul>',
    );
  } else {
    lines.push(lineHtml('ok', 'No suspicious backdoor paths returned HTTP 200 with PHP-like content.'));
  }
  if (report.backdoorPatterns?.length) {
    lines.push(`<p class="section-head">${prefixHtml('crit')}malware patterns in page bodies:</p>`);
    for (const p of report.backdoorPatterns) {
      lines.push(lineHtml('crit', `${p.label || p.id} @ ${p.url}`));
    }
  }
  const sensitive = (report.probes || []).filter(
    (p) => p.path && (p.path.includes('config') || p.path.includes('.env') || p.path.includes('debug')),
  );
  if (sensitive.length) {
    lines.push(`<p class="section-head">${prefixHtml('crit')}sensitive probes:</p>`);
    for (const p of sensitive) {
      lines.push(lineHtml('crit', `${p.path} → HTTP ${p.status} ${p.accessible ? '(accessible)' : ''}`));
    }
  }
  return lines.join('') || lineHtml('ok', 'Backdoor scan clean.');
}

function renderCrawl(pages) {
  if (!pages?.length) return lineHtml('info', 'No pages crawled.');
  const items = pages
    .slice(0, MAX_LIST)
    .map((p) => `<li>${escapeHtml(p.url)}${p.status ? ` [${p.status}]` : ''}${p.depth != null ? ` depth=${p.depth}` : ''}</li>`)
    .join('');
  const more = pages.length > MAX_LIST ? lineHtml('info', `… and ${pages.length - MAX_LIST} more URLs`) : '';
  return `<p class="line">${prefixHtml('info')}Crawled ${pages.length} page(s):</p><ul class="path-list">${items}</ul>${more}`;
}

function renderReport(report) {
  document.getElementById('summary').innerHTML = renderSummary(report);
  document.getElementById('wordpress-panel').innerHTML = renderWordPress(report.wordPress);
  document.getElementById('robots-panel').innerHTML = renderRobots(report.robots);
  document.getElementById('backdoor-panel').innerHTML = renderBackdoors(report);
  document.getElementById('admin-panel').innerHTML = renderFindings(report.admin, 'No admin/login findings.');
  document.getElementById('xss-panel').innerHTML = renderFindings(report.xss, 'No XSS findings.');
  document.getElementById('crawl-panel').innerHTML = renderCrawl(report.crawledPages);

  if (report.errors?.length) {
    const errBlock = report.errors.map((e) => lineHtml('crit', String(e))).join('');
    document.getElementById('summary').innerHTML += errBlock;
  }

  document.getElementById('raw-json').textContent = JSON.stringify(report, null, 2);
  resultsEl.classList.remove('hidden');
}

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  const url = urlInput.value.trim();
  if (!url) return;

  scanBtn.disabled = true;
  resultsEl.classList.add('hidden');
  clearProgress();
  appendProgress('Initializing scan subsystem…', 'info');
  appendProgress(`Target acquired: ${url}`, 'info');
  appendProgress('Dispatching probes to /api/scan …', 'info');

  try {
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/x-ndjson',
      },
      body: JSON.stringify({ url }),
    });

    const contentType = res.headers.get('content-type') || '';

    if (!res.ok) {
      if (contentType.includes('json')) {
        const data = await res.json().catch(() => ({}));
        appendProgress(data.error || `Scan failed (HTTP ${res.status})`, 'crit');
      } else {
        appendProgress(`Scan failed (HTTP ${res.status}). Run: npm run dev`, 'crit');
      }
      return;
    }

    if (!contentType.includes('ndjson')) {
      const data = await res.json();
      if (data.report) {
        for (const ev of data.progress || []) {
          if (ev.message) appendProgress(ev.message, 'info');
        }
        appendProgress('Scan complete. Rendering report…', 'ok');
        renderReport(data.report);
        return;
      }
      appendProgress(data.error || 'Unexpected response', 'crit');
      return;
    }

    const reader = res.body?.getReader();
    if (!reader) {
      appendProgress('No response stream', 'crit');
      return;
    }

    const decoder = new TextDecoder();
    let buffer = '';
    let report = null;

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split('\n');
      buffer = lines.pop() ?? '';
      for (const line of lines) {
        if (!line.trim()) continue;
        const ev = JSON.parse(line);
        if (ev.type === 'progress' && ev.message) appendProgress(ev.message, 'info');
        if (ev.type === 'error') appendProgress(ev.message || 'Scan error', 'crit');
        if (ev.type === 'complete') report = ev.report;
      }
    }

    if (!report) {
      appendProgress('Scan finished without report', 'crit');
      return;
    }
    appendProgress('Scan complete. Rendering report…', 'ok');
    renderReport(report);
  } catch (err) {
    appendProgress(err.message || 'Network error', 'crit');
  } finally {
    scanBtn.disabled = false;
  }
});
