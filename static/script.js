/**
 * PhishShield — Frontend JavaScript
 * Flask backend at http://localhost:5000
 * Handles: URL analysis, result rendering, history tab, stats
 */

const BACKEND_URL = 'http://localhost:5000';

// ── DOM refs ──────────────────────────────────────────────────────────────────
const urlInput      = document.getElementById('urlInput');
const analyzeBtn    = document.getElementById('analyzeBtn');
const clearBtn      = document.getElementById('clearBtn');
const resultEl      = document.getElementById('result');
const emptyResult   = document.getElementById('emptyResult');
const scoreValue    = document.getElementById('scoreValue');
const gaugeProgress = document.getElementById('gaugeProgress');
const riskLabel     = document.getElementById('riskLabel');
const riskDesc      = document.getElementById('riskDesc');
const reasonsList   = document.getElementById('reasonsList');
const signalCount   = document.getElementById('signalCount');
const breakdownGrid = document.getElementById('breakdownGrid');
const metaDomain    = document.getElementById('metaDomain');
const metaTime      = document.getElementById('metaTime');
const verdictBox    = document.getElementById('verdictBox');
const javaBadge     = document.getElementById('javaBadge');
const javaRisk      = document.getElementById('javaRisk');
const dbBadge       = document.getElementById('dbBadge');
const javaPanel     = document.getElementById('javaPanel');
const javaDetails   = document.getElementById('javaDetails');
const javaPanelRisk = document.getElementById('javaPanelRisk');
const statsRow      = document.getElementById('statsRow');

// ── Backend health check ───────────────────────────────────────────────────────
let backendAvailable = null;

async function checkBackend() {
  try {
    const r = await fetch(`${BACKEND_URL}/api/health`, { signal: AbortSignal.timeout(2000) });
    if (r.ok) {
      const data = await r.json();
      backendAvailable = true;
      const status = document.getElementById('shieldStatus');
      let statusParts = ['Flask Connected'];
      if (data.db_available)   statusParts.push('MySQL ✓');
      if (data.ml_available)   statusParts.push('ML ✓');
      if (data.java_available) statusParts.push('Java ✓');
      status.innerHTML = `<span class="dot" style="background:#00E676;box-shadow:0 0 8px #00E676"></span> ${statusParts.join(' · ')}`;
      status.style.borderColor = 'rgba(0,230,118,0.3)';

      if (data.db_available) loadStats();
    } else {
      setOfflineMode();
    }
  } catch {
    backendAvailable = false;
    setOfflineMode();
  }
}

function setOfflineMode() {
  backendAvailable = false;
  const status = document.getElementById('shieldStatus');
  status.innerHTML = '<span class="dot" style="background:#FFAB00;box-shadow:0 0 8px #FFAB00"></span> Offline Mode';
  status.style.borderColor = 'rgba(255,171,0,0.3)';
}

checkBackend();
setInterval(checkBackend, 15000);

// ── Tab switching ──────────────────────────────────────────────────────────────
function switchTab(tab) {
  const tabs = ['analyzer', 'history'];
  tabs.forEach(t => {
    document.getElementById(`tab${t.charAt(0).toUpperCase()+t.slice(1)}`).classList.toggle('hidden', t !== tab);
    document.getElementById(`nav${t.charAt(0).toUpperCase()+t.slice(1)}`).classList.toggle('active', t === tab);
  });
  if (tab === 'history') loadHistory();
}

// ── Stats ─────────────────────────────────────────────────────────────────────
async function loadStats() {
  try {
    const r = await fetch(`${BACKEND_URL}/api/stats`);
    if (!r.ok) return;
    const { stats, db_available } = await r.json();
    if (!db_available || !stats || !stats.total_scans) return;
    statsRow.classList.remove('hidden');
    document.getElementById('statTotal').textContent  = stats.total_scans  ?? '—';
    document.getElementById('statAvg').textContent    = stats.avg_score    ? stats.avg_score + '/100' : '—';
    document.getElementById('statHigh').textContent   = stats.high_risk    ?? '—';
    document.getElementById('statMedium').textContent = stats.medium_risk  ?? '—';
    document.getElementById('statLow').textContent    = stats.low_risk     ?? '—';
  } catch { /* stats are optional */ }
}

// ── History ───────────────────────────────────────────────────────────────────
async function loadHistory() {
  const loading  = document.getElementById('historyLoading');
  const tableEl  = document.getElementById('historyTable');
  const emptyEl  = document.getElementById('historyEmpty');
  const statusEl = document.getElementById('historyDbStatus');

  loading.style.display  = 'flex';
  tableEl.classList.add('hidden');
  emptyEl.classList.add('hidden');

  try {
    const r = await fetch(`${BACKEND_URL}/api/history?limit=50`);
    const { history, db_available } = await r.json();

    loading.style.display = 'none';
    statusEl.textContent = db_available ? '🗄️ MySQL connected' : '⚠️ MySQL unavailable';

    if (!history || history.length === 0) {
      emptyEl.classList.remove('hidden');
      return;
    }

    const tbody = document.getElementById('historyBody');
    tbody.innerHTML = history.map((h, i) => {
      const levelClass = h.level === 'HIGH RISK' ? 'high' : h.level === 'MEDIUM RISK' ? 'medium' : 'low';
      const scoreColor = h.score >= 70 ? '#FF3B30' : h.score >= 35 ? '#FFAB00' : '#00E676';
      const dt = new Date(h.analyzed_at).toLocaleString();
      return `<tr>
        <td class="hist-time">#${h.id}</td>
        <td><span style="font-family:'JetBrains Mono',monospace;font-size:11px">${escHtml(h.hostname)}</span></td>
        <td><span class="hist-score" style="color:${scoreColor}">${h.score}</span><span style="color:var(--muted);font-size:10px">/100</span></td>
        <td><span class="hist-badge ${levelClass}">${h.level}</span></td>
        <td class="hist-time">${h.ml_score != null ? h.ml_score : '—'}</td>
        <td class="hist-time">${h.java_entropy != null ? h.java_entropy.toFixed(2) : '—'}</td>
        <td class="hist-time">${dt}</td>
      </tr>`;
    }).join('');

    tableEl.classList.remove('hidden');
  } catch {
    loading.style.display = 'none';
    statusEl.textContent = '⚠️ Could not load history';
    emptyEl.classList.remove('hidden');
  }
}

// ── Render result ──────────────────────────────────────────────────────────────
function render(result) {
  if (!result) return;

  if (result.error) {
    resultEl.classList.remove('hidden'); emptyResult.style.display = 'none';
    scoreValue.textContent = '—'; gaugeProgress.style.stroke = '#FFAB00';
    riskLabel.textContent = 'INVALID'; riskLabel.className = 'gauge-risk risk-medium';
    riskDesc.textContent = result.error; return;
  }

  resultEl.classList.remove('hidden');
  emptyResult.style.display = 'none';

  // Animate gauge
  const circumference = 2 * Math.PI * 70;
  const offset = circumference - (result.score / 100) * circumference;
  gaugeProgress.style.transition = 'none';
  gaugeProgress.style.strokeDashoffset = circumference;
  gaugeProgress.style.stroke = result.color;
  void gaugeProgress.getBoundingClientRect();
  gaugeProgress.style.transition = 'stroke-dashoffset 1s cubic-bezier(0.34,1.56,0.64,1), stroke 0.3s';
  gaugeProgress.style.strokeDashoffset = offset;

  // Count-up score
  let cur = 0;
  const target = result.score;
  const step = Math.max(1, Math.ceil(target / 30));
  clearInterval(render._timer);
  render._timer = setInterval(() => {
    cur = Math.min(target, cur + step);
    scoreValue.textContent = cur;
    scoreValue.style.color = result.color;
    if (cur >= target) clearInterval(render._timer);
  }, 18);

  riskLabel.textContent = result.level;
  riskLabel.className   = 'gauge-risk ' + (result.score >= 70 ? 'risk-high' : result.score >= 35 ? 'risk-medium' : 'risk-low');
  riskDesc.textContent  = result.desc;
  metaDomain.textContent = '◉ ' + (result.hostname || '—');
  metaTime.textContent   = new Date().toLocaleTimeString();

  // Java badge
  const javaData = result.java;
  if (javaData && javaData.risk) {
    javaBadge.classList.remove('hidden');
    javaRisk.textContent = `Java: ${javaData.risk} (entropy ${javaData.entropy})`;
    renderJavaPanel(javaData);
  } else {
    javaBadge.classList.add('hidden');
    javaPanel.classList.add('hidden');
  }

  // DB badge
  if (result.scan_id) {
    dbBadge.textContent = `🗄️ Saved to MySQL #${result.scan_id}`;
    dbBadge.classList.remove('hidden');
  } else {
    dbBadge.classList.add('hidden');
  }

  // Signals
  const triggered = (result.reasons || []).filter(r => r.type === 'triggered').length;
  signalCount.textContent = `${triggered}/${(result.reasons || []).length} signals`;
  reasonsList.innerHTML = (result.reasons || []).map(r => `
    <li class="${r.type}">
      <span class="reason-icon">${r.icon}</span>
      <span class="reason-text">${r.text}</span>
      ${r.points ? `<span class="reason-points">+${r.points}</span>` : ''}
    </li>
  `).join('');

  // Breakdown bars
  breakdownGrid.innerHTML = (result.breakdown || []).map(b => {
    const pct = b.max ? (b.pts / b.max * 100) : 0;
    const col = b.pts === 0 ? '#00E676' : b.pts / b.max >= 0.6 ? '#FF3B30' : '#FFAB00';
    return `<div class="breakdown-item">
      <div class="breakdown-item-head"><span>${b.name}</span><span class="badge-points" style="background:${col}22;color:${col};border:1px solid ${col}33">${b.pts}/${b.max}</span></div>
      <div class="breakdown-bar"><div class="breakdown-fill" style="width:${pct}%;background:${col}"></div></div>
    </div>`;
  }).join('');

  // Verdict
  if (result.score >= 70) {
    verdictBox.className = 'verdict danger';
    verdictBox.textContent = '⛔ HIGH RISK — Do not visit. Close the tab and report the link. If you clicked, change passwords immediately.';
  } else if (result.score >= 35) {
    verdictBox.className = 'verdict warn';
    verdictBox.textContent = '⚠️ MEDIUM RISK — Suspicious. Verify the domain letter-by-letter and confirm via official site.';
  } else {
    verdictBox.className = 'verdict safe';
    verdictBox.textContent = '✓ LOW RISK — No strong phishing signals. Still verify the sender before entering sensitive data.';
  }

  // Refresh stats after each scan
  loadStats();
}

function renderJavaPanel(java) {
  javaPanel.classList.remove('hidden');
  const rc = java.risk === 'HIGH' ? '#FF3B30' : java.risk === 'MEDIUM' ? '#FFAB00' : '#00E676';
  javaPanelRisk.textContent = java.risk;
  javaPanelRisk.className   = `java-risk-badge ${java.risk}`;
  javaDetails.innerHTML = (java.details || []).map(d => `
    <div class="java-detail-item${d.flagged ? ' flagged' : ''}">
      <div class="java-detail-name">${escHtml(d.name)}</div>
      <div class="java-detail-value">${escHtml(d.value)}</div>
      <div class="java-detail-msg">${escHtml(d.message)}</div>
    </div>
  `).join('');
}

// ── Core analysis call ─────────────────────────────────────────────────────────
async function doAnalyze() {
  const val = urlInput.value.trim();
  if (!val) {
    urlInput.focus();
    urlInput.parentElement.style.borderColor = '#FF3B30';
    setTimeout(() => urlInput.parentElement.style.borderColor = '', 1200);
    return;
  }
  analyzeBtn.innerHTML = '<span>Analyzing…</span>';
  analyzeBtn.disabled = true;

  try {
    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), 12000); // longer timeout for Java+WHOIS
    const resp = await fetch(`${BACKEND_URL}/api/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: val }),
      signal: controller.signal
    });
    clearTimeout(t);
    if (resp.ok) {
      const data = await resp.json();
      render(data);
      backendAvailable = true;
    } else {
      const err = await resp.json().catch(() => ({}));
      render({ error: err.error || `Server error ${resp.status}`, score: 0 });
    }
  } catch (e) {
    if (e.name === 'AbortError') {
      render({ error: 'Request timed out — Flask backend may be slow (WHOIS/Java). Try again.', score: 0 });
    } else {
      render({ error: 'Could not reach Flask backend at ' + BACKEND_URL, score: 0 });
    }
  } finally {
    analyzeBtn.innerHTML = '<span>Analyze</span><span class="btn-arrow">→</span>';
    analyzeBtn.disabled = false;
  }
}

// ── Events ────────────────────────────────────────────────────────────────────
analyzeBtn.addEventListener('click', doAnalyze);
urlInput.addEventListener('keydown', e => { if (e.key === 'Enter') doAnalyze(); });
urlInput.addEventListener('input', () => {
  clearBtn.classList.toggle('visible', urlInput.value.length > 0);
  if (urlInput.value.length === 0) {
    resultEl.classList.add('hidden');
    emptyResult.style.display = '';
  }
});
clearBtn.addEventListener('click', () => {
  urlInput.value = ''; clearBtn.classList.remove('visible');
  resultEl.classList.add('hidden'); emptyResult.style.display = '';
  javaBadge.classList.add('hidden'); dbBadge.classList.add('hidden');
  javaPanel.classList.add('hidden');
  urlInput.focus();
});
document.querySelectorAll('.chip').forEach(c => {
  c.addEventListener('click', () => {
    urlInput.value = c.dataset.url;
    clearBtn.classList.add('visible');
    doAnalyze();
  });
});

document.getElementById('copyBtn').addEventListener('click', () => {
  const score = scoreValue.textContent;
  const level = riskLabel.textContent;
  const host  = metaDomain.textContent;
  const signals = [...reasonsList.querySelectorAll('li.triggered')]
    .map(li => '- ' + li.querySelector('.reason-text').innerText.replace(/<[^>]*>/g, ''))
    .join('\n') || '- No triggers';
  const txt = `PhishShield Report — ${host}
Risk Score: ${score}/100 (${level})
${verdictBox.textContent}

Triggered Signals:
${signals}

Analyzed: ${new Date().toLocaleString()}
Powered by Flask + Java + MySQL`;
  navigator.clipboard.writeText(txt).then(() => {
    const b = document.getElementById('copyBtn');
    const old = b.textContent; b.textContent = 'Copied!';
    setTimeout(() => b.textContent = old, 1500);
  });
});

// ── Utility ───────────────────────────────────────────────────────────────────
function escHtml(s) {
  return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
