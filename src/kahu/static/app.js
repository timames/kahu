/* Kahu PWA — Mobile-first security operations */

const API = '/api/m';
const TRIAGE_API = '/api/triage';
const INVEST_API = '/api/investigation';
const CONN_API = '/api/connectors';
const COMP_API = '/api/compliance';
const VULN_API = '/api/vulns';
const RECON_API = '/api/recon';
const ARSENAL_API = '/api/arsenal';
let currentScreen = 'glance';
let feedCards = [];
let feedRemaining = 0;

// ---- Navigation ----

function navigate(screen) {
  document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
  document.querySelectorAll('nav button').forEach(b => b.classList.remove('active'));
  document.getElementById('screen-' + screen).classList.add('active');
  document.querySelector(`nav button[data-screen="${screen}"]`)?.classList.add('active');
  currentScreen = screen;

  // Load data for screen
  if (screen === 'glance') loadGlance();
  if (screen === 'feed') loadFeed();
  if (screen === 'score') loadScore();
  if (screen === 'profile') loadProfile();
  if (screen === 'compliance') loadCompliance();
  if (screen === 'sources') loadSources();
  if (screen === 'vulns') loadVulns();
  if (screen === 'history') loadHistory();
  if (screen === 'recon') loadRecon();
  if (screen === 'settings') loadSettings();
}

// ---- API helpers ----

async function api(path, opts = {}) {
  try {
    const r = await fetch(path, {
      headers: { 'Content-Type': 'application/json', ...opts.headers },
      ...opts,
    });
    if (!r.ok) {
      const err = await r.json().catch(() => ({ detail: r.statusText }));
      throw new Error(err.detail || 'Request failed');
    }
    return r.json();
  } catch (e) {
    if (e.message === 'Failed to fetch') {
      return { _offline: true };
    }
    throw e;
  }
}

// ---- Glance Screen ----

async function loadGlance() {
  const el = document.getElementById('screen-glance');
  const data = await api(`${API}/glance`);

  if (data._offline) {
    el.querySelector('.glance-headline').textContent = 'Offline. Showing last known state.';
    return;
  }

  const orb = el.querySelector('.glance-orb');
  orb.className = 'glance-orb ' + data.color;
  el.querySelector('.glance-count').textContent = data.count;
  el.querySelector('.glance-label').textContent = data.count === 1 ? 'alert' : 'alerts';
  el.querySelector('.glance-headline').textContent = data.headline;

  // Update nav badge
  const feedBadge = document.getElementById('feed-badge');
  if (data.count > 0) {
    feedBadge.textContent = data.count > 99 ? '99+' : data.count;
    feedBadge.style.display = 'flex';
  } else {
    feedBadge.style.display = 'none';
  }

  // Breakdown
  const bd = el.querySelector('.glance-breakdown');
  const items = ['critical', 'high', 'medium', 'low', 'info'];
  const colors = {
    critical: 'var(--sev-critical)',
    high: 'var(--sev-high)',
    medium: 'var(--sev-medium)',
    low: 'var(--sev-low)',
    info: 'var(--sev-info)',
  };
  bd.innerHTML = items.map(s =>
    `<div class="breakdown-item">
      <div class="breakdown-dot" style="background:${colors[s]}"></div>
      <span class="breakdown-count">${data.breakdown[s] || 0}</span>
      <span class="breakdown-label">${s}</span>
    </div>`
  ).join('');
}

// ---- Feed Screen ----

async function loadFeed() {
  const data = await api(`${API}/feed?limit=50`);
  if (data._offline) return;

  feedCards = data.cards;
  feedRemaining = data.remaining;

  // Show/hide batch ack button
  const batchBtn = document.getElementById('batch-ack-btn');
  if (batchBtn) batchBtn.style.display = feedCards.length > 0 ? '' : 'none';

  renderFeed();
}

async function batchAcknowledge() {
  const total = feedCards.length + feedRemaining;
  if (!confirm(`Acknowledge all ${total} pending alerts?`)) return;

  const btn = document.getElementById('batch-ack-btn');
  btn.disabled = true;
  btn.textContent = 'Working...';

  try {
    const result = await api(`${API}/feed/batch-acknowledge`, {
      method: 'POST',
      body: JSON.stringify({ analyst: getAnalystName() }),
    });

    showXpToast(result.xp_earned, `${result.acknowledged} alerts acknowledged`);
    feedCards = [];
    feedRemaining = 0;
    btn.style.display = 'none';
    renderFeed();

    // Refresh glance badge
    const feedBadge = document.getElementById('feed-badge');
    if (feedBadge) feedBadge.style.display = 'none';
  } catch (err) {
    alert('Batch acknowledge failed: ' + err.message);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Ack All';
  }
}

function renderFeed() {
  const stack = document.getElementById('card-stack');
  const remaining = document.getElementById('feed-remaining');
  const hint = document.getElementById('swipe-hint');

  if (feedCards.length === 0) {
    stack.innerHTML = `
      <div class="feed-empty">
        <div class="feed-empty-icon">
          <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="var(--green)" stroke-width="2">
            <polyline points="20 6 9 17 4 12"></polyline>
          </svg>
        </div>
        <h3>All clear</h3>
        <p style="text-align:center;color:var(--text-dim)">No alerts need your attention.<br>Check back later.</p>
      </div>`;
    remaining.textContent = '';
    hint.style.display = 'none';
    return;
  }

  hint.style.display = 'flex';
  remaining.textContent = `${feedCards.length + feedRemaining} remaining`;

  // Render top 3 cards (stack effect)
  const visible = feedCards.slice(0, 3);
  stack.innerHTML = '';

  visible.forEach((card, i) => {
    const el = document.createElement('div');
    el.className = 'card';
    el.style.zIndex = 10 - i;
    el.style.transform = `scale(${1 - i * 0.03}) translateY(${i * 8}px)`;
    el.style.opacity = i === 0 ? 1 : 0.7 - i * 0.2;

    const timeAgo = formatTimeAgo(new Date(card.timestamp));
    const actions = (card.recommended_actions || []).slice(0, 3);

    // AI verdict badge
    const verdictLabels = {
      true_positive: { text: 'AI: Confirm', cls: 'ai-confirm', arrow: '→' },
      acknowledge: { text: 'AI: Acknowledge', cls: 'ai-dismiss', arrow: '←' },
      false_positive: { text: 'AI: Acknowledge', cls: 'ai-dismiss', arrow: '←' },
      escalate: { text: 'AI: Escalate', cls: 'ai-escalate', arrow: '↑' },
    };
    const aiV = card.ai_verdict && verdictLabels[card.ai_verdict];
    const confidencePct = Math.round((card.ai_confidence || 0) * 100);

    el.innerHTML = `
      <div class="swipe-overlay left">ACKNOWLEDGE</div>
      <div class="swipe-overlay right">CONFIRM</div>
      <div class="swipe-overlay up">ESCALATE</div>
      <div class="card-top-row">
        <span class="card-sev ${card.severity}">${card.severity}</span>
        ${aiV ? `<span class="ai-badge ${aiV.cls}" title="${confidencePct}% confidence">${aiV.arrow} ${aiV.text}</span>` : ''}
      </div>
      <h3 class="card-title">${escHtml(card.title)}</h3>
      <div class="card-meta">
        ${card.agent ? `<span class="card-meta-item">${escHtml(card.agent)}</span>` : ''}
        ${card.source_ip ? `<span class="card-meta-item">${escHtml(card.source_ip)}</span>` : ''}
        <span class="card-meta-item">${timeAgo}</span>
        ${confidencePct > 0 ? `<span class="card-meta-item">${confidencePct}% conf</span>` : ''}
      </div>
      ${card.explanation ? `
        <details class="card-details">
          <summary>Why</summary>
          <p class="card-explanation">${escHtml(card.explanation)}</p>
          ${actions.length > 0 ? `<ul class="card-actions-list">${actions.map(a => `<li>${escHtml(a)}</li>`).join('')}</ul>` : ''}
        </details>
      ` : actions.length > 0 ? `
        <details class="card-details">
          <summary>Actions</summary>
          <ul class="card-actions-list">${actions.map(a => `<li>${escHtml(a)}</li>`).join('')}</ul>
        </details>
      ` : ''}
      <div class="card-buttons">
        <button class="card-btn btn-fp" onclick="event.stopPropagation();doSwipe(feedCards.find(c=>c.id==='${card.id}'),'left')">Acknowledge</button>
        <button class="card-btn btn-esc" onclick="event.stopPropagation();doSwipe(feedCards.find(c=>c.id==='${card.id}'),'up')">Escalate</button>
        <button class="card-btn btn-tp" onclick="event.stopPropagation();doSwipe(feedCards.find(c=>c.id==='${card.id}'),'right')">Confirm</button>
      </div>
    `;

    if (i === 0) setupSwipe(el, card);
    stack.appendChild(el);
  });
}

// ---- Swipe Gesture Engine ----

function setupSwipe(el, card) {
  let startX = 0, startY = 0, dx = 0, dy = 0, swiping = false;

  const overlayL = el.querySelector('.swipe-overlay.left');
  const overlayR = el.querySelector('.swipe-overlay.right');
  const overlayU = el.querySelector('.swipe-overlay.up');

  function onStart(e) {
    const t = e.touches ? e.touches[0] : e;
    startX = t.clientX;
    startY = t.clientY;
    swiping = true;
    el.style.transition = 'none';
  }

  function onMove(e) {
    if (!swiping) return;
    const t = e.touches ? e.touches[0] : e;
    dx = t.clientX - startX;
    dy = t.clientY - startY;

    // Determine dominant direction
    const absDx = Math.abs(dx);
    const absDy = Math.abs(dy);

    if (absDx > absDy) {
      // Horizontal swipe
      el.style.transform = `translateX(${dx}px) rotate(${dx * 0.05}deg)`;
      overlayL.style.opacity = dx < -30 ? Math.min(1, (-dx - 30) / 60) : 0;
      overlayR.style.opacity = dx > 30 ? Math.min(1, (dx - 30) / 60) : 0;
      overlayU.style.opacity = 0;
    } else if (dy < 0) {
      // Upward swipe
      el.style.transform = `translateY(${dy}px)`;
      overlayU.style.opacity = dy < -30 ? Math.min(1, (-dy - 30) / 60) : 0;
      overlayL.style.opacity = 0;
      overlayR.style.opacity = 0;
    }

    e.preventDefault();
  }

  function onEnd() {
    if (!swiping) return;
    swiping = false;
    el.style.transition = 'transform 0.3s ease, opacity 0.3s ease';

    const absDx = Math.abs(dx);
    const absDy = Math.abs(dy);
    const threshold = 80;

    if (absDx > threshold && absDx > absDy) {
      // Horizontal swipe completed
      const dir = dx > 0 ? 'right' : 'left';
      el.style.transform = `translateX(${dx > 0 ? 400 : -400}px) rotate(${dx > 0 ? 20 : -20}deg)`;
      el.style.opacity = '0';
      doSwipe(card, dir);
    } else if (dy < -threshold && absDy > absDx) {
      // Upward swipe completed
      el.style.transform = 'translateY(-400px)';
      el.style.opacity = '0';
      doSwipe(card, 'up');
    } else {
      // Snap back
      el.style.transform = '';
      overlayL.style.opacity = 0;
      overlayR.style.opacity = 0;
      overlayU.style.opacity = 0;
    }

    dx = 0;
    dy = 0;
  }

  el.addEventListener('touchstart', onStart, { passive: true });
  el.addEventListener('touchmove', onMove, { passive: false });
  el.addEventListener('touchend', onEnd);
  el.addEventListener('mousedown', onStart);
  el.addEventListener('mousemove', onMove);
  el.addEventListener('mouseup', onEnd);
  el.addEventListener('mouseleave', onEnd);
}

async function doSwipe(card, direction) {
  // Haptic feedback
  if (navigator.vibrate) navigator.vibrate(50);

  try {
    const result = await api(`${API}/feed/${card.id}/swipe`, {
      method: 'POST',
      body: JSON.stringify({ direction, analyst: getAnalystName() }),
    });

    // Remove card from stack
    feedCards = feedCards.filter(c => c.id !== card.id);

    // Show XP toast
    showXpToast(result.xp_earned, result.ticket_id ? 'Ticket created' : null);

    // If escalated/confirmed and ticket created, show ticket confirmation
    if (result.ticket_id && (direction === 'up' || direction === 'right')) {
      setTimeout(() => showTicketConfirmation(result, card, direction), 400);
    }

    // Re-render
    setTimeout(renderFeed, 300);

    // Update glance badge
    loadGlanceBadge();
  } catch (e) {
    // Re-render to restore card
    renderFeed();
  }
}

// ---- Ticket Confirmation Modal ----

function showTicketConfirmation(result, card, direction) {
  const isEscalate = direction === 'up';
  const typeLabel = isEscalate ? 'Investigation' : 'Incident';
  const typeIcon = isEscalate ? '🔍' : '🚨';
  const actionColor = isEscalate ? 'var(--yellow)' : 'var(--red)';
  const tipText = isEscalate
    ? 'This alert needs deeper analysis. Review evidence and close when investigation is complete.'
    : 'Confirmed threat. Take remediation action, then close the incident ticket.';

  const modal = document.getElementById('coach-modal');
  modal.querySelector('.coach-title').textContent = `${typeLabel} Opened`;
  modal.querySelector('.coach-body').innerHTML = `
    <div style="text-align:center;padding:8px 0">
      <div style="font-size:32px;margin-bottom:8px">${typeIcon}</div>
      <div style="color:${actionColor};font-weight:600;font-size:15px;margin-bottom:4px">${typeLabel}</div>
      <div style="font-size:14px;margin-bottom:12px">${escHtml(card.title).substring(0, 80)}</div>
      <div style="background:var(--card);border-radius:8px;padding:10px;font-size:13px;text-align:left">
        <div><strong>Type:</strong> <span style="color:${actionColor}">${typeLabel}</span></div>
        <div style="margin-top:4px"><strong>Severity:</strong> <span class="card-sev ${card.severity}" style="font-size:11px;padding:2px 6px">${card.severity}</span></div>
        <div style="margin-top:4px"><strong>Agent:</strong> ${escHtml(card.agent || 'unknown')}</div>
        <div style="margin-top:4px"><strong>Status:</strong> Open — assigned to you</div>
      </div>
      <button onclick="closeCoach();navigate('score')" style="margin-top:14px;padding:8px 20px;background:var(--accent);color:var(--bg);border:none;border-radius:8px;font-weight:600;cursor:pointer">
        View in Tickets
      </button>
    </div>
  `;
  modal.querySelector('.coach-tip-text').textContent = tipText;
  modal.querySelector('.coach-controls').innerHTML = '';
  modal.classList.add('active');
}

// ---- Coach Modal ----

async function showCoach(alertId) {
  try {
    const data = await api(`${API}/coach/${alertId}`);
    if (data._offline) return;

    const modal = document.getElementById('coach-modal');
    modal.querySelector('.coach-title').textContent = data.lesson_title;
    modal.querySelector('.coach-body').innerHTML = escHtml(data.lesson_body);
    modal.querySelector('.coach-tip-text').textContent = data.next_tip;

    const tags = modal.querySelector('.coach-controls');
    tags.innerHTML = data.controls_satisfied.map(c =>
      `<span class="coach-control-tag">${escHtml(c)}</span>`
    ).join('');

    modal.classList.add('active');
  } catch {
    // Silent fail — coach is optional
  }
}

function closeCoach() {
  document.getElementById('coach-modal').classList.remove('active');
}

// ---- Score Screen ----

async function loadScore() {
  const data = await api(`${API}/score?analyst=${encodeURIComponent(getAnalystName())}`);
  if (data._offline) return;

  const el = document.getElementById('screen-score');

  // Ring
  const circumference = 2 * Math.PI * 72; // r=72
  const offset = circumference - (data.score / 100) * circumference;
  const ring = el.querySelector('.score-ring-fill');
  ring.style.strokeDasharray = circumference;
  ring.style.strokeDashoffset = offset;

  // Ring color
  if (data.score >= 70) ring.style.stroke = 'var(--green)';
  else if (data.score >= 40) ring.style.stroke = 'var(--yellow)';
  else ring.style.stroke = 'var(--red)';

  el.querySelector('.score-number').textContent = data.score;
  const trendEl = el.querySelector('.score-trend');
  trendEl.className = 'score-trend ' + data.trend;
  const arrows = { up: 'Trending up', down: 'Trending down', steady: 'Holding steady' };
  trendEl.textContent = arrows[data.trend];

  // Stats
  el.querySelector('.stat-xp').textContent = data.xp;
  el.querySelector('.stat-streak').textContent = data.streak_days;
  el.querySelector('.stat-today').textContent = data.alerts_handled_today;
  el.querySelector('.stat-response').textContent = data.avg_response_minutes ? data.avg_response_minutes + 'm' : '--';

  // Badges
  const badgeList = el.querySelector('.badge-list');
  if (data.badges.length > 0) {
    badgeList.innerHTML = data.badges.map(b =>
      `<span class="badge-item" title="${escHtml(b.description)}">${escHtml(b.name)}</span>`
    ).join('');
  } else {
    badgeList.innerHTML = '<span class="badge-item" style="opacity:0.4">Start reviewing alerts to earn badges</span>';
  }

  // Weekly
  el.querySelector('.weekly-text').textContent = data.weekly_summary;

  // Tickets
  document.getElementById('ticket-count').textContent = data.open_tickets > 0 ? `(${data.open_tickets})` : '';

  const tickets = await loadTickets();
  const ticketList = document.getElementById('ticket-list');
  if (!tickets || tickets._offline || tickets.length === 0) {
    ticketList.innerHTML = '<p style="color:var(--text-dim);font-size:13px;padding:8px 0">No open tickets. Confirm or escalate alerts to create tickets.</p>';
  } else if (ticketViewMode === 'table') {
    ticketList.innerHTML = `
      <div class="ticket-table">
        <div class="ticket-table-header">
          <span class="tt-type">Type</span>
          <span class="tt-sev">Sev</span>
          <span class="tt-title">Title</span>
          <span class="tt-time">Age</span>
          <span class="tt-action"></span>
        </div>
        ${tickets.map(t => {
          const isInv = t.ticket_type === 'investigation';
          const typeLabel = isInv ? 'INV' : 'INC';
          const typeColor = isInv ? 'var(--yellow)' : 'var(--red)';
          return `
          <div class="ticket-table-row" onclick="openTicket('${t.id}')" style="cursor:pointer">
            <span class="tt-type" style="color:${typeColor};font-weight:600">${typeLabel}</span>
            <span class="tt-sev"><span class="card-sev ${t.severity}" style="font-size:10px;padding:1px 5px">${t.severity}</span></span>
            <span class="tt-title">${escHtml(t.title).substring(0, 50)}</span>
            <span class="tt-time">${formatTimeAgo(new Date(t.created_at))}</span>
            <span class="tt-action"><button class="ticket-close-btn" onclick="event.stopPropagation();closeTicket('${t.id}')">Close</button></span>
          </div>`;
        }).join('')}
      </div>`;
  } else {
    ticketList.innerHTML = tickets.map(t => {
      const isInvestigation = t.ticket_type === 'investigation';
      const typeLabel = isInvestigation ? 'Investigation' : 'Incident';
      const typeColor = isInvestigation ? 'var(--yellow)' : 'var(--red)';
      return `
      <div class="ticket-card" onclick="openTicket('${t.id}')" style="cursor:pointer">
        <div class="ticket-sev ${t.severity}"></div>
        <div class="ticket-info">
          <div class="ticket-type" style="color:${typeColor};font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.5px">${typeLabel}</div>
          <div class="ticket-title">${escHtml(t.title)}</div>
          <div class="ticket-meta">${escHtml(t.severity)} · ${formatTimeAgo(new Date(t.created_at))}</div>
        </div>
        <button class="ticket-close-btn" onclick="event.stopPropagation();closeTicket('${t.id}')">Close</button>
      </div>`;
    }).join('');
  }
}

// ---- Investigate Screen ----

async function sendMessage() {
  const input = document.getElementById('chat-input');
  const msg = input.value.trim();
  if (!msg) return;

  input.value = '';
  addChatMsg(msg, 'user');

  const btn = document.getElementById('chat-send');
  btn.disabled = true;

  try {
    const data = await api(`${INVEST_API}/query`, {
      method: 'POST',
      body: JSON.stringify({ message: msg }),
    });

    if (data._offline) {
      addChatMsg('Offline. Try again when connected.', 'system');
    } else if (data.degraded) {
      addChatMsg(data.response, 'system');
    } else {
      addChatMsg(data.response, 'assistant');
    }
  } catch (e) {
    addChatMsg('Something went wrong. Try again.', 'system');
  }

  btn.disabled = false;
}

function addChatMsg(text, role) {
  const container = document.getElementById('chat-messages');
  const div = document.createElement('div');
  div.className = 'chat-msg ' + role;
  div.textContent = text;
  container.appendChild(div);
  container.scrollTop = container.scrollHeight;
}

// ---- Settings Screen ----

async function loadSettings() {
  const el = document.getElementById('screen-settings');

  // Check arsenal mode
  checkArsenalMode();

  // Restore tolerance slider
  const saved = localStorage.getItem('kahu_tolerance') || '2';
  const slider = document.getElementById('tolerance-slider');
  if (slider) {
    slider.value = saved;
    setTolerance(saved);
  }

  // Load geo threat feed
  loadGeoFeed();

  // Pipeline status
  try {
    const status = await api(`${TRIAGE_API}/status`);
    if (!status._offline) {
      setStatus('status-wazuh', status.wazuh_api_healthy);
      setStatus('status-indexer', status.wazuh_indexer_healthy);
      setStatus('status-ollama', status.ollama_healthy);
      setStatus('status-pipeline', !status.pipeline_degraded);
    }
  } catch {
    // Leave as unknown
  }

  // Greenbone scanner status
  try {
    const gvm = await api(`${VULN_API}/health`);
    if (!gvm._offline) {
      setStatus('status-greenbone', gvm.online);
    }
  } catch {
    // Leave as unknown
  }
}

// ---- Exposure Tolerance ----

const TOLERANCE_INFO = {
  '1': {
    label: 'Conservative',
    desc: 'Maximum protection. Auto-block unknown geolocations, flag all anomalies, tighter thresholds. Best for regulated environments (HIPAA, CMMC, ITAR).',
  },
  '2': {
    label: 'Balanced',
    desc: 'Default posture. Flag suspicious activity, allow known-good patterns. Good for most organizations.',
  },
  '3': {
    label: 'Aggressive',
    desc: 'Minimal friction. Only flag confirmed threats and high-confidence detections. More noise reduction, slightly higher risk tolerance.',
  },
};

function setTolerance(val) {
  localStorage.setItem('kahu_tolerance', val);
  const info = TOLERANCE_INFO[val];

  // Update labels
  document.querySelectorAll('.tolerance-label').forEach(l => {
    l.classList.toggle('active', l.dataset.val === val);
  });

  // Update description
  document.getElementById('tolerance-desc').textContent = info.desc;

  // Sync to backend
  api(`${API}/tolerance`, {
    method: 'PUT',
    body: JSON.stringify({ level: parseInt(val) }),
  }).catch(() => {});
}

// ---- Auto-Triage ----

async function runAutoTriage() {
  const btn = document.getElementById('auto-triage-btn');
  const resultEl = document.getElementById('auto-triage-result');
  btn.disabled = true;
  btn.textContent = 'Running...';
  resultEl.innerHTML = '';

  try {
    const data = await api(`${API}/auto-triage`, { method: 'POST' });
    if (data._offline) {
      resultEl.innerHTML = '<span style="color:var(--red)">Offline</span>';
      return;
    }

    resultEl.innerHTML = `
      <div class="auto-triage-stats">
        <span>${data.processed} processed</span>
        <span style="color:var(--text-dim)">·</span>
        <span style="color:var(--green)">${data.auto_acknowledged} acknowledged</span>
        <span style="color:var(--text-dim)">·</span>
        <span style="color:var(--yellow)">${data.auto_confirmed} confirmed</span>
        <span style="color:var(--text-dim)">·</span>
        <span>${data.remaining} remaining for you</span>
      </div>
    `;

    if (data.auto_dismissed + data.auto_confirmed > 0) {
      showXpToast(0, `AI handled ${data.auto_dismissed + data.auto_confirmed} alerts`);
    }
  } catch (e) {
    resultEl.innerHTML = `<span style="color:var(--red)">${e.message || 'Failed'}</span>`;
  }

  btn.disabled = false;
  btn.textContent = 'Run Auto-Triage Now';
}

// ---- Geo Threat Feed ----

async function loadGeoFeed() {
  const feedEl = document.getElementById('geo-feed');

  // Pull geo data from alert analysis
  try {
    const data = await api(`${API}/glance`);
    if (data._offline) {
      feedEl.innerHTML = '<p style="color:var(--text-dim);font-size:13px">Offline</p>';
      return;
    }

    // Analyze recent alerts for geo patterns
    const geoData = await api(`${API}/feed?limit=50`);
    if (geoData._offline || !geoData.cards) return;
    if (geoData.cards.length === 0) {
      feedEl.innerHTML = '<p style="color:var(--text-dim);font-size:13px">No alerts to analyze. Geo intel will appear when events arrive.</p>';
      return;
    }

    // Extract source IPs and identify geo patterns
    const geoThreats = analyzeGeoThreats(geoData.cards);

    if (geoThreats.length === 0) {
      feedEl.innerHTML = '<p style="color:var(--text-dim);font-size:13px">No geo-based threats detected. Your perimeter looks clean.</p>';
      return;
    }

    feedEl.innerHTML = geoThreats.map(t => `
      <div class="geo-item">
        <div class="geo-flag">${t.flag}</div>
        <div class="geo-info">
          <div class="geo-title">${escHtml(t.title)}</div>
          <div class="geo-detail">${escHtml(t.detail)}</div>
        </div>
        <button class="geo-action${t.applied ? ' applied' : ''}"
                onclick="applyGeoRule('${escHtml(t.id)}')">${t.applied ? 'Applied' : 'Block'}</button>
      </div>
    `).join('');
  } catch {
    feedEl.innerHTML = '<p style="color:var(--text-dim);font-size:13px">Unable to load threat intel</p>';
  }
}

function analyzeGeoThreats(cards) {
  // Group alerts by source IP prefix to detect geo patterns
  const ipCounts = {};
  for (const card of cards) {
    if (!card.source_ip) continue;
    const prefix = card.source_ip.split('.').slice(0, 2).join('.');
    if (!ipCounts[prefix]) {
      ipCounts[prefix] = { count: 0, ips: new Set(), severities: [] };
    }
    ipCounts[prefix].count++;
    ipCounts[prefix].ips.add(card.source_ip);
    ipCounts[prefix].severities.push(card.severity);
  }

  // Generate threat recommendations for high-volume sources
  const threats = [];
  const applied = JSON.parse(localStorage.getItem('kahu_geo_rules') || '[]');

  for (const [prefix, data] of Object.entries(ipCounts)) {
    if (data.count < 3) continue;
    const hasCritical = data.severities.includes('critical') || data.severities.includes('high');
    threats.push({
      id: prefix,
      flag: hasCritical ? '🔴' : '🟡',
      title: `Block ${prefix}.x.x subnet`,
      detail: `${data.count} alerts from ${data.ips.size} IPs — ${data.severities.filter(s => s === 'critical' || s === 'high').length} high/critical`,
      applied: applied.includes(prefix),
    });
  }

  // Sort by count descending
  threats.sort((a, b) => b.count - a.count);
  return threats.slice(0, 10);
}

function applyGeoRule(id) {
  const applied = JSON.parse(localStorage.getItem('kahu_geo_rules') || '[]');
  if (!applied.includes(id)) {
    applied.push(id);
    localStorage.setItem('kahu_geo_rules', JSON.stringify(applied));
  }
  // Re-render
  loadGeoFeed();
  if (navigator.vibrate) navigator.vibrate(30);
}

function setStatus(id, ok) {
  const el = document.getElementById(id);
  el.querySelector('.status-dot').className = 'status-dot ' + (ok ? 'ok' : 'fail');
  el.querySelector('.settings-item-value span').textContent = ok ? 'Connected' : 'Offline';
}

async function refreshServices() {
  const btn = document.querySelector('.service-refresh-btn');
  btn.disabled = true;
  btn.querySelector('svg').style.animation = 'spin 1s linear infinite';
  await loadSettings();
  btn.disabled = false;
  btn.querySelector('svg').style.animation = '';
}

async function restartService(service) {
  const btns = document.querySelectorAll('.service-action-btn');
  const btn = [...btns].find(b => b.textContent.toLowerCase().includes(service === 'reeval' ? 're-eval' : service));
  if (btn) { btn.disabled = true; btn.textContent = 'Restarting...'; }

  try {
    const result = await api(`${TRIAGE_API}/restart/${service}`, { method: 'POST' });
    if (result.status === 'ok') {
      showXpToast(0, result.message);
    } else {
      alert(result.message || 'Failed');
    }
  } catch (e) {
    alert(e.message || 'Failed');
  }

  // Refresh status after restart
  await loadSettings();
  if (btn) { btn.disabled = false; }
  // Restore button text
  const labels = { wazuh: 'Restart Wazuh', pipeline: 'Restart Pipeline', reeval: 'Run Re-evaluation' };
  if (btn) btn.textContent = labels[service] || service;
}

// ---- Glance badge (lightweight, for nav) ----

async function loadGlanceBadge() {
  try {
    const data = await api(`${API}/glance`);
    if (data._offline) return;
    const badge = document.getElementById('feed-badge');
    if (data.count > 0) {
      badge.textContent = data.count > 99 ? '99+' : data.count;
      badge.style.display = 'flex';
    } else {
      badge.style.display = 'none';
    }
  } catch { /* silent */ }
}

// ---- Themes ----

const THEMES = [
  { id: 'cyber',   name: 'Cyber',   colors: ['#00ffc8','#0a0e17','#00b894'], tag: 'free' },
  { id: 'lava',    name: 'Lava',    colors: ['#ff4d4d','#1a0a0a','#ff6b35'], tag: 'free' },
  { id: 'ocean',   name: 'Ocean',   colors: ['#0ea5e9','#0a1628','#06b6d4'], tag: 'free' },
  { id: 'stealth', name: 'Stealth', colors: ['#a0a0a0','#111111','#666666'], tag: 'free' },
  { id: 'sakura',  name: 'Sakura',  colors: ['#f472b6','#1a0a14','#e879a8'], tag: 'free' },
  { id: 'aurora',  name: 'Aurora',  colors: ['#a78bfa','#0a0e17','#34d399'], tag: 'free' },
];

// ---- Avatars ----

const AVATARS = [
  { id: 'shield',    emoji: '🛡️', name: 'Shield',    unlock: null },
  { id: 'hawk',      emoji: '🦅', name: 'Hawk',      unlock: null },
  { id: 'wolf',      emoji: '🐺', name: 'Wolf',      unlock: null },
  { id: 'dragon',    emoji: '🐉', name: 'Dragon',    unlock: 'Reach Sentinel rank' },
  { id: 'phoenix',   emoji: '🔥', name: 'Phoenix',   unlock: 'Reach Commander rank' },
  { id: 'guardian',  emoji: '⚔️', name: 'Guardian',  unlock: 'Reach Warden rank' },
  { id: 'owl',       emoji: '🦉', name: 'Owl',       unlock: '50 alerts triaged' },
  { id: 'lightning', emoji: '⚡', name: 'Lightning', unlock: '7-day streak' },
];

// ---- Ranks ----

const RANKS = [
  { name: 'Recruit',   minXp: 0,    badge: '🔰' },
  { name: 'Guardian',  minXp: 100,  badge: '🛡️' },
  { name: 'Sentinel',  minXp: 300,  badge: '⚔️' },
  { name: 'Commander', minXp: 700,  badge: '🎖️' },
  { name: 'Warden',    minXp: 1500, badge: '👑' },
];

function getRank(xp) {
  let rank = RANKS[0];
  for (const r of RANKS) {
    if (xp >= r.minXp) rank = r;
  }
  return rank;
}

function getNextRank(xp) {
  for (const r of RANKS) {
    if (xp < r.minXp) return r;
  }
  return null;
}

// ---- Profile Screen ----

async function loadProfile() {
  const data = await api(`${API}/score?analyst=${encodeURIComponent(getAnalystName())}`);
  if (data._offline) return;

  const totalXp = data.xp || 0;

  const rank = getRank(totalXp);
  const next = getNextRank(totalXp);

  // Name & rank
  document.getElementById('profile-name').textContent = getAnalystName();
  document.getElementById('profile-rank-title').textContent = rank.name;
  document.getElementById('profile-rank-badge').textContent = rank.badge;

  // XP bar
  if (next) {
    const progress = (totalXp - rank.minXp) / (next.minXp - rank.minXp);
    document.getElementById('profile-xp-fill').style.width = (progress * 100) + '%';
    document.getElementById('profile-xp-label').textContent = `${totalXp} / ${next.minXp} XP`;
  } else {
    document.getElementById('profile-xp-fill').style.width = '100%';
    document.getElementById('profile-xp-label').textContent = `${totalXp} XP — Max Rank`;
  }

  // Avatar
  const savedAvatar = localStorage.getItem('kahu_avatar') || 'shield';
  const currentAvatar = AVATARS.find(a => a.id === savedAvatar) || AVATARS[0];
  document.getElementById('profile-avatar').textContent = currentAvatar.emoji;

  // Render avatar grid
  const avatarGrid = document.getElementById('avatar-grid');
  avatarGrid.innerHTML = AVATARS.map(a => {
    const locked = a.unlock && !isAvatarUnlocked(a, rank, data);
    return `<div class="avatar-option ${a.id === savedAvatar ? 'selected' : ''} ${locked ? 'locked' : ''}"
                 onclick="${locked ? '' : `selectAvatar('${a.id}')`}"
                 title="${locked ? a.unlock : a.name}">
              <span class="avatar-emoji">${a.emoji}</span>
              <span class="avatar-name">${a.name}</span>
              ${locked ? '<span class="avatar-lock">🔒</span>' : ''}
            </div>`;
  }).join('');

  // Render skin grid
  const skinGrid = document.getElementById('skin-grid');
  const savedTheme = localStorage.getItem('kahu_theme') || 'cyber';
  skinGrid.innerHTML = THEMES.map(t => {
    const swatch = t.colors.map(c => `<span style="background:${c};width:12px;height:12px;border-radius:50%;display:inline-block"></span>`).join('');
    return `<div class="skin-option ${t.id === savedTheme ? 'selected' : ''}"
                 onclick="selectTheme('${t.id}')">
              <div class="skin-preview">${swatch}</div>
              <span class="skin-name">${t.name}</span>
              <span class="skin-tag free">Free</span>
            </div>`;
  }).join('');

  // Render badges
  const badgeContainer = document.getElementById('profile-badges');
  if (data.badges && data.badges.length > 0) {
    badgeContainer.innerHTML = data.badges.map(b =>
      `<div class="badge-item-enhanced">
        <span class="badge-icon">${getBadgeIcon(b.name)}</span>
        <div><strong>${escHtml(b.name)}</strong><br><small style="color:var(--text-dim)">${escHtml(b.description)}</small></div>
      </div>`
    ).join('');
  } else {
    badgeContainer.innerHTML = '<p style="color:var(--text-dim);font-size:14px">Triage alerts to earn badges</p>';
  }
}

function isAvatarUnlocked(avatar, rank, scoreData) {
  if (!avatar.unlock) return true;
  const u = avatar.unlock.toLowerCase();
  if (u.includes('sentinel') && RANKS.indexOf(rank) >= 2) return true;
  if (u.includes('commander') && RANKS.indexOf(rank) >= 3) return true;
  if (u.includes('warden') && RANKS.indexOf(rank) >= 4) return true;
  if (u.includes('50 alerts') && (scoreData.alerts_handled_today || 0) >= 50) return true;
  if (u.includes('7-day') && (scoreData.streak_days || 0) >= 7) return true;
  return false;
}

function selectAvatar(id) {
  localStorage.setItem('kahu_avatar', id);
  const avatar = AVATARS.find(a => a.id === id) || AVATARS[0];
  document.getElementById('profile-avatar').textContent = avatar.emoji;
  // Update selection state
  document.querySelectorAll('.avatar-option').forEach(el => el.classList.remove('selected'));
  const clicked = [...document.querySelectorAll('.avatar-option')].find(el => el.querySelector('.avatar-name')?.textContent === avatar.name);
  if (clicked) clicked.classList.add('selected');
}

function selectTheme(id) {
  localStorage.setItem('kahu_theme', id);
  document.documentElement.setAttribute('data-theme', id);
  // Update selection state
  document.querySelectorAll('.skin-option').forEach(el => el.classList.remove('selected'));
  const clicked = [...document.querySelectorAll('.skin-option')].find(el => el.querySelector('.skin-name')?.textContent === THEMES.find(t => t.id === id)?.name);
  if (clicked) clicked.classList.add('selected');
}

function getBadgeIcon(name) {
  const n = name.toLowerCase();
  if (n.includes('first')) return '🎯';
  if (n.includes('streak')) return '🔥';
  if (n.includes('speed')) return '⚡';
  if (n.includes('night')) return '🌙';
  if (n.includes('perfect')) return '💎';
  if (n.includes('volume')) return '📊';
  return '🏅';
}

// ---- XP Toast ----

function showXpToast(xp, extra) {
  const existing = document.querySelector('.xp-toast');
  if (existing) existing.remove();

  const toast = document.createElement('div');
  toast.className = 'xp-toast';
  toast.innerHTML = `+${xp} XP${extra ? ' · ' + escHtml(extra) : ''}`;
  document.body.appendChild(toast);

  requestAnimationFrame(() => toast.classList.add('show'));
  setTimeout(() => {
    toast.classList.remove('show');
    setTimeout(() => toast.remove(), 300);
  }, 1800);
}

// ---- Tickets ----

let ticketViewMode = 'cards';

function setTicketView(mode) {
  ticketViewMode = mode;
  document.getElementById('view-cards').classList.toggle('active', mode === 'cards');
  document.getElementById('view-table').classList.toggle('active', mode === 'table');
  if (currentScreen === 'score') loadScore();
}

async function loadTickets() {
  const data = await api(`${API}/tickets?analyst=${encodeURIComponent(getAnalystName())}`);
  if (data._offline) return data;
  return data;
}

async function closeTicket(ticketId) {
  const notes = prompt('Resolution notes (optional):') || '';
  try {
    const result = await api(`${API}/tickets/${ticketId}/close`, {
      method: 'POST',
      body: JSON.stringify({ analyst: getAnalystName(), resolution_notes: notes }),
    });
    if (result.xp_earned) {
      showXpToast(result.xp_earned, 'Ticket closed');
    }
    // Refresh the score screen if visible
    if (currentScreen === 'score') loadScore();
  } catch (e) {
    alert(e.message || 'Failed to close ticket');
  }
}

// ---- Ticket Detail ----

let openTicketId = null;

async function openTicket(ticketId) {
  openTicketId = ticketId;
  const modal = document.getElementById('ticket-modal');
  const content = document.getElementById('ticket-detail-content');
  content.innerHTML = '<div class="loading"><div class="spinner"></div></div>';
  modal.classList.add('active');

  const t = await api(`${API}/tickets/${ticketId}`);
  if (t._offline || !t.id) {
    content.innerHTML = '<p style="color:var(--text-dim);text-align:center;padding:20px">Could not load ticket.</p>';
    return;
  }

  const isInv = t.ticket_type === 'investigation';
  const typeLabel = isInv ? 'Investigation' : 'Incident';
  const typeColor = isInv ? 'var(--yellow)' : 'var(--red)';
  const statusOpts = ['open', 'in_progress', 'closed'].map(s =>
    `<option value="${s}"${t.status === s ? ' selected' : ''}>${s.replace('_', ' ')}</option>`
  ).join('');

  content.innerHTML = `
    <div class="td-header">
      <span class="td-type" style="color:${typeColor}">${typeLabel}</span>
      <span class="card-sev ${t.severity}">${t.severity}</span>
    </div>

    <div class="td-field">
      <label>Title</label>
      <input id="td-title" type="text" value="${escHtml(t.title)}" />
    </div>

    <div class="td-row">
      <div class="td-field td-half">
        <label>Status</label>
        <select id="td-status">${statusOpts}</select>
      </div>
      <div class="td-field td-half">
        <label>Assigned to</label>
        <input id="td-assigned" type="text" value="${escHtml(t.assigned_to)}" />
      </div>
    </div>

    <div class="td-field">
      <label>Notes</label>
      <textarea id="td-notes" rows="3" placeholder="Add investigation notes...">${escHtml(t.notes || '')}</textarea>
    </div>

    ${t.alert_llm_explanation ? `
    <div class="td-section">
      <h4>AI Analysis</h4>
      <p class="td-explanation">${escHtml(t.alert_llm_explanation)}</p>
    </div>` : ''}

    ${t.alert_recommended_actions && t.alert_recommended_actions.length ? `
    <div class="td-section">
      <h4>Recommended Actions</h4>
      <ul class="td-actions">${t.alert_recommended_actions.map(a => `<li>${escHtml(a)}</li>`).join('')}</ul>
    </div>` : ''}

    <div class="td-section">
      <h4>Alert Details</h4>
      <div class="td-meta-grid">
        ${t.alert_rule_id ? `<div class="td-meta-item"><span class="td-meta-key">Rule ID</span><span class="td-meta-val">${escHtml(t.alert_rule_id)}</span></div>` : ''}
        ${t.alert_rule_description ? `<div class="td-meta-item"><span class="td-meta-key">Rule</span><span class="td-meta-val">${escHtml(t.alert_rule_description)}</span></div>` : ''}
        ${t.alert_agent_name ? `<div class="td-meta-item"><span class="td-meta-key">Agent</span><span class="td-meta-val">${escHtml(t.alert_agent_name)}</span></div>` : ''}
        <div class="td-meta-item"><span class="td-meta-key">Created</span><span class="td-meta-val">${new Date(t.created_at).toLocaleString()}</span></div>
      </div>
    </div>

    ${t.alert_enrichment ? `
    <div class="td-section">
      <h4>Enrichment</h4>
      <div class="td-enrichment">${Object.entries(t.alert_enrichment).map(([k,v]) =>
        `<div class="td-meta-item"><span class="td-meta-key">${escHtml(k)}</span><span class="td-meta-val">${escHtml(typeof v === 'object' ? JSON.stringify(v) : String(v))}</span></div>`
      ).join('')}</div>
    </div>` : ''}

    <div class="td-buttons">
      <button class="td-save-btn" onclick="saveTicket('${t.id}')">Save Changes</button>
      <button class="td-close-btn" onclick="closeTicketModal()">Cancel</button>
    </div>
  `;
}

async function saveTicket(ticketId) {
  const title = document.getElementById('td-title').value.trim();
  const status = document.getElementById('td-status').value;
  const assigned_to = document.getElementById('td-assigned').value.trim();
  const notes = document.getElementById('td-notes').value;

  try {
    await api(`${API}/tickets/${ticketId}`, {
      method: 'PATCH',
      body: JSON.stringify({ title, status, assigned_to, notes }),
    });
    closeTicketModal();
    if (currentScreen === 'score') loadScore();
  } catch (e) {
    alert(e.message || 'Failed to save ticket');
  }
}

function closeTicketModal() {
  document.getElementById('ticket-modal').classList.remove('active');
  openTicketId = null;
}

// ---- Sources Screen ----

let connectorCatalog = null;
let selectedConnectorType = null;

async function loadSources() {
  const [overview, sources] = await Promise.all([
    api(`${CONN_API}/overview`),
    api(`${CONN_API}/sources`),
  ]);

  if (overview._offline) return;

  // Stats
  const statsEl = document.getElementById('sources-stats');
  statsEl.innerHTML = `
    <div class="src-stat">
      <div class="src-stat-value">${overview.total_sources}</div>
      <div class="src-stat-label">Sources</div>
    </div>
    <div class="src-stat">
      <div class="src-stat-value" style="color:var(--green)">${overview.active_sources}</div>
      <div class="src-stat-label">Active</div>
    </div>
    <div class="src-stat">
      <div class="src-stat-value">${overview.events_today.toLocaleString()}</div>
      <div class="src-stat-label">Events today</div>
    </div>
  `;

  // Source list
  const listEl = document.getElementById('sources-list');
  if (sources.length === 0) {
    listEl.innerHTML = `
      <div class="sources-empty">
        <div class="sources-empty-icon">📡</div>
        <h3>No sources connected</h3>
        <p>Tap + to add your first log source.<br>Firewalls, endpoints, cloud apps — all in one place.</p>
      </div>`;
    return;
  }

  listEl.innerHTML = sources.map(s => `
    <div class="source-card" onclick="toggleSourceMenu('${s.id}')">
      <div class="source-icon">${escHtml(s.type_icon)}</div>
      <div class="source-info">
        <div class="source-name">${escHtml(s.name)}</div>
        <div class="source-type">${escHtml(s.type_name)}</div>
        <div class="source-events">${s.events_today.toLocaleString()} events today · ${s.events_total.toLocaleString()} total</div>
      </div>
      <div class="source-status ${s.status}" title="${s.status}${s.error_message ? ': ' + s.error_message : ''}"></div>
    </div>
  `).join('');
}

function toggleSourceMenu(id) {
  // Future: expand card to show actions (test, disable, delete)
}

async function openAddSource() {
  const modal = document.getElementById('add-source-modal');

  // Load catalog if not cached
  if (!connectorCatalog) {
    const data = await api(`${CONN_API}/catalog`);
    if (data._offline) return;
    connectorCatalog = data;
  }

  // Show step 1
  showSrcStep('catalog');

  // Render category tabs
  const tabsEl = document.getElementById('src-category-tabs');
  const allTab = { id: 'all', name: 'All', count: connectorCatalog.connectors.length };
  const cats = [allTab, ...connectorCatalog.categories];
  tabsEl.innerHTML = cats.map((c, i) =>
    `<div class="src-cat-tab ${i === 0 ? 'active' : ''}" onclick="filterCatalog('${c.id}')">${c.name} (${c.count})</div>`
  ).join('');

  // Render all connectors
  filterCatalog('all');

  modal.classList.add('active');
}

function filterCatalog(category) {
  // Update tab state
  document.querySelectorAll('.src-cat-tab').forEach(t => t.classList.remove('active'));
  const tabs = document.querySelectorAll('.src-cat-tab');
  for (const t of tabs) {
    if (t.textContent.startsWith(category === 'all' ? 'All' : '')) t.classList.add('active');
  }
  // Find by category name match
  document.querySelectorAll('.src-cat-tab').forEach(t => {
    const catData = connectorCatalog.categories.find(c => t.textContent.includes(c.name));
    if (category === 'all' && t.textContent.startsWith('All')) t.classList.add('active');
    else if (catData && catData.id === category) t.classList.add('active');
    else if (category !== 'all') { /* keep non-matching inactive */ }
  });

  const filtered = category === 'all'
    ? connectorCatalog.connectors
    : connectorCatalog.connectors.filter(c => c.category === category);

  const listEl = document.getElementById('src-type-list');
  listEl.innerHTML = filtered.map(c => `
    <div class="src-type-item" onclick="selectConnectorType('${c.id}')">
      <div class="src-type-icon">${c.icon}</div>
      <div class="src-type-info">
        <div class="src-type-name">${escHtml(c.name)}</div>
        <div class="src-type-desc">${escHtml(c.description)}</div>
        <div class="src-type-vol">${c.events_per_day} events/day typical</div>
      </div>
      <div class="src-type-arrow">›</div>
    </div>
  `).join('');
}

function selectConnectorType(typeId) {
  const ct = connectorCatalog.connectors.find(c => c.id === typeId);
  if (!ct) return;
  selectedConnectorType = ct;

  // Header
  document.getElementById('src-config-header').innerHTML = `
    <div class="src-type-icon">${ct.icon}</div>
    <h3>${escHtml(ct.name)}</h3>
  `;

  // Name field + credential fields
  const fieldsEl = document.getElementById('src-config-fields');
  let html = `
    <div class="src-field-name">
      <label>Source Name <span class="required">*</span></label>
      <input id="src-name" type="text" placeholder="e.g. Main Office Firewall" required>
    </div>
  `;

  for (const f of ct.fields) {
    if (f.type === 'select') {
      const options = f.placeholder.split(',');
      html += `
        <div class="src-field">
          <label>${escHtml(f.label)} ${f.required ? '<span class="required">*</span>' : ''}</label>
          <select name="${f.name}" ${f.required ? 'required' : ''}>
            ${options.map(o => `<option value="${o.trim()}">${escHtml(o.trim())}</option>`).join('')}
          </select>
          ${f.help_text ? `<span class="src-help">${escHtml(f.help_text)}</span>` : ''}
        </div>`;
    } else if (f.type === 'textarea') {
      html += `
        <div class="src-field">
          <label>${escHtml(f.label)} ${f.required ? '<span class="required">*</span>' : ''}</label>
          <textarea name="${f.name}" placeholder="${escHtml(f.placeholder)}" ${f.required ? 'required' : ''}></textarea>
          ${f.help_text ? `<span class="src-help">${escHtml(f.help_text)}</span>` : ''}
        </div>`;
    } else {
      html += `
        <div class="src-field">
          <label>${escHtml(f.label)} ${f.required ? '<span class="required">*</span>' : ''}</label>
          <input name="${f.name}" type="${f.type === 'password' ? 'password' : 'text'}"
                 placeholder="${escHtml(f.placeholder)}" ${f.required ? 'required' : ''}>
          ${f.help_text ? `<span class="src-help">${escHtml(f.help_text)}</span>` : ''}
        </div>`;
    }
  }
  fieldsEl.innerHTML = html;

  // Setup guide link
  const linkEl = document.getElementById('src-setup-link');
  if (ct.setup_guide_url) {
    linkEl.innerHTML = `
      <a href="${ct.setup_guide_url}" target="_blank" rel="noopener">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/></svg>
        How to configure ${escHtml(ct.name)}
      </a>`;
  } else {
    linkEl.innerHTML = '';
  }

  showSrcStep('config');
}

async function submitSource(e) {
  e.preventDefault();
  const form = document.getElementById('src-config-form');
  const btn = form.querySelector('.src-submit-btn');
  btn.disabled = true;
  btn.textContent = 'Connecting...';

  const name = document.getElementById('src-name').value.trim();
  const credentials = {};
  const config = {};

  for (const f of selectedConnectorType.fields) {
    const el = form.querySelector(`[name="${f.name}"]`);
    if (!el) continue;
    const val = el.value.trim();
    if (f.type === 'password' || f.name.includes('secret') || f.name.includes('key') || f.name.includes('password') || f.name.includes('token')) {
      credentials[f.name] = val;
    } else {
      config[f.name] = val;
    }
  }

  try {
    // Create source
    const source = await api(`${CONN_API}/sources`, {
      method: 'POST',
      body: JSON.stringify({
        connector_type: selectedConnectorType.id,
        name,
        config,
        credentials,
      }),
    });

    if (source._offline) {
      showSrcResult(false, 'Offline', 'Cannot add sources while offline.');
      return;
    }

    // Test connection
    const test = await api(`${CONN_API}/sources/${source.id}/test`, { method: 'POST' });

    if (test.success) {
      showSrcResult(true, 'Connected!', test.message);
    } else {
      showSrcResult(false, 'Connection Failed', test.message);
    }
  } catch (err) {
    showSrcResult(false, 'Error', err.message || 'Something went wrong');
  }

  btn.disabled = false;
  btn.textContent = 'Add & Test Connection';
}

function showSrcResult(success, title, message) {
  document.getElementById('src-result-content').innerHTML = `
    <div class="src-result-icon">${success ? '✅' : '❌'}</div>
    <div class="src-result-title">${escHtml(title)}</div>
    <div class="src-result-msg">${escHtml(message)}</div>
  `;
  showSrcStep('result');
}

function showSrcStep(step) {
  document.querySelectorAll('.src-step').forEach(s => s.classList.remove('active'));
  document.getElementById('src-step-' + step).classList.add('active');
}

function srcStepBack() {
  showSrcStep('catalog');
}

function closeAddSource() {
  document.getElementById('add-source-modal').classList.remove('active');
  selectedConnectorType = null;
  // Refresh sources list
  if (currentScreen === 'sources') loadSources();
}

// ---- Vulnerability Scanner Screen ----

async function loadVulns() {
  const [summary, results, scans] = await Promise.all([
    api(`${VULN_API}/summary`),
    api(`${VULN_API}/results`).catch(() => ({ findings: [] })),
    api(`${VULN_API}/scans`).catch(() => ({ scans: [] })),
  ]);

  if (summary._offline) return;

  // Summary cards
  const summaryEl = document.getElementById('vulns-summary');
  if (!summary.scanner_online) {
    summaryEl.innerHTML = `
      <div class="vulns-offline">
        <div class="vulns-offline-icon">&#x26A0;</div>
        <h3>Scanner Offline</h3>
        <p>Greenbone vulnerability scanner is not reachable. Check that the service is running.</p>
      </div>`;
    document.getElementById('vulns-findings').innerHTML = '';
    return;
  }

  const sevColors = { critical: '#ff4444', high: '#ff8c00', medium: '#ffd600', low: '#4fc3f7', info: '#888' };
  summaryEl.innerHTML = `
    <div class="vulns-stat-row">
      <div class="vulns-stat" style="border-left:3px solid ${sevColors.critical}">
        <div class="vulns-stat-value">${summary.critical}</div>
        <div class="vulns-stat-label">Critical</div>
      </div>
      <div class="vulns-stat" style="border-left:3px solid ${sevColors.high}">
        <div class="vulns-stat-value">${summary.high}</div>
        <div class="vulns-stat-label">High</div>
      </div>
      <div class="vulns-stat" style="border-left:3px solid ${sevColors.medium}">
        <div class="vulns-stat-value">${summary.medium}</div>
        <div class="vulns-stat-label">Medium</div>
      </div>
      <div class="vulns-stat" style="border-left:3px solid ${sevColors.low}">
        <div class="vulns-stat-value">${summary.low}</div>
        <div class="vulns-stat-label">Low</div>
      </div>
      <div class="vulns-stat">
        <div class="vulns-stat-value">${summary.total}</div>
        <div class="vulns-stat-label">Total</div>
      </div>
    </div>
    <div class="vulns-scan-status">
      ${summary.tasks_running > 0
        ? `<span class="vulns-running"><div class="spinner-sm"></div> ${summary.tasks_running} scan${summary.tasks_running > 1 ? 's' : ''} running</span>`
        : `<span>${summary.tasks_total} scan${summary.tasks_total !== 1 ? 's' : ''} configured</span>`}
    </div>
  `;

  // Findings list
  renderFindings(results.findings || []);

  // Scans list
  renderScans(scans.scans || []);

  // Load targets
  loadVulnTargets();
}

function renderFindings(findings) {
  const el = document.getElementById('vulns-findings');
  if (findings.length === 0) {
    el.innerHTML = `
      <div class="sources-empty">
        <div class="sources-empty-icon">&#x2705;</div>
        <h3>No findings yet</h3>
        <p>Run a vulnerability scan to discover issues in your network.</p>
      </div>`;
    return;
  }

  const sevColors = { critical: '#ff4444', high: '#ff8c00', medium: '#ffd600', low: '#4fc3f7', info: '#888' };
  el.innerHTML = findings.map(f => `
    <div class="vuln-card">
      <div class="vuln-sev" style="background:${sevColors[f.severity_label] || '#888'}">${f.severity_label[0].toUpperCase()}</div>
      <div class="vuln-info">
        <div class="vuln-name">${escHtml(f.name)}</div>
        <div class="vuln-meta">${escHtml(f.host)}${f.port ? ':' + escHtml(f.port) : ''} ${f.cve ? '&middot; ' + escHtml(f.cve) : ''}</div>
        ${f.solution ? `<div class="vuln-solution">${escHtml(f.solution)}</div>` : ''}
      </div>
      <div class="vuln-score">${Number(f.severity).toFixed(1)}</div>
    </div>
  `).join('');
}

function renderScans(scans) {
  const el = document.getElementById('vulns-scans');
  if (scans.length === 0) {
    el.innerHTML = `
      <div class="sources-empty">
        <div class="sources-empty-icon">&#x1F50D;</div>
        <h3>No scans yet</h3>
        <p>Create a scan to start finding vulnerabilities.</p>
      </div>`;
    return;
  }

  const statusIcons = { Done: '&#x2705;', Running: '&#x23F3;', Requested: '&#x23F3;', New: '&#x2B55;', Stopped: '&#x23F9;' };
  el.innerHTML = scans.map(s => {
    const isRunning = s.status === 'Running' || s.status === 'Requested';
    const isDone = s.status === 'Done';
    const isStopped = s.status === 'Stopped' || s.status === 'New';
    const actions = [];
    if (isDone) actions.push(`<button class="scan-action-btn" onclick="viewScanResults('${s.id}')">Results</button>`);
    if (isRunning) actions.push(`<button class="scan-action-btn scan-stop" onclick="stopScan('${s.id}')">Stop</button>`);
    if (isStopped) actions.push(`<button class="scan-action-btn" onclick="startScan('${s.id}')">Start</button>`);
    actions.push(`<button class="scan-action-btn scan-delete" onclick="deleteScan('${s.id}')">Delete</button>`);
    return `
    <div class="scan-card">
      <div class="scan-status-icon">${statusIcons[s.status] || '&#x2B55;'}</div>
      <div class="scan-info">
        <div class="scan-name">${escHtml(s.name || 'Unnamed scan')}</div>
        <div class="scan-meta">
          ${escHtml(s.status || 'Unknown')}${s.progress && s.progress !== '-1' ? ' &middot; ' + s.progress + '%' : ''}
          ${s.target_name ? ' &middot; ' + escHtml(s.target_name) : ''}
          ${s.result_count ? ' &middot; ' + s.result_count + ' results' : ''}
        </div>
      </div>
      <div class="scan-actions">${actions.join('')}</div>
    </div>`;
  }).join('');
}

async function loadVulnTargets() {
  try {
    const data = await api(`${VULN_API}/targets`);
    const el = document.getElementById('vulns-targets');
    const targets = data.targets || [];
    if (targets.length === 0) {
      el.innerHTML = `
        <div class="sources-empty">
          <div class="sources-empty-icon">&#x1F3AF;</div>
          <h3>No targets</h3>
          <p>Targets are created automatically when you start a scan.</p>
        </div>`;
      return;
    }
    el.innerHTML = targets.map(t => `
      <div class="scan-card">
        <div class="scan-status-icon">&#x1F3AF;</div>
        <div class="scan-info">
          <div class="scan-name">${escHtml(t.name || 'Unnamed')}</div>
          <div class="scan-meta">${escHtml(t.hosts || '')}</div>
        </div>
      </div>
    `).join('');
  } catch {
    document.getElementById('vulns-targets').innerHTML = '<p style="color:var(--text-dim);padding:16px">Could not load targets.</p>';
  }
}

async function viewScanResults(taskId) {
  try {
    const data = await api(`${VULN_API}/results?task_id=${taskId}`);
    renderFindings(data.findings || []);
    switchVulnTab('findings');
  } catch {
    // ignore
  }
}

function switchVulnTab(tab) {
  document.querySelectorAll('.vulns-tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.vulns-tab-content').forEach(c => c.classList.remove('active'));
  document.querySelector(`.vulns-tab-content#vulns-tab-${tab}`)?.classList.add('active');
  document.querySelectorAll('.vulns-tab').forEach(t => {
    if (t.textContent.toLowerCase() === tab || t.textContent.toLowerCase().startsWith(tab)) t.classList.add('active');
  });
  if (tab === 'reports') loadReports();
}

async function stopScan(taskId) {
  try {
    await api(`${VULN_API}/scans/${taskId}/stop`, { method: 'POST' });
    loadVulns();
  } catch { /* ignore */ }
}

async function startScan(taskId) {
  try {
    await api(`${VULN_API}/scans/${taskId}/start`, { method: 'POST' });
    loadVulns();
  } catch { /* ignore */ }
}

async function deleteScan(taskId) {
  if (!confirm('Delete this scan and its results?')) return;
  try {
    await api(`${VULN_API}/scans/${taskId}`, { method: 'DELETE' });
    loadVulns();
  } catch { /* ignore */ }
}

async function loadReports() {
  const el = document.getElementById('vulns-reports');
  try {
    const data = await api(`${VULN_API}/reports`);
    const reports = data.reports || [];
    if (reports.length === 0) {
      el.innerHTML = `
        <div class="sources-empty">
          <div class="sources-empty-icon">&#x1F4C4;</div>
          <h3>No reports</h3>
          <p>Reports are generated when scans complete.</p>
        </div>`;
      return;
    }
    el.innerHTML = reports.map(r => `
      <div class="scan-card">
        <div class="scan-status-icon">&#x1F4C4;</div>
        <div class="scan-info">
          <div class="scan-name">Report ${escHtml(r.id?.substring(0, 8) || '')}</div>
          <div class="scan-meta">
            ${r.scan_start ? escHtml(r.scan_start) : ''}${r.scan_end ? ' &rarr; ' + escHtml(r.scan_end) : ''}
            ${r.result_count ? ' &middot; ' + r.result_count + ' results' : ''}
            ${r.severity ? ' &middot; Sev ' + r.severity : ''}
          </div>
        </div>
        ${r.task_id ? `<button class="scan-action-btn" onclick="viewScanResults('${r.task_id}')">View</button>` : ''}
      </div>
    `).join('');
  } catch {
    el.innerHTML = '<p style="color:var(--text-dim);padding:16px">Could not load reports.</p>';
  }
}

async function openNewScan() {
  const modal = document.getElementById('scan-modal');
  document.querySelectorAll('.scan-step').forEach(s => s.classList.remove('active'));
  document.getElementById('scan-step-target').classList.add('active');
  document.getElementById('scan-name').value = '';
  document.getElementById('scan-hosts').value = '';
  modal.classList.add('active');

  // Load scan configs and port lists
  const configSel = document.getElementById('scan-config');
  const portSel = document.getElementById('scan-port-list');
  try {
    const [configs, portLists] = await Promise.all([
      api(`${VULN_API}/configs`).catch(() => ({ configs: [] })),
      api(`${VULN_API}/port-lists`).catch(() => ({ port_lists: [] })),
    ]);
    configSel.innerHTML = '<option value="">Default (Full and fast)</option>' +
      (configs.configs || []).map(c => `<option value="${c.id}">${escHtml(c.name)}</option>`).join('');
    portSel.innerHTML = '<option value="">Default</option>' +
      (portLists.port_lists || []).map(p => `<option value="${p.id}">${escHtml(p.name)} (${p.port_count || '?'} ports)</option>`).join('');
  } catch {
    configSel.innerHTML = '<option value="">Default</option>';
    portSel.innerHTML = '<option value="">Default</option>';
  }
}

async function submitScan(e) {
  e.preventDefault();
  const btn = document.getElementById('scan-submit-btn');
  btn.disabled = true;
  btn.textContent = 'Starting...';

  const name = document.getElementById('scan-name').value.trim();
  const hosts = document.getElementById('scan-hosts').value.trim();
  const scanConfigId = document.getElementById('scan-config').value;
  const portListId = document.getElementById('scan-port-list').value;

  try {
    // Create target first
    const targetBody = { name: name + ' target', hosts };
    if (portListId) targetBody.port_list_id = portListId;
    const target = await api(`${VULN_API}/targets`, {
      method: 'POST',
      body: JSON.stringify(targetBody),
    });

    const targetId = target.id || target.target_id || '';
    if (!targetId) throw new Error('Failed to create target');

    // Create and start scan
    const scanBody = { name, target_id: targetId };
    if (scanConfigId) scanBody.scan_config_id = scanConfigId;
    const scan = await api(`${VULN_API}/scans`, {
      method: 'POST',
      body: JSON.stringify(scanBody),
    });

    document.getElementById('scan-result-content').innerHTML = `
      <div class="src-result-icon">&#x2705;</div>
      <div class="src-result-title">Scan Started</div>
      <div class="src-result-msg">Vulnerability scan "${escHtml(name)}" is now running against ${escHtml(hosts)}. Results will appear as the scan progresses.</div>
    `;
    document.querySelectorAll('.scan-step').forEach(s => s.classList.remove('active'));
    document.getElementById('scan-step-result').classList.add('active');
  } catch (err) {
    document.getElementById('scan-result-content').innerHTML = `
      <div class="src-result-icon">&#x274C;</div>
      <div class="src-result-title">Scan Failed</div>
      <div class="src-result-msg">${escHtml(err.message || 'Could not start scan')}</div>
    `;
    document.querySelectorAll('.scan-step').forEach(s => s.classList.remove('active'));
    document.getElementById('scan-step-result').classList.add('active');
  }

  btn.disabled = false;
  btn.textContent = 'Start Scan';
}

function closeScanModal() {
  document.getElementById('scan-modal').classList.remove('active');
  if (currentScreen === 'vulns') loadVulns();
}

// ---- Compliance Screen ----

let compActiveFramework = null;
let compFrameworks = [];

async function loadCompliance() {
  const tabsEl = document.getElementById('comp-fw-tabs');
  const summaryEl = document.getElementById('comp-coverage-summary');
  const familiesEl = document.getElementById('comp-families');
  const statsEl = document.getElementById('comp-evidence-stats');

  // Load frameworks list (once)
  if (!compFrameworks.length) {
    const fwData = await api(`${COMP_API}/frameworks`);
    if (fwData._offline) return;
    compFrameworks = fwData.frameworks || [];
  }

  // Load evidence summary
  const evSummary = await api(`${COMP_API}/evidence/summary`);
  if (evSummary && !evSummary._offline) {
    statsEl.innerHTML = `
      <div class="comp-stat"><span class="comp-stat-val">${evSummary.total_records || 0}</span><span class="comp-stat-lbl">Evidence Records</span></div>
      <div class="comp-stat"><span class="comp-stat-val">${evSummary.chain_intact ? 'Intact' : 'Broken'}</span><span class="comp-stat-lbl">Hash Chain</span></div>
      <div class="comp-stat"><span class="comp-stat-val">${evSummary.latest_timestamp ? formatTimeAgo(new Date(evSummary.latest_timestamp)) : '--'}</span><span class="comp-stat-lbl">Last Record</span></div>
    `;
  }

  // Render framework tabs
  if (!compActiveFramework && compFrameworks.length) {
    compActiveFramework = compFrameworks[0].id;
  }
  tabsEl.innerHTML = compFrameworks.map(fw =>
    `<button class="comp-fw-tab${fw.id === compActiveFramework ? ' active' : ''}" onclick="selectFramework('${fw.id}')">${escHtml(fw.name)}</button>`
  ).join('');

  // Load coverage for active framework
  if (compActiveFramework) {
    await loadCoverage(compActiveFramework);
  }
}

function selectFramework(fwId) {
  compActiveFramework = fwId;
  document.querySelectorAll('.comp-fw-tab').forEach(t => t.classList.remove('active'));
  document.querySelector(`.comp-fw-tab[onclick*="${fwId}"]`)?.classList.add('active');
  loadCoverage(fwId);
}

async function loadCoverage(fwId) {
  const summaryEl = document.getElementById('comp-coverage-summary');
  const familiesEl = document.getElementById('comp-families');

  summaryEl.innerHTML = '<div class="loading"><div class="spinner"></div></div>';
  familiesEl.innerHTML = '';

  const data = await api(`${COMP_API}/frameworks/${fwId}/coverage`);
  if (data._offline || !data.framework_id) {
    summaryEl.innerHTML = '<p style="color:var(--text-dim)">Could not load coverage data.</p>';
    return;
  }

  // Coverage ring
  const pct = data.coverage_pct || 0;
  const color = pct >= 75 ? 'var(--green)' : pct >= 50 ? 'var(--yellow)' : 'var(--red)';
  const dashOffset = 283 - (283 * pct / 100);

  summaryEl.innerHTML = `
    <div class="comp-ring-wrap">
      <svg class="comp-ring" viewBox="0 0 100 100">
        <circle class="comp-ring-bg" cx="50" cy="50" r="45"/>
        <circle class="comp-ring-fill" cx="50" cy="50" r="45"
          stroke="${color}" stroke-dasharray="283" stroke-dashoffset="${dashOffset}"/>
      </svg>
      <div class="comp-ring-text">
        <span class="comp-ring-pct">${Math.round(pct)}%</span>
        <span class="comp-ring-lbl">Coverage</span>
      </div>
    </div>
    <div class="comp-summary-stats">
      <div><strong>${data.covered_controls}</strong> of <strong>${data.total_controls}</strong> controls covered</div>
      <div class="comp-summary-name">${escHtml(data.framework_name)}</div>
    </div>
  `;

  // Family breakdown
  familiesEl.innerHTML = data.families.map(fam => {
    const famPct = fam.coverage_pct || 0;
    const famColor = famPct >= 75 ? 'var(--green)' : famPct >= 50 ? 'var(--yellow)' : 'var(--red)';
    const covered = fam.controls.filter(c => c.covered).length;
    const total = fam.controls.length;

    return `
      <div class="comp-family">
        <div class="comp-family-header" onclick="toggleFamily(this)">
          <div class="comp-family-info">
            <span class="comp-family-id">${escHtml(fam.family_id)}</span>
            <span class="comp-family-name">${escHtml(fam.family_name)}</span>
          </div>
          <div class="comp-family-bar-wrap">
            <div class="comp-family-bar">
              <div class="comp-family-bar-fill" style="width:${famPct}%;background:${famColor}"></div>
            </div>
            <span class="comp-family-pct">${covered}/${total}</span>
          </div>
          <svg class="comp-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 12 15 18 9"/></svg>
        </div>
        <div class="comp-family-controls" style="display:none">
          ${fam.controls.map(ctrl => `
            <div class="comp-control ${ctrl.covered ? 'covered' : 'gap'}">
              <div class="comp-control-status">${ctrl.covered ? (ctrl.evidence_type === 'automated' ? '<span class="ctrl-dot auto"></span>' : '<span class="ctrl-dot cap"></span>') : '<span class="ctrl-dot gap"></span>'}</div>
              <div class="comp-control-info">
                <div class="comp-control-id">${escHtml(ctrl.id)}</div>
                <div class="comp-control-title">${escHtml(ctrl.title)}</div>
                ${ctrl.coverage_source ? `<div class="comp-control-source">${escHtml(ctrl.coverage_source)}</div>` : ''}
              </div>
              <button class="comp-evidence-btn" onclick="openEvidence('${escHtml(ctrl.id)}','${escHtml(ctrl.title)}')">Evidence</button>
            </div>
          `).join('')}
        </div>
      </div>
    `;
  }).join('');
}

function toggleFamily(header) {
  const controls = header.nextElementSibling;
  const chevron = header.querySelector('.comp-chevron');
  if (controls.style.display === 'none') {
    controls.style.display = 'block';
    chevron.style.transform = 'rotate(180deg)';
  } else {
    controls.style.display = 'none';
    chevron.style.transform = '';
  }
}

async function openEvidence(controlId, controlTitle) {
  const modal = document.getElementById('evidence-modal');
  const header = document.getElementById('evidence-modal-header');
  const list = document.getElementById('evidence-list');

  header.innerHTML = `<h3>Evidence: ${escHtml(controlId)}</h3><p class="evidence-subtitle">${escHtml(controlTitle)}</p>`;
  list.innerHTML = '<div class="loading"><div class="spinner"></div></div>';
  modal.classList.add('active');

  const data = await api(`${COMP_API}/evidence?control_id=${encodeURIComponent(controlId)}&limit=50`);
  if (data._offline || !data.records) {
    list.innerHTML = '<p style="color:var(--text-dim);padding:20px;text-align:center">No evidence records found.</p>';
    return;
  }

  if (!data.records.length) {
    list.innerHTML = '<p style="color:var(--text-dim);padding:20px;text-align:center">No evidence records match this control yet.</p>';
    return;
  }

  list.innerHTML = data.records.map(r => `
    <div class="evidence-record">
      <div class="evidence-record-header">
        <span class="evidence-type ${r.event_type}">${escHtml(r.event_type.replace(/_/g, ' '))}</span>
        <span class="evidence-time">${formatTimeAgo(new Date(r.timestamp))}</span>
      </div>
      <div class="evidence-record-body">
        ${r.payload ? Object.entries(r.payload).map(([k,v]) =>
          `<div class="evidence-kv"><span class="evidence-key">${escHtml(k)}</span><span class="evidence-val">${escHtml(String(v))}</span></div>`
        ).join('') : ''}
      </div>
      <div class="evidence-record-footer">
        <span class="evidence-actor">${escHtml(r.actor || 'system')}</span>
        <span class="evidence-hash" title="Record hash">#${r.record_hash}</span>
      </div>
    </div>
  `).join('');
}

function closeEvidenceModal() {
  document.getElementById('evidence-modal').classList.remove('active');
}

// ---- Utilities ----

function escHtml(s) {
  const d = document.createElement('div');
  d.textContent = s || '';
  return d.innerHTML;
}

function formatTimeAgo(date) {
  const seconds = Math.floor((Date.now() - date.getTime()) / 1000);
  if (seconds < 60) return 'just now';
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return minutes + 'm ago';
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return hours + 'h ago';
  const days = Math.floor(hours / 24);
  return days + 'd ago';
}

function getAnalystName() {
  return localStorage.getItem('kahu_analyst') || 'mobile-user';
}

function setAnalystName(name) {
  localStorage.setItem('kahu_analyst', name);
}

// ---- Chat enter key ----

document.addEventListener('DOMContentLoaded', () => {
  const input = document.getElementById('chat-input');
  if (input) {
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        sendMessage();
      }
    });
  }

  // Modals — close on overlay click
  const modal = document.getElementById('coach-modal');
  if (modal) {
    modal.addEventListener('click', (e) => {
      if (e.target === modal) closeCoach();
    });
  }
  const ticketModal = document.getElementById('ticket-modal');
  if (ticketModal) {
    ticketModal.addEventListener('click', (e) => {
      if (e.target === ticketModal) closeTicketModal();
    });
  }
  const evModal = document.getElementById('evidence-modal');
  if (evModal) {
    evModal.addEventListener('click', (e) => {
      if (e.target === evModal) closeEvidenceModal();
    });
  }
  const srcModal = document.getElementById('add-source-modal');
  if (srcModal) {
    srcModal.addEventListener('click', (e) => {
      if (e.target === srcModal) closeAddSource();
    });
  }

  // Apply saved theme
  const savedTheme = localStorage.getItem('kahu_theme');
  if (savedTheme) document.documentElement.setAttribute('data-theme', savedTheme);

  // Apply saved analyst name
  const savedName = localStorage.getItem('kahu_analyst');
  if (savedName) {
    const nameInput = document.getElementById('analyst-name');
    if (nameInput) nameInput.value = savedName;
  }

  // Load initial screen
  navigate('glance');

  // Auto-refresh glance every 30s
  setInterval(() => {
    if (currentScreen === 'glance') loadGlance();
  }, 30000);
});

// ---- Recon Screen ----

function loadRecon() {
  checkArsenalMode();
}

function switchReconTab(tab) {
  document.querySelectorAll('.recon-tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.recon-tab-content').forEach(c => c.classList.remove('active'));
  document.getElementById(`recon-tab-${tab}`)?.classList.add('active');
  // Activate the correct tab button
  document.querySelectorAll('.recon-tab').forEach(t => {
    const text = t.textContent.toLowerCase().trim();
    if (tab === 'dns' && text === 'dns') t.classList.add('active');
    else if (tab === 'reverse' && text === 'reverse dns') t.classList.add('active');
    else if (tab === 'ipscan' && text === 'ip scan') t.classList.add('active');
    else if (tab === 'portscan' && text === 'port scan') t.classList.add('active');
    else if (tab === 'arsenal' && text === 'arsenal') t.classList.add('active');
  });
  if (tab === 'arsenal') loadArsenalTools();
}

async function submitDnsLookup(e) {
  e.preventDefault();
  const domain = document.getElementById('dns-domain').value.trim();
  if (!domain) return false;

  const checkboxes = document.querySelectorAll('#dns-record-types input[type=checkbox]:checked');
  const types = Array.from(checkboxes).map(cb => cb.value);

  const btn = document.getElementById('dns-submit-btn');
  const results = document.getElementById('dns-results');
  btn.disabled = true;
  btn.textContent = 'Resolving...';
  results.innerHTML = '<div class="loading"><div class="spinner"></div></div>';

  try {
    const data = await api(`${RECON_API}/dns`, {
      method: 'POST',
      body: JSON.stringify({ domain, record_types: types }),
    });

    if (data._offline) {
      results.innerHTML = '<p style="color:var(--text-dim);padding:16px">Offline — cannot perform DNS lookup.</p>';
      return false;
    }

    let html = `<div class="recon-domain-header">${escHtml(data.domain)}</div>`;

    if (data.records && data.records.length > 0) {
      // Group by type
      const grouped = {};
      data.records.forEach(r => {
        if (!grouped[r.type]) grouped[r.type] = [];
        grouped[r.type].push(r);
      });

      html += '<div class="recon-record-groups">';
      for (const [type, recs] of Object.entries(grouped)) {
        html += `<div class="recon-record-group">
          <div class="recon-type-badge">${escHtml(type)}</div>
          <div class="recon-records">`;
        for (const r of recs) {
          html += `<div class="recon-record">
            <span class="recon-record-value">${escHtml(r.value)}</span>
            <span class="recon-record-meta">TTL ${r.ttl}${r.priority != null ? ' &middot; Priority ' + r.priority : ''}</span>
          </div>`;
        }
        html += '</div></div>';
      }
      html += '</div>';
    } else {
      html += '<p style="color:var(--text-dim);padding:8px 0">No records found.</p>';
    }

    if (data.errors && Object.keys(data.errors).length > 0) {
      html += '<div class="recon-errors">';
      for (const [type, msg] of Object.entries(data.errors)) {
        html += `<div class="recon-error"><strong>${escHtml(type)}:</strong> ${escHtml(msg)}</div>`;
      }
      html += '</div>';
    }

    results.innerHTML = html;
  } catch (err) {
    results.innerHTML = `<p style="color:#ff4444;padding:16px">${escHtml(err.message)}</p>`;
  } finally {
    btn.disabled = false;
    btn.textContent = 'Lookup';
  }
  return false;
}

async function submitReverseLookup(e) {
  e.preventDefault();
  const ip = document.getElementById('reverse-ip').value.trim();
  if (!ip) return false;

  const btn = document.getElementById('reverse-submit-btn');
  const results = document.getElementById('reverse-results');
  btn.disabled = true;
  btn.textContent = 'Resolving...';
  results.innerHTML = '<div class="loading"><div class="spinner"></div></div>';

  try {
    const data = await api(`${RECON_API}/dns/reverse`, {
      method: 'POST',
      body: JSON.stringify({ ip }),
    });

    if (data._offline) {
      results.innerHTML = '<p style="color:var(--text-dim);padding:16px">Offline — cannot perform reverse lookup.</p>';
      return false;
    }

    let html = `<div class="recon-domain-header">${escHtml(data.ip)}</div>`;
    if (data.hostnames && data.hostnames.length > 0) {
      html += '<div class="recon-record-groups"><div class="recon-record-group">';
      html += '<div class="recon-type-badge">PTR</div><div class="recon-records">';
      data.hostnames.forEach(h => {
        html += `<div class="recon-record"><span class="recon-record-value">${escHtml(h)}</span></div>`;
      });
      html += '</div></div></div>';
    } else {
      html += '<p style="color:var(--text-dim);padding:8px 0">No reverse DNS records found for this IP.</p>';
    }

    results.innerHTML = html;
  } catch (err) {
    results.innerHTML = `<p style="color:#ff4444;padding:16px">${escHtml(err.message)}</p>`;
  } finally {
    btn.disabled = false;
    btn.textContent = 'Reverse Lookup';
  }
  return false;
}

async function submitIpScan(e) {
  e.preventDefault();
  const target = document.getElementById('ipscan-target').value.trim();
  if (!target) return false;

  const timeout_ms = parseInt(document.getElementById('ipscan-timeout').value) || 1000;
  const btn = document.getElementById('ipscan-submit-btn');
  const results = document.getElementById('ipscan-results');
  btn.disabled = true;
  btn.textContent = 'Scanning...';
  results.innerHTML = '<div class="loading"><div class="spinner"></div></div>';

  try {
    const data = await api(`${RECON_API}/ip-scan`, {
      method: 'POST',
      body: JSON.stringify({ target, timeout_ms }),
    });

    if (data._offline) {
      results.innerHTML = '<p style="color:var(--text-dim);padding:16px">Offline.</p>';
      return false;
    }

    let html = `<div class="recon-domain-header">${escHtml(data.target)}</div>`;
    html += `<div class="recon-scan-summary">${data.alive_count} alive / ${data.total_scanned} scanned</div>`;

    if (data.hosts && data.hosts.length > 0) {
      html += '<div class="recon-host-list">';
      for (const h of data.hosts) {
        if (!h.alive) continue;
        html += `<div class="recon-host-card alive">
          <div class="recon-host-status"></div>
          <div class="recon-host-info">
            <span class="recon-host-ip">${escHtml(h.ip)}</span>
            ${h.hostname ? `<span class="recon-host-name">${escHtml(h.hostname)}</span>` : ''}
          </div>
          ${h.latency_ms != null ? `<span class="recon-host-latency">${h.latency_ms}ms</span>` : ''}
          <button class="recon-scan-port-btn" onclick="quickPortScan('${escHtml(h.ip)}')">Ports</button>
        </div>`;
      }
      // Show dead hosts collapsed
      const dead = data.hosts.filter(h => !h.alive);
      if (dead.length > 0) {
        html += `<details class="recon-dead-hosts"><summary>${dead.length} host${dead.length !== 1 ? 's' : ''} not responding</summary>`;
        for (const h of dead) {
          html += `<div class="recon-host-card dead"><div class="recon-host-status"></div><span class="recon-host-ip">${escHtml(h.ip)}</span></div>`;
        }
        html += '</details>';
      }
      html += '</div>';
    } else {
      html += '<p style="color:var(--text-dim);padding:8px 0">No hosts responded.</p>';
    }

    results.innerHTML = html;
  } catch (err) {
    results.innerHTML = `<p style="color:#ff4444;padding:16px">${escHtml(err.message)}</p>`;
  } finally {
    btn.disabled = false;
    btn.textContent = 'Scan';
  }
  return false;
}

function quickPortScan(ip) {
  switchReconTab('portscan');
  document.getElementById('portscan-target').value = ip;
}

async function submitPortScan(e) {
  e.preventDefault();
  const target = document.getElementById('portscan-target').value.trim();
  if (!target) return false;

  const ports = document.getElementById('portscan-ports').value.trim() || 'common';
  const timeout_ms = parseInt(document.getElementById('portscan-timeout').value) || 1500;
  const btn = document.getElementById('portscan-submit-btn');
  const results = document.getElementById('portscan-results');
  btn.disabled = true;
  btn.textContent = 'Scanning...';
  results.innerHTML = '<div class="loading"><div class="spinner"></div></div>';

  try {
    const data = await api(`${RECON_API}/port-scan`, {
      method: 'POST',
      body: JSON.stringify({ target, ports, timeout_ms }),
    });

    if (data._offline) {
      results.innerHTML = '<p style="color:var(--text-dim);padding:16px">Offline.</p>';
      return false;
    }

    let html = `<div class="recon-domain-header">${escHtml(data.target)}</div>`;
    html += `<div class="recon-scan-summary">${data.open_count} open / ${data.total_scanned} scanned</div>`;

    const openPorts = data.ports.filter(p => p.state === 'open');
    const closedPorts = data.ports.filter(p => p.state === 'closed');

    if (openPorts.length > 0) {
      html += '<div class="recon-port-list">';
      for (const p of openPorts) {
        html += `<div class="recon-port-card open">
          <span class="recon-port-num">${p.port}</span>
          <span class="recon-port-state">OPEN</span>
          <span class="recon-port-service">${escHtml(p.service)}</span>
        </div>`;
      }
      html += '</div>';
    } else {
      html += '<p style="color:var(--text-dim);padding:8px 0">No open ports found.</p>';
    }

    if (closedPorts.length > 0) {
      html += `<details class="recon-dead-hosts"><summary>${closedPorts.length} closed port${closedPorts.length !== 1 ? 's' : ''}</summary><div class="recon-port-list">`;
      for (const p of closedPorts) {
        html += `<div class="recon-port-card closed">
          <span class="recon-port-num">${p.port}</span>
          <span class="recon-port-state">CLOSED</span>
          <span class="recon-port-service">${escHtml(p.service)}</span>
        </div>`;
      }
      html += '</div></details>';
    }

    results.innerHTML = html;
  } catch (err) {
    results.innerHTML = `<p style="color:#ff4444;padding:16px">${escHtml(err.message)}</p>`;
  } finally {
    btn.disabled = false;
    btn.textContent = 'Scan Ports';
  }
  return false;
}

// ---- Arsenal / Unlocked Mode ----

async function checkArsenalMode() {
  try {
    const data = await api(`${ARSENAL_API}/status`);
    if (data._offline) return;
    updateModeUI(data.mode === 'unlocked');
  } catch { /* ignore */ }
}

function updateModeUI(unlocked) {
  const btn = document.getElementById('mode-toggle-btn');
  const arsenalTab = document.getElementById('arsenal-tab-btn');
  if (btn) {
    btn.textContent = unlocked ? 'Unlocked' : 'Guardian';
    btn.className = 'mode-toggle-btn ' + (unlocked ? 'unlocked' : 'guardian');
  }
  if (arsenalTab) arsenalTab.style.display = unlocked ? '' : 'none';

  // Update arsenal tab content
  const lockedMsg = document.getElementById('arsenal-locked-msg');
  const content = document.getElementById('arsenal-content');
  if (lockedMsg) lockedMsg.style.display = unlocked ? 'none' : '';
  if (content) content.style.display = unlocked ? '' : 'none';
}

async function toggleArsenalMode() {
  const btn = document.getElementById('mode-toggle-btn');
  const isUnlocked = btn.classList.contains('unlocked');

  if (!isUnlocked) {
    if (!confirm('Switch to UNLOCKED mode?\n\nThis enables offensive security tools (port scanning, exploit planning, password attacks).\n\nOnly use this for authorized penetration testing.')) return;
  }

  try {
    const endpoint = isUnlocked ? 'lock' : 'unlock';
    const data = await api(`${ARSENAL_API}/${endpoint}`, {
      method: 'POST',
      body: JSON.stringify({ analyst: getAnalystName() }),
    });
    updateModeUI(data.mode === 'unlocked');
    if (data.mode === 'unlocked') loadArsenalTools();
  } catch (err) {
    alert('Failed to toggle mode: ' + err.message);
  }
}

async function loadArsenalTools() {
  const category = document.getElementById('arsenal-category-filter')?.value || '';
  try {
    const data = await api(`${ARSENAL_API}/tools${category ? '?category=' + category : ''}`);
    if (data._offline) return;

    // Populate category filter (once)
    const filter = document.getElementById('arsenal-category-filter');
    if (filter && filter.options.length <= 1 && data.categories) {
      for (const [id, name] of Object.entries(data.categories)) {
        const opt = document.createElement('option');
        opt.value = id;
        opt.textContent = name;
        filter.appendChild(opt);
      }
    }

    const list = document.getElementById('arsenal-tools-list');
    if (!data.tools || data.tools.length === 0) {
      list.innerHTML = '<p style="color:var(--text-dim)">No tools in this category.</p>';
      return;
    }

    list.innerHTML = data.tools.map(t => `
      <div class="arsenal-tool-card" onclick="this.querySelector('.arsenal-tool-detail').classList.toggle('open')">
        <div class="arsenal-tool-header">
          <span class="arsenal-tool-name">${escHtml(t.name)}</span>
          <span class="arsenal-tool-cat">${escHtml(t.category)}</span>
        </div>
        <div class="arsenal-tool-desc">${escHtml(t.description)}</div>
        <div class="arsenal-tool-detail">
          <div class="arsenal-tool-examples">
            ${t.examples.map(ex => `<code>${escHtml(ex)}</code>`).join('')}
          </div>
        </div>
      </div>
    `).join('');
  } catch { /* locked or offline */ }
}

async function submitAttackPlan(e) {
  e.preventDefault();
  const target = document.getElementById('arsenal-target').value.trim();
  const objective = document.getElementById('arsenal-objective').value.trim();
  const phase = document.getElementById('arsenal-phase').value;
  const scope = document.getElementById('arsenal-scope').value;
  const credentials = document.getElementById('arsenal-creds')?.value.trim() || '';
  const constraints = document.getElementById('arsenal-constraints').value.trim();

  if (!target || !objective) return false;

  const btn = document.getElementById('arsenal-plan-btn');
  const results = document.getElementById('arsenal-plan-results');
  btn.disabled = true;
  btn.textContent = 'Planning...';
  results.innerHTML = '<div class="loading"><div class="spinner"></div></div>';

  try {
    const data = await api(`${ARSENAL_API}/plan`, {
      method: 'POST',
      body: JSON.stringify({ target, objective, phase, scope, credentials, constraints }),
    });

    const phaseLabel = phase === 'both' ? 'Full Pentest' : phase === 'authenticated' ? 'Authenticated' : 'Unauthenticated';
    let html = `<div class="recon-domain-header">Attack Plan: ${escHtml(target)} <span class="arsenal-phase-badge">${phaseLabel}</span></div>`;

    if (data.degraded) {
      html += '<div class="recon-error">AI engine offline — showing limited results.</div>';
    }

    if (data.tools_referenced && data.tools_referenced.length > 0) {
      html += '<div class="arsenal-tools-used">';
      data.tools_referenced.forEach(t => {
        html += `<span class="arsenal-tool-badge">${escHtml(t)}</span>`;
      });
      html += '</div>';
    }

    html += `<div class="arsenal-plan-text">${escHtml(data.plan).replace(/\n/g, '<br>')}</div>`;
    results.innerHTML = html;
  } catch (err) {
    results.innerHTML = `<p style="color:#ff4444;padding:16px">${escHtml(err.message)}</p>`;
  } finally {
    btn.disabled = false;
    btn.textContent = 'Generate Attack Plan';
  }
  return false;
}

// ---- Alert History & Runbooks ----

let historyPage = 0;
let historySearchTimer = null;

async function loadHistory() {
  const search = document.getElementById('history-search')?.value?.trim() || '';
  const severity = document.getElementById('history-severity')?.value || '';
  const verdict = document.getElementById('history-verdict')?.value || '';
  const limit = 50;
  const offset = historyPage * limit;

  const params = new URLSearchParams();
  if (search) params.set('search', search);
  if (severity) params.set('severity', severity);
  if (verdict && verdict !== 'pending') params.set('verdict', verdict);
  params.set('offset', offset);
  params.set('limit', limit);

  const el = document.getElementById('history-list');
  el.innerHTML = '<div class="loading"><div class="spinner"></div></div>';

  try {
    const data = await api(`${TRIAGE_API}/history?${params}`);
    let alerts = data.alerts || [];

    // Client-side filter for "pending" (no disposition)
    if (verdict === 'pending') {
      alerts = alerts.filter(a => !a.verdict);
    }

    if (alerts.length === 0) {
      el.innerHTML = `
        <div class="sources-empty">
          <div class="sources-empty-icon">&#x1F4CB;</div>
          <h3>No alerts found</h3>
          <p>${search ? 'Try a different search term.' : 'Alerts will appear here as they are processed.'}</p>
        </div>`;
      document.getElementById('history-pager').innerHTML = '';
      return;
    }

    const sevColors = { critical: '#ff4444', high: '#ff8c00', medium: '#ffd600', low: '#4fc3f7', info: '#888' };
    const verdictLabels = {
      true_positive: 'True Positive',
      acknowledged: 'Acknowledged',
      false_positive: 'False Positive',
      benign_true_positive: 'Benign TP',
      undetermined: 'Undetermined',
    };

    el.innerHTML = alerts.map(a => `
      <div class="history-card" onclick="viewAlertDetail('${a.id}')">
        <div class="history-sev" style="background:${sevColors[a.severity] || '#888'}">${a.severity[0].toUpperCase()}</div>
        <div class="history-info">
          <div class="history-name">${escHtml(a.rule_description)}</div>
          <div class="history-meta">
            Rule ${escHtml(a.rule_id)}
            ${a.agent_name ? ' &middot; ' + escHtml(a.agent_name) : ''}
            &middot; ${formatTimeAgo(new Date(a.created_at))}
          </div>
        </div>
        <div class="history-verdict ${a.verdict ? 'has-verdict' : 'pending'}">
          ${a.verdict ? verdictLabels[a.verdict] || a.verdict : 'Pending'}
        </div>
      </div>
    `).join('');

    // Pager
    const totalPages = Math.ceil(data.total / limit);
    const pager = document.getElementById('history-pager');
    if (totalPages > 1) {
      pager.innerHTML = `
        <button ${historyPage === 0 ? 'disabled' : ''} onclick="historyPage--;loadHistory()">Prev</button>
        <span>Page ${historyPage + 1} of ${totalPages} (${data.total} alerts)</span>
        <button ${historyPage >= totalPages - 1 ? 'disabled' : ''} onclick="historyPage++;loadHistory()">Next</button>
      `;
    } else {
      pager.innerHTML = `<span>${data.total} alert${data.total !== 1 ? 's' : ''}</span>`;
    }
  } catch {
    el.innerHTML = '<p style="color:var(--text-dim);padding:16px">Could not load alert history.</p>';
  }
}

function debounceHistorySearch() {
  clearTimeout(historySearchTimer);
  historySearchTimer = setTimeout(() => { historyPage = 0; loadHistory(); }, 300);
}

async function viewAlertDetail(alertId) {
  try {
    const alert = await api(`${TRIAGE_API}/alerts/${alertId}`);
    const sevColors = { critical: '#ff4444', high: '#ff8c00', medium: '#ffd600', low: '#4fc3f7', info: '#888' };
    const modal = document.getElementById('coach-modal');
    const content = document.getElementById('coach-content');

    const disp = alert.disposition;
    const llm = alert.llm_triage || {};
    const raw = alert.raw_event || {};

    content.innerHTML = `
      <h3 style="margin:0 0 12px">${escHtml(alert.rule_description)}</h3>
      <div style="display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap">
        <span class="history-sev" style="background:${sevColors[alert.severity] || '#888'};display:inline-block;padding:2px 8px;border-radius:4px;color:#fff;font-size:12px">${alert.severity.toUpperCase()}</span>
        <span style="color:var(--text-dim);font-size:12px">Rule ${escHtml(alert.rule_id)}</span>
        ${alert.agent_name ? `<span style="color:var(--text-dim);font-size:12px">${escHtml(alert.agent_name)}</span>` : ''}
        <span style="color:var(--text-dim);font-size:12px">${new Date(alert.created_at).toLocaleString()}</span>
      </div>
      ${llm.explanation ? `<div style="background:var(--bg-elevated);padding:10px;border-radius:8px;margin-bottom:12px;font-size:13px"><strong>AI Analysis:</strong> ${escHtml(llm.explanation)}</div>` : ''}
      ${disp ? `<div style="background:var(--bg-elevated);padding:10px;border-radius:8px;margin-bottom:12px;font-size:13px"><strong>Disposition:</strong> ${escHtml(disp.verdict)} by ${escHtml(disp.analyst)}${disp.notes ? ' — ' + escHtml(disp.notes) : ''}</div>` : ''}
      <details style="margin-top:8px">
        <summary style="cursor:pointer;color:var(--text-dim);font-size:12px">Raw Event</summary>
        <pre style="background:var(--bg-elevated);padding:10px;border-radius:8px;font-size:11px;overflow-x:auto;margin-top:6px;max-height:300px">${escHtml(JSON.stringify(raw, null, 2))}</pre>
      </details>
    `;
    modal.classList.add('active');
  } catch {
    // ignore
  }
}

function switchHistoryTab(tab) {
  document.querySelectorAll('.history-tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.history-tab-content').forEach(c => c.classList.remove('active'));
  document.getElementById(`history-tab-${tab}`)?.classList.add('active');
  document.querySelectorAll('.history-tab').forEach(t => {
    if (t.textContent.toLowerCase() === tab || t.textContent.toLowerCase().startsWith(tab)) t.classList.add('active');
  });
  if (tab === 'runbooks') loadRunbooks();
}

async function loadRunbooks() {
  const el = document.getElementById('runbooks-list');
  try {
    const data = await api(`${TRIAGE_API}/runbooks`);
    const runbooks = data.runbooks || [];
    const sevColors = { critical: '#ff4444', high: '#ff8c00', medium: '#ffd600', low: '#4fc3f7', info: '#888' };

    el.innerHTML = runbooks.map(rb => `
      <div class="runbook-card">
        <div class="runbook-header">
          <span class="runbook-sev" style="background:${sevColors[rb.severity] || '#888'}">${rb.severity[0].toUpperCase()}</span>
          <div class="runbook-title">${escHtml(rb.title)}</div>
          <span class="runbook-rules">Rules: ${rb.rule_ids.join(', ')}</span>
        </div>
        <ol class="runbook-steps">
          ${rb.steps.map(s => `<li>${escHtml(s)}</li>`).join('')}
        </ol>
      </div>
    `).join('');
  } catch {
    el.innerHTML = '<p style="color:var(--text-dim);padding:16px">Could not load runbooks.</p>';
  }
}

// ---- Service Worker Registration ----

if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('/sw.js', { scope: '/' }).catch(() => {});
}
