/* Kahu PWA — Mobile-first security operations */

const API = '/api/m';
const TRIAGE_API = '/api/triage';
const INVEST_API = '/api/investigation';
let currentScreen = 'glance';
let feedCards = [];
let feedRemaining = 0;

// ---- Navigation ----

function navigate(screen) {
  document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
  document.querySelectorAll('nav button').forEach(b => b.classList.remove('active'));
  document.getElementById('screen-' + screen).classList.add('active');
  document.querySelector(`nav button[data-screen="${screen}"]`).classList.add('active');
  currentScreen = screen;

  // Load data for screen
  if (screen === 'glance') loadGlance();
  if (screen === 'feed') loadFeed();
  if (screen === 'score') loadScore();
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
  const data = await api(`${API}/feed?limit=20`);
  if (data._offline) return;

  feedCards = data.cards;
  feedRemaining = data.remaining;
  renderFeed();
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

    el.innerHTML = `
      <div class="swipe-overlay left">FALSE POS</div>
      <div class="swipe-overlay right">CONFIRM</div>
      <div class="swipe-overlay up">ESCALATE</div>
      <span class="card-sev ${card.severity}">${card.severity}</span>
      <h3 class="card-title">${escHtml(card.title)}</h3>
      <p class="card-explanation">${escHtml(card.explanation)}</p>
      <div class="card-meta">
        ${card.agent ? `<span class="card-meta-item">${escHtml(card.agent)}</span>` : ''}
        ${card.source_ip ? `<span class="card-meta-item">${escHtml(card.source_ip)}</span>` : ''}
        <span class="card-meta-item">${timeAgo}</span>
      </div>
      ${actions.length > 0 ? `
        <div class="card-actions">
          <h4>Recommended</h4>
          <ul>${actions.map(a => `<li>${escHtml(a)}</li>`).join('')}</ul>
        </div>
      ` : ''}
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
    await api(`${API}/feed/${card.id}/swipe`, {
      method: 'POST',
      body: JSON.stringify({ direction, analyst: getAnalystName() }),
    });

    // Remove card from stack
    feedCards = feedCards.filter(c => c.id !== card.id);

    // Show coach modal after a moment
    setTimeout(() => showCoach(card.id), 400);

    // Re-render
    setTimeout(renderFeed, 300);

    // Update glance badge
    loadGlanceBadge();
  } catch (e) {
    // Re-render to restore card
    renderFeed();
  }
}

// ---- Coach Modal ----

async function showCoach(alertId) {
  try {
    const data = await api(`${API}/coach/${alertId}`);
    if (data._offline) return;

    const modal = document.getElementById('coach-modal');
    modal.querySelector('.coach-title').textContent = data.lesson_title;
    modal.querySelector('.coach-body').textContent = data.lesson_body;
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
}

function setStatus(id, ok) {
  const el = document.getElementById(id);
  el.querySelector('.status-dot').className = 'status-dot ' + (ok ? 'ok' : 'fail');
  el.querySelector('.settings-item-value span').textContent = ok ? 'Connected' : 'Offline';
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

  // Coach modal — close on overlay click
  const modal = document.getElementById('coach-modal');
  if (modal) {
    modal.addEventListener('click', (e) => {
      if (e.target === modal) closeCoach();
    });
  }

  // Load initial screen
  navigate('glance');

  // Auto-refresh glance every 30s
  setInterval(() => {
    if (currentScreen === 'glance') loadGlance();
  }, 30000);
});

// ---- Service Worker Registration ----

if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('/sw.js', { scope: '/' }).catch(() => {});
}
