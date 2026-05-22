const state = {
  userId: 'u_' + Math.random().toString(36).slice(2, 10),
  ws: null,
  terminal: null,
};

function $(id) { return document.getElementById(id); }

function authHeaders() {
  const el = document.getElementById('api-key-input');
  const key = el ? el.value.trim() : '';
  return key ? { 'Authorization': 'Bearer ' + key } : {};
}

async function authFetch(url, opts = {}) {
  opts.headers = { ...(opts.headers || {}), ...authHeaders() };
  return fetch(url, opts);
}

async function fetchIdentity() {
  try {
    const res = await authFetch('/api/whoami');
    console.log('fetchIdentity:', res.status, res.ok);
    if (!res.ok) {
      const el = document.getElementById('identity-display');
      if (el) el.innerHTML = '<span style="color:#8b949e">未登录</span>';
      return;
    }
    const data = await res.json();
    const el = document.getElementById('identity-display');
    if (el) {
      if (!data.role || data.role === 'anonymous') {
        el.innerHTML = '<span style="color:#8b949e">未登录</span>';
        return;
      }
      const roleColors = { admin: '#3fb950', operator: '#d29922', viewer: '#58a6ff' };
      const roleLabels = { admin: '管理员', operator: '运维', viewer: '访客' };
      const color = roleColors[data.role] || '#8b949e';
      const label = roleLabels[data.role] || data.role;
      el.innerHTML = `<span style="color:${color};font-weight:600">${label}</span> <span style="color:var(--text-muted)">|</span> <span style="color:#c9d1d9">${data.user_id || '?'}</span>`;
    }
  } catch (e) { /* server may not be running */ }
}

async function fetchPosture() {
  try {
    const res = await fetch('/api/posture');
    const data = await res.json();
    const badge = document.getElementById('posture-badge');
    if (badge) {
      badge.textContent = data.posture;
      badge.style.background = data.posture === 'restrictive'
        ? 'rgba(248,81,73,0.2)' : data.posture === 'permissive'
        ? 'rgba(63,185,80,0.15)' : 'rgba(88,166,255,0.15)';
      badge.style.color = data.posture === 'restrictive'
        ? '#f85149' : data.posture === 'permissive'
        ? '#3fb950' : '#58a6ff';
      badge.style.cursor = 'pointer';
      badge.title = 'veto:' + data.veto_count + ' | click for drift log';
      badge.onclick = () => {
        const log = data.drift_log || [];
        const lines = log.map(e => `[${e.ts.slice(0,19)}] ${e.from} → ${e.to} (${e.reason})`);
        alert('Posture: ' + data.posture + '\nVeto: ' + data.veto_count + '\n\nDrift Log:\n' + (lines.length ? lines.join('\n') : '(none)'));
      };
    }
  } catch (e) {}
}

document.addEventListener('DOMContentLoaded', () => {
  // Restore saved API key
  const saved = localStorage.getItem('apiKey');
  if (saved) {
    const el = document.getElementById('api-key-input');
    if (el) el.value = saved;
  }
  fetchIdentity();
  fetchContext();
  fetchPosture();
  connectWS();
  bindEvents();
  initTerminal();
  setInterval(fetchContext, 15000);
  setInterval(fetchPosture, 30000);
  verifyChain();
  setInterval(verifyChain, 60000);
  // Login button refreshes identity
  const loginBtn = document.getElementById('btn-login');
  if (loginBtn) {
    loginBtn.addEventListener('click', () => { fetchIdentity(); fetchContext(); });
  }
});

function bindEvents() {
  $('btn-send').addEventListener('click', sendMessage);
  $('chat-input').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') sendMessage();
  });
}

async function fetchContext() {
  try {
    const res = await authFetch('/api/context');
    const data = await res.json();
    renderContext(data.system);
  } catch (e) { /* server may not be running yet */ }
}

function renderContext(sys) {
  const mem = sys.memory || {};
  const disk = sys.disk || {};
  const svcs = sys.services || [];
  const procs = sys.processes || [];

  let html = '';
  html += `<div class="metric"><div class="metric-label">内存</div><div class="metric-value">${mem.used || '?'} / ${mem.total || '?'}</div></div>`;
  html += `<div class="metric"><div class="metric-label">磁盘</div><div class="metric-value ${(parseInt(disk.use_pct)||0) > 80 ? 'warn' : 'ok'}">${disk.use_pct || '?'}</div></div>`;
  html += `<div class="metric"><div class="metric-label">服务</div>`;
  svcs.forEach(s => {
    const cls = s.state === 'running' ? 'running' : 'stopped';
    html += `<div class="service-item"><span>${s.unit.replace('.service','')}</span><span class="${cls}">${s.state}</span></div>`;
  });
  html += `</div>`;
  html += `<div class="metric"><div class="metric-label">进程 (TOP 5)</div>`;
  procs.forEach(p => {
    html += `<div class="process-item"><span>${(p.command||'').slice(0,25)}</span><span style="font-size:10px;color:var(--text-muted)">${p.mem}%</span></div>`;
  });
  html += `</div>`;
  $('context-content').innerHTML = html;
}

async function sendMessage() {
  const input = $('chat-input');
  const text = input.value.trim();
  if (!text) return;

  addMessage(text, 'user');
  input.value = '';
  $('btn-send').disabled = true;
  addAuditEvent('receive', text.slice(0, 60));

  try {
    const res = await authFetch('/api/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ user_id: state.userId, input: text }),
    });
    const data = await res.json();

    addMessage(data.response, 'agent');

    if (data.risk_awareness === 'VETOED') {
      addAuditEvent('veto', data.response.slice(0, 60));
    } else if (data.risk_awareness === 'CONFIRMATION_REQUIRED') {
      addAuditEvent('confirm', '需要用户确认');
      const ids = data.pending_event_ids || [];
      if (ids.length > 0) {
        addConfirmButtons(ids);
      }
    } else {
      addAuditEvent('completed', data.commands?.length ? `${data.commands.length} commands executed` : 'query completed');
    }

    if (data.commands) {
      data.commands.forEach(c => {
        if (state.terminal) {
          state.terminal.writeln(`\x1b[33m$ ${c.command}\x1b[0m`);
          if (c.risk_label) state.terminal.writeln(`  risk: ${c.risk_label}`);
        }
      });
    }
  } catch (err) {
    addMessage('请求失败，请检查后端是否运行。', 'agent');
    addAuditEvent('error', 'request failed');
  } finally {
    $('btn-send').disabled = false;
  }
}

function addMessage(text, sender) {
  const div = document.createElement('div');
  div.className = `msg msg-${sender}`;
  div.innerHTML = `<div class="label">${sender === 'user' ? '你' : 'Agent'}</div><div class="content">${escapeHtml(text)}</div>`;
  $('chat-messages').appendChild(div);
  $('chat-messages').scrollTop = $('chat-messages').scrollHeight;
}

function addConfirmButtons(eventIds) {
  const div = document.createElement('div');
  div.className = 'confirm-bar';
  div.innerHTML = `
    <span class="confirm-hint">${eventIds.length} 个操作待确认</span>
    <button class="btn-confirm btn-approve">允许执行</button>
    <button class="btn-confirm btn-deny">拒绝</button>
  `;
  div.querySelector('.btn-approve').addEventListener('click', () => confirmCommands(eventIds, true));
  div.querySelector('.btn-deny').addEventListener('click', () => confirmCommands(eventIds, false));
  $('chat-messages').appendChild(div);
  $('chat-messages').scrollTop = $('chat-messages').scrollHeight;
}

async function confirmCommands(eventIds, confirmed) {
  const action = confirmed ? 'approve' : 'deny';
  for (const eid of eventIds) {
    try {
      const res = await authFetch('/api/confirm', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ user_id: state.userId, event_id: eid, confirmed }),
      });
      const data = await res.json();
      if (confirmed && data.status === 'executed') {
        const result = data.exit_code === 0
          ? `执行成功 (exit ${data.exit_code})${data.stdout ? '\\n' + data.stdout.slice(0, 200) : ''}`
          : `执行失败 (exit ${data.exit_code})${data.stderr ? '\\n' + data.stderr.slice(0, 200) : ''}`;
        addMessage(`${data.command}\n→ ${result}`, 'agent');
        addAuditEvent('executed', `${data.command} → exit ${data.exit_code}`);
      } else if (confirmed && data.status === 'denied') {
        addMessage(`操作被拒绝: ${data.message || ''}`, 'agent');
        addAuditEvent('denied', data.message || 'denied');
      } else {
        addAuditEvent(action, data.message || data.status);
      }
    } catch (err) {
      addAuditEvent('error', `${action} failed for ${eid}`);
    }
  }
  // Remove confirm bar after handling
  const bars = document.querySelectorAll('.confirm-bar');
  bars.forEach(b => b.remove());
}

function addAuditEvent(type, detail) {
  const div = document.createElement('div');
  div.className = `audit-event ${type.split('_')[0]}`;
  div.innerHTML = `<span class="ts">${new Date().toLocaleTimeString()}</span> ${type}: ${detail}`;
  const content = $('audit-content');
  content.insertBefore(div, content.firstChild);
  if (content.children.length > 50) content.removeChild(content.lastChild);
}

function connectWS() {
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const url = `${proto}//${location.host}/stream`;
  state.ws = new WebSocket(url);
  state.ws.onmessage = (e) => {
    try {
      const data = JSON.parse(e.data);
      if (data.type === 'agent_log' && data.message && state.terminal) {
        state.terminal.writeln(`\x1b[36m${data.message.slice(0, 200)}\x1b[0m`);
      }
      if (data.type === 'alert') {
        const color = data.severity === 'critical' ? '#f85149' : '#d29922';
        const icon = data.severity === 'critical' ? '!' : '~';
        const msg = `[${icon} ${data.category}] ${data.message}`;
        addAuditEvent('alert_' + data.severity, msg);
        if (state.terminal) {
          state.terminal.writeln(`\x1b[${data.severity === 'critical' ? '31' : '33'}m${msg}\x1b[0m`);
        }
      }
    } catch (_) {}
  };
  state.ws.onclose = () => { setTimeout(connectWS, 3000); };
}

async function verifyChain() {
  const status = document.getElementById('chain-status');
  if (!status) return;
  status.textContent = '...';
  try {
    const res = await authFetch('/api/audit/verify');
    const data = await res.json();
    if (data.chain_valid) {
      status.textContent = data.event_count + ' OK';
      status.style.color = '#3fb950';
    } else {
      status.textContent = 'BROKEN @' + data.first_mismatch;
      status.style.color = '#f85149';
    }
  } catch(e) {
    status.textContent = 'err';
    status.style.color = '#8b949e';
  }
}

function initTerminal() {
  if (typeof Terminal === 'undefined') return;
  state.terminal = new Terminal({
    rows: 10,
    theme: { background: '#0d1117', foreground: '#c9d1d9' },
    fontSize: 12,
  });
  state.terminal.open($('terminal-container'));
  state.terminal.writeln('\x1b[32mKylin OS Security Agent Terminal\x1b[0m');
  state.terminal.writeln('Type commands in chat or use natural language.');
}

function escapeHtml(s) {
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}
