const state = {
  userId: 'u_' + Math.random().toString(36).slice(2, 10),
  ws: null,
  terminal: null,
  currentTraceId: '',
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
      const dot = document.getElementById('dot-posture');
      if (dot) dot.className = 'status-dot ' + (data.posture === 'restrictive' ? 'critical' : data.posture === 'balanced' ? 'ok' : 'warn');
      const anomalyEl = document.getElementById('anomaly-count');
      if (anomalyEl && data.veto_count !== undefined) {
        const n = data.veto_count;
        const adot = document.getElementById('dot-anomaly');
        if (adot) adot.className = 'status-dot ' + (n > 2 ? 'critical' : n > 0 ? 'warn' : 'ok');
        anomalyEl.textContent = n + ' veto';
      }
    }
  } catch (e) {}
}

async function fetchAuditHistory() {
  try {
    var today = new Date().toISOString().slice(0, 10);
    var res = await authFetch('/api/audit/trail?from_date=' + today + '&to_date=' + today + '&limit=100');
    if (!res.ok) return;
    var data = await res.json();
    var events = data.events || [];
    // Clear placeholder
    var content = document.getElementById('audit-content');
    if (content && events.length > 0) {
      content.innerHTML = '';
    }
    // Add events in chronological order (oldest first)
    events.forEach(function(e) {
      var type = e.type || 'receive';
      var detail = '';
      if (e.data) {
        if (e.data.input_text) detail = e.data.input_text.slice(0, 80);
        else if (e.data.summary) detail = e.data.summary.slice(0, 80);
        else if (e.data.command) detail = e.data.command.slice(0, 80);
        else detail = JSON.stringify(e.data).slice(0, 80);
      }
      addAuditEvent(type, detail);
    });
  } catch(e) {}
}

document.addEventListener('DOMContentLoaded', () => {
  fetchIdentity();
  fetchContext();
  fetchPosture();
  connectWS();
  bindEvents();
  initTerminal();
  // Load historical audit trail on startup
  fetchAuditHistory();
  setInterval(fetchContext, 15000);
  setInterval(fetchPosture, 30000);
  verifyChain();
  setInterval(verifyChain, 60000);
  // Login button refreshes identity
  const loginBtn = document.getElementById('btn-login');
  if (loginBtn) {
    loginBtn.addEventListener('click', () => {
      fetchIdentity();
      fetchContext();
      reconnectWS();
    });
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
  // Handle both old dict format and new list format for disk
  const diskData = Array.isArray(sys.disk) ? sys.disk[0] : (sys.disk || {});
  const svcs = sys.services || [];
  const procs = sys.processes || [];
  const container = document.getElementById('context-content');
  if (!container) return;
  container.innerHTML = ''; // clear safely

  function el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text) e.textContent = text;
    return e;
  }

  const memDiv = el('div', 'metric');
  memDiv.appendChild(el('div', 'metric-label', '内存'));
  memDiv.appendChild(el('div', 'metric-value', (mem.used || '?') + ' / ' + (mem.total || '?')));
  container.appendChild(memDiv);

  const diskPct = parseInt(diskData.use_pct) || 0;
  const diskDiv = el('div', 'metric');
  diskDiv.appendChild(el('div', 'metric-label', '磁盘'));
  diskDiv.appendChild(el('div', 'metric-value ' + (diskPct > 80 ? 'warn' : 'ok'), diskData.use_pct || '?'));
  container.appendChild(diskDiv);

  const svcDiv = el('div', 'metric');
  svcDiv.appendChild(el('div', 'metric-label', '服务'));
  svcs.forEach(s => {
    const row = el('div', 'service-item');
    row.appendChild(el('span', '', (s.unit || '').replace('.service', '')));
    row.appendChild(el('span', s.state === 'running' ? 'running' : 'stopped', s.state));
    svcDiv.appendChild(row);
  });
  container.appendChild(svcDiv);

  const procDiv = el('div', 'metric');
  procDiv.appendChild(el('div', 'metric-label', '进程 (TOP 5)'));
  procs.forEach(p => {
    const row = el('div', 'process-item');
    row.appendChild(el('span', '', (p.command || '').slice(0, 25)));
    const memSpan = el('span', '', (p.mem || '') + '%');
    memSpan.style.cssText = 'font-size:10px;color:var(--text-muted)';
    row.appendChild(memSpan);
    procDiv.appendChild(row);
  });
  container.appendChild(procDiv);
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

    // Store trace_id for audit chain display (#19)
    if (data.trace_id) state.currentTraceId = data.trace_id;

    // Update status bar
    if (data.trace_id && typeof updateTraceId === 'function') updateTraceId(data.trace_id);

    if (data.risk_awareness === 'VETOED') {
      addAuditEvent('veto', data.response.slice(0, 60));
      if (typeof flashVeto === 'function') flashVeto();
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
      // Generate stable idempotency key to prevent duplicate execution (#05)
      const idemKey = eid + '_' + (confirmed ? 'approve' : 'deny') + '_' + state.userId;
      const res = await authFetch('/api/confirm', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          event_id: eid,
          confirmed,
          idempotency_key: idemKey,
        }),
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

// Track the current interaction chain for the 5-stage audit display
let currentChain = {};

function addAuditEvent(type, detail) {
  const ts = new Date().toLocaleTimeString();
  const stageMap = {
    'receive': '📥 接收指令',
    'perceive': '🔍 感知环境',
    'route': '🧭 意图分类',
    'reason': '🧠 推理决策',
    'validate': '🛡️ 安全校验',
    'execute': '⚡ 执行结果',
    'result': '✅ 完成',
    'veto': '🚫 拦截',
    'alert': '⚠️ 告警',
  };

  const label = stageMap[type] || type;
  const div = document.createElement('div');
  div.className = `audit-event ${type.split('_')[0]}`;
  const detailText = typeof detail === 'object' ? JSON.stringify(detail).slice(0, 120) : String(detail);
  // Safe DOM creation — no innerHTML (#review-9)
  const tsSpan = document.createElement('span');
  tsSpan.className = 'ts';
  tsSpan.textContent = ts;
  const labelBold = document.createElement('b');
  labelBold.textContent = label;
  div.appendChild(tsSpan);
  div.appendChild(document.createTextNode(' '));
  div.appendChild(labelBold);
  div.appendChild(document.createTextNode(' ' + detailText));
  div.style.cursor = 'pointer';
  div.title = '点击查看完整链路';

  // Track chain stages for the current trace
  if (!currentChain.events) currentChain = {events: [], startTs: ts};
  currentChain.events.push({type, label, detail: detailText, ts});

  // Click to show full 5-stage chain detail
  div.onclick = () => showChainDetail(currentChain);

  const content = $('audit-content');
  content.insertBefore(div, content.firstChild);
  if (content.children.length > 80) content.removeChild(content.lastChild);
}

function showChainDetail(chain) {
  const detailDiv = document.getElementById('audit-chain-detail');
  if (!detailDiv) return;
  detailDiv.style.display = 'block';
  // Clear safely
  while (detailDiv.firstChild) detailDiv.removeChild(detailDiv.firstChild);

  const stages = ['receive', 'perceive', 'route', 'reason', 'validate', 'execute', 'result'];
  const title = document.createElement('div');
  title.style.cssText = 'font-weight:bold;margin-bottom:6px;color:var(--text);';
  title.textContent = '完整推理链路溯源';
  detailDiv.appendChild(title);

  const colors = {
    'veto': 'var(--danger)',
  };
  function stageColor(type) {
    if (type === 'veto' || (type && type.includes('critical'))) return 'var(--danger)';
    if (type === 'validate') return 'var(--warn)';
    if (type === 'execute') return 'var(--ok)';
    return 'var(--accent)';
  }

  for (const evt of (chain.events || [])) {
    const stageIdx = stages.indexOf(evt.type);
    const stageNum = stageIdx >= 0 ? stageIdx + 1 : '';
    const color = stageColor(evt.type);

    const row = document.createElement('div');
    row.style.cssText = `margin:3px 0;border-left:2px solid ${color};padding-left:6px;`;

    const labelSpan = document.createElement('span');
    labelSpan.style.color = color;
    labelSpan.textContent = (stageNum ? '[' + stageNum + '/' + stages.length + '] ' : '') + (evt.label || evt.type);
    row.appendChild(labelSpan);

    const detailSpan = document.createElement('div');
    detailSpan.style.cssText = 'color:var(--text-muted);font-size:10px;';
    detailSpan.textContent = evt.detail || '';
    row.appendChild(detailSpan);

    detailDiv.appendChild(row);
  }

  // Use real trace_id if available (#19)
  const traceId = chain.trace_id || (typeof state !== 'undefined' && state.currentTraceId) || '';
  const hashStr = traceId ? `Trace: ${traceId}` : `SHA256: ${chain.startTs || '?'} → ${(chain.events || []).length} events`;

  const footer = document.createElement('div');
  footer.style.cssText = 'margin-top:8px;font-size:10px;color:var(--text-muted);border-top:1px solid var(--border);padding-top:4px;';
  footer.textContent = hashStr;
  detailDiv.appendChild(footer);

  setTimeout(() => { detailDiv.style.display = 'none'; }, 30000);
}

function connectWS() {
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  // No token in URL — use post-connect auth message (#11)
  const url = `${proto}//${location.host}/stream`;
  state.ws = new WebSocket(url);
  state.ws.onopen = () => {
    // Authenticate via first message instead of URL query param
    const key = (document.getElementById('api-key-input')?.value || '').trim();
    state.ws.send(JSON.stringify({ action: 'auth', token: key }));
  };
  state.ws.onmessage = (e) => {
    try {
      const data = JSON.parse(e.data);
      // Handle auth response
      if (data.type === 'auth_ok') {
        console.log('WS authenticated as', data.role);
        return;
      }
      if (data.type === 'auth_failed' || data.type === 'auth_timeout') {
        console.warn('WS auth failed:', data.reason || data.type);
        return;
      }
      // Audit pipeline events from backend
      // Trace ID from any response
      if (data.trace_id && typeof updateTraceId === 'function') {
        updateTraceId(data.trace_id);
      }

      if (data.type === 'audit' && data.stage) {
        addAuditEvent(data.stage, data.detail || '');
        // Activate defense layer visual
        var stageToLayer = {receive:0, perceive:1, route:1, reason:2, validate:2, execute:3, veto:3};
        if (typeof activateLayer === 'function' && data.stage in stageToLayer) {
          activateLayer(stageToLayer[data.stage]);
        }
        if (data.stage === 'veto' || data.stage === 'alert_critical') {
          if (typeof flashVeto === 'function') flashVeto();
        }
      }
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

function reconnectWS() {
  if (state.ws) {
    state.ws.onclose = null;
    try { state.ws.close(); } catch (_) {}
  }
  connectWS();
}

async function verifyChain() {
  const dot = document.getElementById('dot-chain');
  const text = document.getElementById('chain-status-text');
  try {
    const res = await authFetch('/api/audit/verify');
    const data = await res.json();
    if (data.chain_valid) {
      if (dot) dot.className = 'status-dot ok';
      if (text) { text.textContent = '审计链 OK (' + data.event_count + ')'; text.style.color = '#3fb950'; }
    } else {
      if (dot) dot.className = 'status-dot critical';
      if (text) { text.textContent = '审计链断裂!'; text.style.color = '#f85149'; }
    }
  } catch(e) {
    if (dot) dot.className = 'status-dot warn';
    if (text) { text.textContent = '审计链 err'; text.style.color = '#8b949e'; }
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
