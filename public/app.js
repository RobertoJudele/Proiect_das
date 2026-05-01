
const API = '';

let currentToken = localStorage.getItem('authx_token') || null;
let currentUser = JSON.parse(localStorage.getItem('authx_user') || 'null');
window.addEventListener('DOMContentLoaded', () => {
  if (currentToken && currentUser) {
    showDashboard();
  }
});


function switchTab(tab) {
  const isLogin = tab === 'login';
  document.getElementById('login-form').classList.toggle('hidden', !isLogin);
  document.getElementById('register-form').classList.toggle('hidden', isLogin);
  document.getElementById('tab-login').classList.toggle('active', isLogin);
  document.getElementById('tab-register').classList.toggle('active', !isLogin);
  hideMsg();
}


function showMsg(text, type = 'error') {
  const el = document.getElementById('auth-msg');
  el.textContent = text;
  el.className = `msg ${type}`;
  el.classList.remove('hidden');
}
function hideMsg() {
  document.getElementById('auth-msg').classList.add('hidden');
}

async function doLogin(e) {
  e.preventDefault();
  const email = document.getElementById('login-email').value;
  const password = document.getElementById('login-password').value;

  try {
    const res = await fetch(`${API}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });
    const data = await res.json();

    if (!res.ok) {

      showMsg(`❌ ${data.error}`, 'error');
      return;
    }

    currentToken = data.token;
    currentUser = data.user;
    localStorage.setItem('authx_token', currentToken);
    localStorage.setItem('authx_user', JSON.stringify(currentUser));
    showDashboard();
  } catch {
    showMsg('Eroare de rețea', 'error');
  }
}

async function doRegister(e) {
  e.preventDefault();
  const email = document.getElementById('reg-email').value;
  const password = document.getElementById('reg-password').value;
  const role = document.getElementById('reg-role').value;

  try {
    const res = await fetch(`${API}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password, role })
    });
    const data = await res.json();
    if (!res.ok) { showMsg(`❌ ${data.error}`, 'error'); return; }
    showMsg(`✅ Cont creat! Acum te poți autentifica.`, 'success');
    switchTab('login');
  } catch {
    showMsg('Eroare de rețea', 'error');
  }
}

async function doLogout() {
  await fetch(`${API}/api/auth/logout`, { method: 'POST' });
  currentToken = null;
  currentUser = null;
  localStorage.removeItem('authx_token');
  localStorage.removeItem('authx_user');
  document.getElementById('dashboard-page').classList.add('hidden');
  document.getElementById('auth-page').classList.remove('hidden');
}

function showDashboard() {
  document.getElementById('auth-page').classList.add('hidden');
  document.getElementById('dashboard-page').classList.remove('hidden');
  document.getElementById('user-display').innerHTML =
    `${currentUser.email} <span class="badge-role">${currentUser.role}</span>`;
  loadTickets();
  loadAudit();
}

async function loadTickets() {
  const el = document.getElementById('tickets-list');
  try {
    const res = await fetch(`${API}/api/tickets`, {
      headers: { 'authorization': `Bearer ${currentToken}` }
    });
    const data = await res.json();
    if (!data.length) {
      el.innerHTML = '<p class="audit-empty">Niciun ticket</p>';
      return;
    }
    el.innerHTML = data.map(t => `
      <div class="ticket-item">
        <div class="ticket-info">
          <div class="ticket-title">${escHtml(t.title)}</div>
          <div class="ticket-meta">
            #${t.id} · owner: ${t.owner_id} · <span>${t.status}</span>
          </div>
        </div>
        <div style="display:flex;gap:.4rem;align-items:center;flex-shrink:0">
          <span class="ticket-sev sev-${t.severity}">${t.severity}</span>
          <button class="btn-danger" onclick="deleteTicket(${t.id})">✕</button>
        </div>
      </div>
    `).join('');
  } catch {
    el.innerHTML = '<p class="audit-empty">Eroare la încărcare</p>';
  }
}

async function deleteTicket(id) {
  await fetch(`${API}/api/tickets/${id}`, {
    method: 'DELETE',
    headers: { 'authorization': `Bearer ${currentToken}` }
  });
  loadTickets();
}

function openCreateModal() {
  document.getElementById('modal').classList.remove('hidden');
}
function closeModal() {
  document.getElementById('modal').classList.add('hidden');
}

async function doCreateTicket(e) {
  e.preventDefault();
  const body = {
    title: document.getElementById('t-title').value,
    description: document.getElementById('t-desc').value,
    severity: document.getElementById('t-severity').value,
  };
  await fetch(`${API}/api/tickets`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'authorization': `Bearer ${currentToken}` },
    body: JSON.stringify(body)
  });
  closeModal();
  loadTickets();
  document.getElementById('t-title').value = '';
  document.getElementById('t-desc').value = '';
}

async function loadAudit() {
  const el = document.getElementById('audit-list');
  try {
    const res = await fetch(`${API}/api/audit`, {
      headers: { 'authorization': `Bearer ${currentToken}` }
    });
    const data = await res.json();
    if (!res.ok) {
      el.innerHTML = `<p class="audit-empty" style="color:red">Eroare: ${data.error || 'Necunoscută'}</p>`;
      return;
    }
    if (!data.length) {
      el.innerHTML = '<p class="audit-empty">Log gol</p>';
      return;
    }
    el.innerHTML = data.map(l => `
      <div class="audit-item">
        <span class="audit-action">${l.action}</span>
        · user:${l.user_id} · ${l.resource} · ${l.timestamp}
      </div>
    `).join('');
  } catch {
    el.innerHTML = '<p class="audit-empty">Eroare</p>';
  }
}
async function doForgot(e) {
  e.preventDefault();
  const email = document.getElementById('forgot-email').value;
  const res = await fetch(`${API}/api/auth/forgot-password`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email })
  });
  const data = await res.json();
  const box = document.getElementById('reset-token-box');
  if (data.resetToken) {
    box.textContent = `⚠️ Token (în loc de email): ${data.resetToken}`;
    box.classList.remove('hidden');
    document.getElementById('reset-token-input').value = data.resetToken;
  } else {
    box.textContent = data.error || 'Eroare';
    box.classList.remove('hidden');
  }
}

async function doReset(e) {
  e.preventDefault();
  const token = document.getElementById('reset-token-input').value;
  const newPassword = document.getElementById('new-password').value;
  const res = await fetch(`${API}/api/auth/reset-password`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token, newPassword })
  });
  const data = await res.json();
  const box = document.getElementById('reset-token-box');
  box.textContent = res.ok ? `✅ ${data.message} (token NEINVALIDAT — reutilizabil!)` : `❌ ${data.error}`;
  box.classList.remove('hidden');
}

function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
