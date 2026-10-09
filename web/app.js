'use strict';

// BinTalk web client. Talks to the API through the same origin (Nginx), so no CORS is needed.

const API = '/api/v1';
const SESSION_KEY = 'bintalk.session';
const EDIT_WINDOW_MS = 15 * 60 * 1000; // text messages can be edited for 15 minutes

const $ = (sel) => document.querySelector(sel);

const state = {
  session: null,        // { token, refresh_token, expiresAt, user }
  conversations: [],
  groups: [],
  active: null,         // { kind: 'user' | 'group', id, title, subtitle, username? }
  messages: [],         // main chat, oldest first
  firstUnreadId: null,  // where the "New messages" divider goes in the open chat
  unread: {},           // chat key -> messages received live while not viewing
  members: {},          // group id -> members (for @mentions)
  groupRoles: {},       // group id -> { owner: user id, roles: Map(user id -> role) }
  thread: null,         // { parent, replies, groupId }
  ws: null,
  wsRetry: null,
  wsPing: null,
  refreshTimer: null,
  infoMessageId: null,  // message whose "Message info" panel is open
  pendingNew: 0,        // messages that arrived while scrolled up
  resetToken: null,     // from a password reset link (#reset=...)
  openReports: 0,       // admins: open abuse reports
  presence: new Map(),  // user id -> 'active' | 'away' (everyone else is offline)
  presencePref: 'auto', // the status you chose: 'auto' | 'away' | 'offline'
  company: null,        // the signed-in user's company (workspace)
  plans: [],            // subscription plans (landing page and billing)
  cycle: 'monthly',     // billing cycle shown on the landing page
  inviteToken: null,    // from an invitation link (#invite=...)
  paymentRef: null,     // from Chapa's return link (#payment=...)
  collapsed: {},        // sidebar section -> collapsed
};

// ---------- Helpers ----------

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === undefined || value === null || value === false) continue;
    if (key === 'class') node.className = value;
    else if (key === 'style') node.style.cssText = value; // CSSOM: allowed by the CSP, unlike style attributes
    else if (key.startsWith('on')) node.addEventListener(key.slice(2), value);
    else node.setAttribute(key, value === true ? '' : value);
  }
  for (const child of children.flat(Infinity)) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

function initials(name) {
  return (name || '?').trim().split(/\s+/).slice(0, 2).map((p) => p[0]).join('').toUpperCase();
}

// An icon from the sprite in index.html.
function icon(name, cls = '') {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('class', `ic ${cls}`.trim());
  svg.setAttribute('aria-hidden', 'true');
  const use = document.createElementNS('http://www.w3.org/2000/svg', 'use');
  use.setAttribute('href', `#i-${name}`);
  svg.append(use);
  return svg;
}

// A stable color for a person or group, derived from their id.
function hueOf(id) {
  let h = 0;
  for (const ch of String(id || '')) h = (h * 31 + ch.charCodeAt(0)) % 360;
  return h;
}

function avatarEl(name, id, cls = '') {
  return el('div', { class: `avatar ${cls}`.trim(), 'data-hue': '', style: `--hue:${hueOf(id || name)}` }, initials(name));
}

function money(amount, currency = 'ETB') {
  return `${Number(amount).toLocaleString(undefined, { maximumFractionDigits: 2 })} ${currency}`;
}

function isCompanyAdmin(user = state.session && state.session.user) {
  return !!user && (user.company_role === 'owner' || user.company_role === 'admin');
}

function isPlatformAdmin(user = state.session && state.session.user) {
  return !!user && user.role === 'admin';
}

function displayName(user) {
  return (user && (user.full_name || user.username)) || 'Unknown';
}

function formatTime(iso) {
  const d = new Date(iso);
  if (d.toDateString() === new Date().toDateString()) {
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }
  return d.toLocaleDateString([], { month: 'short', day: 'numeric' });
}

function clockTime(iso) {
  return new Date(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(0)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

function chatKey(kind, id) {
  return `${kind}:${id}`;
}

function me() {
  return state.session.user.id;
}

let toastTimer;
function toast(message, isError = false) {
  const node = $('#toast');
  node.textContent = message;
  node.classList.toggle('error', isError);
  node.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { node.hidden = true; }, 3500);
}

function debounce(fn, ms) {
  let timer;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...args), ms);
  };
}

// ---------- Session & API ----------

class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
}

function saveSession(loginResponse) {
  if (loginResponse.company) state.company = loginResponse.company;
  state.session = {
    token: loginResponse.token,
    refresh_token: loginResponse.refresh_token,
    expiresAt: Date.now() + loginResponse.expires_in * 1000,
    user: loginResponse.user,
  };
  try { localStorage.setItem(SESSION_KEY, JSON.stringify(state.session)); } catch { /* private mode */ }
  scheduleRefresh();
}

function saveSessionUser() {
  try { localStorage.setItem(SESSION_KEY, JSON.stringify(state.session)); } catch { /* private mode */ }
}

function loadSession() {
  try {
    const raw = localStorage.getItem(SESSION_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

function clearSession() {
  state.session = null;
  try { localStorage.removeItem(SESSION_KEY); } catch { /* ignore */ }
  clearTimeout(state.refreshTimer);
}

// Refresh the access token a minute before it expires so the WebSocket can always reconnect.
function scheduleRefresh() {
  clearTimeout(state.refreshTimer);
  if (!state.session) return;
  const delay = Math.max(state.session.expiresAt - Date.now() - 60_000, 5_000);
  state.refreshTimer = setTimeout(() => refreshToken(), delay);
}

let refreshing = null;
function refreshToken() {
  if (!state.session) return Promise.resolve(false);
  if (!refreshing) {
    refreshing = (async () => {
      try {
        const res = await fetch(`${API}/auth/refresh`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ refresh_token: state.session.refresh_token }),
        });
        if (!res.ok) {
          signOut('Your session expired. Please sign in again.');
          return false;
        }
        saveSession(await res.json());
        return true;
      } catch {
        return false;
      } finally {
        refreshing = null;
      }
    })();
  }
  return refreshing;
}

async function api(path, { method = 'GET', body, form, raw = false } = {}) {
  const send = () => {
    const headers = {};
    if (state.session) headers.Authorization = `Bearer ${state.session.token}`;
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    return fetch(API + path, {
      method,
      headers,
      body: form || (body !== undefined ? JSON.stringify(body) : undefined),
    });
  };

  let res = await send();
  if (res.status === 401 && state.session && !path.startsWith('/auth/')) {
    if (await refreshToken()) res = await send();
  }

  if (raw) {
    if (!res.ok) throw new ApiError(`Request failed (${res.status})`, res.status);
    return res;
  }
  const data = await res.json().catch(() => ({}));
  if (res.status === 403 && data.code === 'password_change_required' && state.session) {
    showPasswordView();
  }
  if (!res.ok) throw new ApiError(data.error || `Request failed (${res.status})`, res.status);
  return data;
}

// Uploads a FormData with progress reporting (fetch cannot report upload progress).
function apiUpload(path, formData, onProgress) {
  const attempt = () => new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open('POST', API + path);
    xhr.setRequestHeader('Authorization', `Bearer ${state.session.token}`);
    xhr.upload.onprogress = (event) => {
      if (event.lengthComputable) onProgress(event.loaded / event.total);
    };
    xhr.onload = () => {
      let data = {};
      try { data = JSON.parse(xhr.responseText); } catch { /* not JSON */ }
      if (xhr.status >= 200 && xhr.status < 300) resolve(data);
      else reject(new ApiError(data.error || `Upload failed (${xhr.status})`, xhr.status));
    };
    xhr.onerror = () => reject(new ApiError('Network error during upload', 0));
    xhr.send(formData);
  });
  return attempt().catch(async (err) => {
    if (err.status === 401 && await refreshToken()) return attempt();
    throw err;
  });
}

// Downloads a file, reporting progress (0..1) as it arrives.
async function downloadWithProgress(path, onProgress) {
  const res = await api(path, { raw: true });
  const total = Number(res.headers.get('Content-Length')) || 0;
  const type = res.headers.get('Content-Type') || '';
  if (!res.body || !total) {
    const blob = await res.blob();
    onProgress(1);
    return blob;
  }
  const reader = res.body.getReader();
  const chunks = [];
  let received = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    received += value.length;
    onProgress(Math.min(received / total, 1));
  }
  return new Blob(chunks, { type });
}

// ---------- Auth view ----------

function showOnly(viewId) {
  for (const id of ['landing-view', 'auth-view', 'password-view', 'app-view', 'admin-view']) $(`#${id}`).hidden = id !== viewId;
  window.scrollTo(0, 0);
}

function showLanding() {
  showOnly('landing-view');
  document.title = 'BinTalk · Where your company talks';
  loadPlans();
}

function showAuth(tab = 'login') {
  showOnly('auth-view');
  setAuthTab(tab);
}

const authScreens = {
  login: ['Sign in to your workspace', 'Use the email and password of your BinTalk account.'],
  signup: ['Create your company workspace', 'Choose a plan, then pay securely with Chapa (Telebirr, CBE Birr, cards).'],
  invite: ['Join your team', ''],
  checkout: ['Complete or renew your subscription', ''],
  payment: ['Payment', ''],
  forgot: ['Reset your password', ''],
  reset: ['Choose a new password', ''],
};

// tab: login | signup | invite | checkout | payment | forgot | reset
function setAuthTab(tab) {
  const [title, subtitle] = authScreens[tab] || authScreens.login;
  $('#auth-title').textContent = title;
  $('#auth-subtitle').textContent = subtitle;
  for (const name of ['login', 'signup', 'invite', 'checkout', 'forgot', 'reset']) $(`#${name}-form`).hidden = name !== tab;
  $('#payment-panel').hidden = tab !== 'payment';
  $('#auth-error').hidden = true;
  $('#auth-info').hidden = true;
  document.title = `${title} · BinTalk`;
  if (tab === 'signup' || tab === 'checkout') loadPlans().then(fillPlanSelects);
  const firstInput = document.querySelector(`#${tab}-form input:not([readonly])`);
  if (firstInput) firstInput.focus();
}

function authError(message) {
  const node = $('#auth-error');
  node.textContent = message;
  node.hidden = false;
}

function authInfo(message) {
  const node = $('#auth-info');
  node.textContent = message;
  node.hidden = false;
}

// ---------- Landing page: plans, sign-up, payments, invitations ----------

let plansLoaded = null;
function loadPlans() {
  if (!plansLoaded) {
    plansLoaded = api('/public/plans')
      .then((data) => { state.plans = data.plans; state.onlinePayment = data.online_payment; renderPlans(); })
      .catch((err) => { plansLoaded = null; $('#plan-grid').replaceChildren(el('p', { class: 'muted center' }, `Could not load plans: ${err.message}`)); });
  }
  return plansLoaded;
}

function planPrice(plan, cycle) {
  return cycle === 'yearly' ? plan.price_yearly : plan.price_monthly;
}

function planSeats(plan) {
  return plan.max_users ? `Up to ${plan.max_users} members` : 'Unlimited members';
}

function renderPlans() {
  const grid = $('#plan-grid');
  const cycle = state.cycle;
  const featured = state.plans.length > 1 ? state.plans[Math.floor(state.plans.length / 2)].code : null;
  grid.replaceChildren(...state.plans.map((p) => {
    const monthlyEquivalent = cycle === 'yearly' ? p.price_yearly / 12 : null;
    return el('article', { class: `plan-card${p.code === featured ? ' featured' : ''}` },
      p.code === featured ? el('span', { class: 'plan-tag' }, 'Most popular') : null,
      el('div', { class: 'plan-name' }, p.name),
      el('div', { class: 'muted' }, p.description),
      el('div', { class: 'plan-price' }, money(planPrice(p, cycle), p.currency), el('small', {}, cycle === 'yearly' ? ' / year' : ' / month')),
      monthlyEquivalent ? el('div', { class: 'muted small' }, `≈ ${money(monthlyEquivalent, p.currency)} per month`) : null,
      el('ul', { class: 'plan-features' },
        el('li', {}, icon('check'), planSeats(p)),
        el('li', {}, icon('check'), 'Unlimited channels and groups'),
        el('li', {}, icon('check'), 'Voice & video calls, file sharing'),
        el('li', {}, icon('check'), 'Admin console and audit log')),
      el('button', { type: 'button', class: p.code === featured ? 'primary' : 'ghost', onclick: () => openSignup(p.code) }, 'Choose ' + p.name));
  }));
}

function fillPlanSelects() {
  for (const select of [$('#signup-plan'), $('#checkout-plan')]) {
    const current = select.value;
    select.replaceChildren(...state.plans.map((p) => el('option', { value: p.code }, `${p.name} · ${planSeats(p)}`)));
    if (current) select.value = current;
  }
  $('#checkout-plan').prepend(el('option', { value: '' }, 'Keep my current plan'));
  if (!$('#checkout-plan').dataset.touched) $('#checkout-plan').value = '';
  updateSignupTotal();
}

function updateSignupTotal() {
  const plan = state.plans.find((p) => p.code === $('#signup-plan').value);
  const cycle = $('#signup-cycle').value;
  $('#signup-total').textContent = plan
    ? `${plan.name}, billed ${cycle}: ${money(planPrice(plan, cycle), plan.currency)}${state.onlinePayment === false ? ' · a BinTalk admin will activate your workspace' : ''}`
    : '';
}

function openSignup(planCode) {
  showAuth('signup');
  loadPlans().then(() => {
    if (planCode) $('#signup-plan').value = planCode;
    $('#signup-cycle').value = state.cycle;
    updateSignupTotal();
  });
}

async function withButton(form, fn) {
  const button = form.querySelector('button[type=submit]');
  button.disabled = true;
  $('#auth-error').hidden = true;
  try {
    await fn();
  } catch (err) {
    authError(err.message);
  } finally {
    button.disabled = false;
  }
}

async function handleSignup(event) {
  event.preventDefault();
  const form = event.target;
  await withButton(form, async () => {
    const data = Object.fromEntries(new FormData(form));
    const res = await api('/public/signup', { method: 'POST', body: data });
    form.reset();
    if (res.checkout_url) {
      location.assign(res.checkout_url); // Chapa's hosted checkout
      return;
    }
    showPaymentPanel(res.payment_error ? 'bad' : 'wait', res.payment_error
      || `Thanks! ${res.company.name} is registered and waiting for a BinTalk admin to activate it. You will be able to sign in as soon as it is approved.`);
  });
}

async function handleCheckout(event) {
  event.preventDefault();
  const form = event.target;
  await withButton(form, async () => {
    const data = Object.fromEntries(new FormData(form));
    const res = await api('/public/checkout', { method: 'POST', body: data });
    location.assign(res.checkout_url);
  });
}

function showPaymentPanel(kind, text, { signIn = false, retry = false } = {}) {
  showAuth('payment');
  const iconNode = $('#payment-icon');
  iconNode.className = `payment-icon ${kind}`;
  iconNode.replaceChildren(kind === 'busy' ? el('div', { class: 'spinner' }) : kind === 'ok' ? icon('check') : kind === 'bad' ? icon('x') : icon('info'));
  $('#payment-text').textContent = text;
  $('#payment-signin').hidden = !signIn;
  $('#payment-retry').hidden = !retry;
}

// After Chapa's checkout the customer returns to /#payment=<tx_ref>; the server verifies it.
async function checkPayment(attempt = 0) {
  const ref = state.paymentRef;
  if (!ref) return;
  showPaymentPanel('busy', 'Confirming your payment with Chapa…');
  try {
    const res = await api(`/public/payments/${encodeURIComponent(ref)}`);
    if (res.status === 'success') {
      history.replaceState(null, '', location.pathname);
      if (res.company_status === 'active') {
        showPaymentPanel('ok', `Payment received: ${money(res.amount, res.currency)}. ${res.company_name} is active. Sign in to start talking with your team.`, { signIn: true });
      } else {
        showPaymentPanel('ok', `Payment received: ${money(res.amount, res.currency)}. ${res.company_name} will be activated by a BinTalk admin shortly.`);
      }
    } else if (res.status === 'failed') {
      showPaymentPanel('bad', 'The payment did not go through. You can try again with “Renew / complete payment”.');
    } else if (attempt < 6) {
      setTimeout(() => checkPayment(attempt + 1), 4000);
    } else {
      showPaymentPanel('wait', 'We have not received confirmation from Chapa yet. If you completed the payment, check again in a minute.', { retry: true });
    }
  } catch (err) {
    showPaymentPanel('bad', err.message, { retry: true });
  }
}

async function openInvite(token) {
  state.inviteToken = token;
  showAuth('invite');
  try {
    const info = await api(`/public/invitations/${encodeURIComponent(token)}`);
    $('#auth-title').textContent = `Join ${info.company_name}`;
    $('#auth-subtitle').textContent = `You were invited as ${info.company_role === 'admin' ? 'an admin' : 'a member'}. Create your account to start chatting with your team.`;
    $('#invite-form').elements.email.value = info.email;
    if (!info.company_active) authInfo('The workspace is not active right now; you can still create your account.');
  } catch (err) {
    $('#invite-form').hidden = true;
    authError(err.message);
  }
}

async function handleInvite(event) {
  event.preventDefault();
  const form = event.target;
  await withButton(form, async () => {
    const data = Object.fromEntries(new FormData(form));
    await api('/auth/register', { method: 'POST', body: { ...data, invite_token: state.inviteToken } });
    const resp = await api('/auth/login', { method: 'POST', body: { email: data.email, password: data.password } });
    state.inviteToken = null;
    history.replaceState(null, '', location.pathname);
    form.reset();
    saveSession(resp);
    startApp();
    toast(`Welcome to ${state.company ? state.company.name : 'your workspace'}!`);
  });
}

async function handleForgot(event) {
  event.preventDefault();
  const form = event.target;
  const button = form.querySelector('button[type=submit]');
  button.disabled = true;
  try {
    const { email } = Object.fromEntries(new FormData(form));
    const data = await api('/auth/forgot-password', { method: 'POST', body: { email } });
    form.reset();
    setAuthTab('login');
    authInfo(`${data.message} The link is valid for 30 minutes.`
      + (location.hostname === 'localhost' ? ' (Development: open the email in Mailpit at http://localhost:8025.)' : ''));
  } catch (err) {
    authError(err.message);
  } finally {
    button.disabled = false;
  }
}

async function handleReset(event) {
  event.preventDefault();
  const form = event.target;
  const { new_password: password, confirm } = Object.fromEntries(new FormData(form));
  if (password !== confirm) {
    authError('The two passwords do not match.');
    return;
  }
  const button = form.querySelector('button[type=submit]');
  button.disabled = true;
  try {
    const data = await api('/auth/reset-password', { method: 'POST', body: { token: state.resetToken, new_password: password } });
    form.reset();
    state.resetToken = null;
    history.replaceState(null, '', location.pathname);
    setAuthTab('login');
    authInfo(data.message);
  } catch (err) {
    authError(err.message);
  } finally {
    button.disabled = false;
  }
}

// ---------- Password change ----------

let knownCurrentPassword = null; // the temporary password just used to sign in

function showPasswordView() {
  if (!$('#password-view').hidden) return;
  disconnectWS();
  showOnly('password-view');
  document.title = 'Set a new password · BinTalk';
  const form = $('#force-change-form');
  form.reset();
  $('#password-error').hidden = true;
  const known = !!knownCurrentPassword;
  $('#force-current-label').hidden = known;
  form.elements.old_password.required = !known;
  (known ? form.elements.new_password : form.elements.old_password).focus();
}

async function handleForcedChange(event) {
  event.preventDefault();
  const form = event.target;
  const values = Object.fromEntries(new FormData(form));
  const error = $('#password-error');
  if (values.new_password !== values.confirm) {
    error.textContent = 'The two passwords do not match.';
    error.hidden = false;
    return;
  }
  const button = form.querySelector('button[type=submit]');
  button.disabled = true;
  try {
    const resp = await api('/auth/change-password', {
      method: 'POST',
      body: { old_password: knownCurrentPassword || values.old_password, new_password: values.new_password },
    });
    knownCurrentPassword = null;
    saveSession(resp);
    form.reset();
    startApp();
    toast('Password changed. You are signed in.');
  } catch (err) {
    error.textContent = err.message;
    error.hidden = false;
  } finally {
    button.disabled = false;
  }
}

function showChangePassword() {
  const form = el('form', { class: 'form', onsubmit: async (event) => {
    event.preventDefault();
    const values = Object.fromEntries(new FormData(form));
    if (values.new_password !== values.confirm) {
      toast('The two new passwords do not match.', true);
      return;
    }
    try {
      const resp = await api('/auth/change-password', {
        method: 'POST', body: { old_password: values.old_password, new_password: values.new_password },
      });
      saveSession(resp);
      connectWS();
      closeModal();
      toast('Password changed. Your other devices were signed out.');
    } catch (err) {
      toast(err.message, true);
    }
  } },
  el('label', {}, 'Current password', el('input', { name: 'old_password', type: 'password', autocomplete: 'current-password', required: true })),
  el('label', {}, 'New password', el('input', { name: 'new_password', type: 'password', autocomplete: 'new-password', minlength: 8, maxlength: 72, required: true })),
  el('label', {}, 'Confirm new password', el('input', { name: 'confirm', type: 'password', autocomplete: 'new-password', minlength: 8, maxlength: 72, required: true })),
  el('p', { class: 'muted small' }, 'At least 8 characters. You will stay signed in here; other devices are signed out.'),
  el('button', { class: 'primary', type: 'submit' }, 'Change password'));
  openModal('Change password', form);
  form.querySelector('input').focus();
}

async function handleLogin(event) {
  event.preventDefault();
  const form = event.target;
  const button = form.querySelector('button');
  button.disabled = true;
  try {
    const data = Object.fromEntries(new FormData(form));
    const resp = await api('/auth/login', { method: 'POST', body: data });
    saveSession(resp);
    form.reset();
    if (resp.user.must_change_password) {
      knownCurrentPassword = data.password;
      showPasswordView();
    } else {
      startApp();
    }
  } catch (err) {
    authError(err.message);
  } finally {
    button.disabled = false;
  }
}

function confirmSignOut() {
  closeAccountMenu();
  if (calls.current && !window.confirm('Leave the call and sign out?')) return;
  signOut();
}

function signOut(message, { revoke = true } = {}) {
  if (calls.current) hangUp();
  hideIncoming();
  disconnectWS();
  if (state.session && revoke) {
    // Best effort: revoke this session's tokens on the server.
    fetch(`${API}/auth/logout`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${state.session.token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: state.session.refresh_token }),
    }).catch(() => {});
  }
  clearSession();
  clearMediaCaches();
  knownCurrentPassword = null;
  Object.assign(state, {
    conversations: [], groups: [], active: null, messages: [], unread: {}, members: {}, groupRoles: {}, thread: null,
    presence: new Map(), presencePref: 'auto',
  });
  calls.active = new Map();
  state.company = null;
  closeThread();
  showAuth('login');
  if (message) authError(message);
}

// ---------- App view ----------

function startApp() {
  const { user } = state.session;
  showOnly('app-view');
  const canAdmin = isCompanyAdmin(user) || isPlatformAdmin(user);
  $('#admin-btn').hidden = !canAdmin;
  if (canAdmin) refreshAdminBadge();
  $('#me-avatar').replaceWith(Object.assign(avatarEl(displayName(user), user.id), { id: 'me-avatar' }));
  $('#menu-name').textContent = displayName(user);
  $('#menu-username').textContent = `@${user.username}`;
  renderWorkspaceHeader();
  renderOwnPresence();
  closeChat();
  loadLists();
  connectWS();
  if (!state.company) {
    api('/auth/me').then(({ company }) => { state.company = company; renderWorkspaceHeader(); }).catch(() => {});
  }
}

function renderWorkspaceHeader() {
  const co = state.company;
  $('#ws-name').textContent = co ? co.name : 'BinTalk';
  $('#ws-plan').textContent = co && co.plan ? `${co.plan.name} plan · ${co.member_count} member${co.member_count === 1 ? '' : 's'}` : '';
  $('#welcome-title').textContent = `Welcome to ${co ? co.name : 'BinTalk'}, ${state.session.user.full_name.split(' ')[0] || state.session.user.username}`;
  $('#search-input').placeholder = co ? `Search people in ${co.name}` : 'Search people';
}

async function loadLists() {
  try {
    const [conversations, groups] = await Promise.all([api('/conversations?limit=100'), api('/groups?limit=100')]);
    state.conversations = conversations.conversations;
    state.groups = groups.groups;
    renderChatList();
  } catch (err) {
    toast(`Could not load chats: ${err.message}`, true);
  }
}
const reloadLists = debounce(loadLists, 250);

// Sidebar entries: kind 'user' (direct message) or 'group'; category 'channel' | 'group' | 'dm'.
function chatEntries() {
  const entries = state.conversations.map((c) => ({
    kind: 'user',
    category: 'dm',
    id: c.other_user.id,
    title: displayName(c.other_user),
    subtitle: `@${c.other_user.username}`,
    username: c.other_user.username,
    preview: c.last_message ? previewText(c.last_message, 'user') : 'No messages yet',
    time: c.last_message ? c.last_message.created_at : c.created_at,
    unread: c.unread_count,
    mentions: c.mention_count,
  }));
  for (const g of state.groups) {
    entries.push({
      kind: 'group',
      category: g.category || (g.group_type === 'channel' ? 'channel' : 'group'),
      id: g.id,
      title: g.name,
      subtitle: g.description || `${g.member_count} member${g.member_count === 1 ? '' : 's'}`,
      memberCount: g.member_count,
      ownerId: g.owner && g.owner.id,
      preview: g.last_message ? previewText(g.last_message, 'group') : (g.description || 'No messages yet'),
      time: g.last_message ? g.last_message.created_at : g.updated_at,
      unread: g.unread_count,
      mentions: g.mention_count,
    });
  }
  for (const e of entries) {
    const key = chatKey(e.kind, e.id);
    if (state.active && chatKey(state.active.kind, state.active.id) === key && !document.hidden) {
      e.unread = 0;
      e.mentions = 0;
    } else {
      e.unread = Math.max(e.unread, state.unread[key] || 0);
    }
  }
  return entries;
}

function categoryIcon(category) {
  return icon({ channel: 'hash', group: 'lock', dm: 'user' }[category] || 'hash');
}

function sideItem(e, activeKey) {
  return el('li', {
    class: `side-item${chatKey(e.kind, e.id) === activeKey ? ' active' : ''}${e.unread > 0 ? ' has-unread' : ''}`,
    title: e.preview,
    onclick: () => openChat(e),
  },
  e.category === 'dm' ? avatarWithPresence(e.title, e.id) : categoryIcon(e.category),
  el('span', { class: 'side-name' }, e.title),
  liveChip(calls.active.get(chatKey(e.kind, e.id))),
  e.mentions > 0 ? el('span', { class: 'badge mention-badge', title: `${e.mentions} unread mention${e.mentions === 1 ? '' : 's'}` }, '@') : null,
  e.unread > 0 ? el('span', { class: 'badge', title: `${e.unread} unread` }, e.unread) : null);
}

function renderChatList() {
  const entries = chatEntries();
  const activeKey = state.active && chatKey(state.active.kind, state.active.id);
  const byName = (a, b) => a.title.localeCompare(b.title);
  const byTime = (a, b) => new Date(b.time) - new Date(a.time);
  const lists = {
    channel: ['#channel-list', entries.filter((e) => e.category === 'channel').sort(byName)],
    group: ['#group-list', entries.filter((e) => e.category === 'group').sort(byName)],
    dm: ['#dm-list', entries.filter((e) => e.category === 'dm').sort(byTime)],
  };
  for (const [selector, items] of Object.values(lists)) {
    $(selector).replaceChildren(...items.map((e) => sideItem(e, activeKey)));
  }
  $('#chat-list-empty').hidden = entries.length > 0;

  const totalUnread = entries.reduce((sum, e) => sum + (e.unread || 0), 0);
  const name = state.company ? state.company.name : 'BinTalk';
  document.title = totalUnread > 0 ? `(${totalUnread}) ${name} · BinTalk` : `${name} · BinTalk`;
}

function attachmentOf(message) {
  return message.attachments && message.attachments[0];
}

// 'video' | 'audio' | null, from the message type or the file's MIME type (older uploads).
function mediaKind(message, file) {
  if (message.message_type === 'video' || (file && /^video\//.test(file.mime_type))) return 'video';
  if (message.message_type === 'voice' || (file && /^audio\//.test(file.mime_type))) return 'audio';
  return null;
}

function messageTypeFor(file) {
  if (file.type.startsWith('image/')) return 'image';
  if (file.type.startsWith('video/')) return 'video';
  if (file.type.startsWith('audio/')) return 'voice';
  return 'file';
}

// The note on an attachment (older messages stored the filename as their text).
function noteOf(message) {
  const file = attachmentOf(message);
  if (file && message.content === file.filename) return '';
  return message.content || '';
}

function previewText(message, kind) {
  if (message.message_type === 'system') return message.content || 'Call';
  let who = '';
  if (message.sender_id === me()) who = 'You: ';
  else if (kind === 'group' && message.sender) who = `${message.sender.full_name || message.sender.username}: `;
  const file = attachmentOf(message);
  if (message.file_id) {
    const note = noteOf(message);
    if (message.message_type === 'image') return `${who}📷 ${note || 'Photo'}`;
    const kind = mediaKind(message, file);
    if (kind === 'video') return `${who}🎬 ${note || 'Video'}`;
    if (kind === 'audio') return `${who}🎵 ${note || 'Audio'}`;
    return `${who}📎 ${note || (file ? file.filename : message.content) || 'File'}`;
  }
  return who + (message.content || '🔒 Encrypted message');
}

// A sidebar chip for a call going on in a chat.
function liveChip(dto) {
  if (!dto || !dto.participants.length) return null;
  const n = dto.participants.length;
  return el('span', {
    class: 'live-chip',
    title: `Call in progress · ${n} ${n === 1 ? 'person' : 'people'}`,
  }, '📞', ` ${n}`);
}

// ---------- Read receipts ----------

// Group messages count as read (✓✓) once every member who was in the group when it was sent has read it.
function receiptState(message, kind) {
  if (kind === 'user') {
    return message.read_at
      ? { read: true, label: `Read ${formatTime(message.read_at)}`, title: `Read ${new Date(message.read_at).toLocaleString()}` }
      : { read: false, label: 'Sent', title: 'Sent' };
  }
  const total = message.recipient_count || 0;
  const count = Math.min(message.read_count || 0, total);
  if (total > 0 && count >= total) {
    return { read: true, label: total === 1 ? 'Read' : 'Read by all', title: `Read by all ${total} recipient${total === 1 ? '' : 's'}` };
  }
  if (count > 0) return { read: false, label: `Read by ${count} of ${total}`, title: 'Right-click to see who read it' };
  return { read: false, label: 'Sent', title: 'Sent' };
}

function receipt(message, kind, { withLabel = false } = {}) {
  const { read, label, title } = receiptState(message, kind);
  const ticks = el('span', { class: `receipt${read ? ' read' : ''}`, title, 'aria-label': label }, read ? '✓✓' : '✓');
  if (!withLabel) return ticks;
  return el('span', { class: `receipt-status${read ? ' read' : ''}`, title }, ticks, label);
}

// ---------- Search ----------

const searchUsers = debounce(async (query) => {
  const results = $('#search-results');
  if (!query) {
    results.hidden = true;
    return;
  }
  try {
    const data = await api(`/users/search?q=${encodeURIComponent(query)}&limit=10`);
    const users = data.users.filter((u) => u.id !== me());
    results.replaceChildren(...(users.length ? users.map((u) => el('li', {
      class: 'item',
      onclick: () => {
        $('#search-input').value = '';
        results.hidden = true;
        openChat({ kind: 'user', category: 'dm', id: u.id, title: displayName(u), subtitle: `@${u.username}`, username: u.username });
      },
    },
    avatarWithPresence(displayName(u), u.id),
    el('div', { class: 'item-main' },
      el('div', { class: 'item-name' }, displayName(u)),
      el('div', { class: 'item-preview' }, `@${u.username}`)))) : [el('li', { class: 'empty-hint muted' }, 'No people found')]));
    results.hidden = false;
  } catch (err) {
    toast(err.message, true);
  }
}, 250);

// ---------- Chat ----------

function closeChat() {
  state.active = null;
  state.messages = [];
  state.firstUnreadId = null;
  closeThread();
  $('#chat-active').hidden = true;
  $('#chat-empty').hidden = false;
  $('#app-view').classList.remove('chat-open');
  renderChatList();
}

function isActive(kind, id) {
  return state.active && state.active.kind === kind && state.active.id === id;
}

async function openChat(chat) {
  closeThread();
  mediaNodes.clear();
  state.active = { kind: chat.kind, id: chat.id, title: chat.title, subtitle: chat.subtitle, username: chat.username };
  state.messages = [];
  state.firstUnreadId = null;
  state.pendingNew = 0;
  delete state.unread[chatKey(chat.kind, chat.id)];

  const category = chat.category || (chat.kind === 'user' ? 'dm' : 'group');
  state.active.category = category;
  state.active.ownerId = chat.ownerId;
  $('#chat-empty').hidden = true;
  $('#chat-active').hidden = false;
  $('#app-view').classList.add('chat-open');
  $('#chat-name').textContent = chat.title;
  $('#chat-icon').replaceChildren(category === 'dm' ? avatarEl(chat.title, chat.id) : categoryIcon(category));
  renderChatSubtitle();
  $('#members-btn').hidden = chat.kind !== 'group';
  $('#members-count').textContent = chat.memberCount || '';
  $('#leave-btn').hidden = chat.kind !== 'group' || chat.ownerId === me();
  $('#leave-btn').title = category === 'channel' ? 'Leave channel' : 'Leave group';
  $('#jump-new').hidden = true;
  renderCallBanner();
  updateCallButtons();
  refreshActiveCalls();
  $('#messages').replaceChildren(el('p', { class: 'muted day-divider' }, 'Loading…'));
  renderChatList();
  mainComposer.reset();
  mainComposer.focus();

  if (chat.kind === 'group') loadMembers(chat.id);

  try {
    const data = await api(`/messages/${chat.id}?limit=100`);
    if (!isActive(chat.kind, chat.id)) return;
    state.messages = data.messages.reverse();
    const firstUnread = state.messages.find((m) => m.unread);
    state.firstUnreadId = firstUnread ? firstUnread.id : null;
    renderMessages({ scrollTo: state.firstUnreadId ? 'unread' : 'bottom' });

    // Acknowledge what is now on screen (only while the tab is visible).
    if (!document.hidden) {
      markActiveChatRead();
      const conv = chat.kind === 'user' && state.conversations.find((c) => c.other_user.id === chat.id);
      if (conv) Object.assign(conv, { unread_count: 0, mention_count: 0 });
      const group = chat.kind === 'group' && state.groups.find((g) => g.id === chat.id);
      if (group) Object.assign(group, { unread_count: 0, mention_count: 0 });
      renderChatList();
    }
  } catch (err) {
    toast(`Could not load messages: ${err.message}`, true);
  }
}

function rememberGroup(group) {
  state.members[group.id] = group.members.map((m) => m.user);
  state.groupRoles[group.id] = { owner: group.owner && group.owner.id, roles: new Map(group.members.map((m) => [m.user.id, m.role])) };
  refreshModerationControls();
}

// Mirrors the server rule: admins can remove or mute anyone but the group owner, moderators only
// plain members, and nobody themselves.
function canModerate(groupId, userId) {
  const g = state.groupRoles[groupId];
  if (!g || userId === me() || userId === g.owner) return false;
  const mine = g.roles.get(me());
  const theirs = g.roles.get(userId);
  if (!theirs) return false;
  return mine === 'admin' || (mine === 'moderator' && theirs === 'member');
}

async function loadMembers(groupId, force = false) {
  if (state.members[groupId] && !force) return state.members[groupId];
  try {
    const { group } = await api(`/groups/${groupId}`);
    rememberGroup(group);
    if (isActive('group', groupId)) {
      $('#members-count').textContent = group.member_count;
      $('#chat-subtitle').textContent = group.description || `${group.member_count} member${group.member_count === 1 ? '' : 's'}`;
      $('#leave-btn').hidden = !!group.owner && group.owner.id === me();
    }
  } catch {
    state.members[groupId] = state.members[groupId] || [];
  }
  return state.members[groupId];
}

// People who can be @mentioned in the open chat.
async function mentionCandidates() {
  if (!state.active) return [];
  if (state.active.kind === 'group') {
    return (await loadMembers(state.active.id)).filter((u) => u.id !== me());
  }
  return state.active.username
    ? [{ id: state.active.id, username: state.active.username, full_name: state.active.title }]
    : [];
}

// ---------- Message rendering ----------

const mentionToken = /@([A-Za-z0-9_.-]{3,50})/g;

// Message text with @mentions highlighted (only names the server recognised as mentions).
function renderText(content, mentions) {
  const known = new Map((mentions || []).map((m) => [m.username.toLowerCase(), m]));
  if (!content.includes('@') || known.size === 0) return [content];
  const parts = [];
  let last = 0;
  for (const match of content.matchAll(mentionToken)) {
    const name = match[1].replace(/[.-]+$/, '');
    const mention = known.get(name.toLowerCase());
    if (!mention) continue;
    parts.push(content.slice(last, match.index));
    parts.push(el('span', {
      class: `mention${mention.user_id === me() ? ' mention-self' : ''}`,
      title: mention.user_id === me() ? 'You were mentioned' : `@${mention.username}`,
    }, `@${name}`));
    last = match.index + 1 + name.length;
  }
  parts.push(content.slice(last));
  return parts;
}

function mentionsMe(m) {
  return (m.mentions || []).some((x) => x.user_id === me());
}

function messageBubble(m, { inThread = false } = {}) {
  const file = attachmentOf(m);
  const note = noteOf(m);
  const noteNode = note ? el('div', { class: 'note' }, renderText(note, m.mentions)) : null;

  if (m.file_id) {
    let attachment;
    if (!file) {
      attachment = el('div', { class: 'file-chip muted' }, '📎', el('span', {}, 'Attachment no longer available'));
    } else if (m.message_type === 'image' && thumbResults.get(m.file_id) !== null) {
      attachment = imagePreview(m, file);
    } else if (mediaKind(m, file)) {
      attachment = mediaPlayer(m, file, mediaKind(m, file), `${inThread ? 't' : 'm'}:${m.id}`);
    } else {
      attachment = fileChip(m, file);
    }
    return el('div', { class: `bubble attachment-bubble${noteNode ? ' with-note' : ''}${mentionsMe(m) ? ' mentions-me' : ''}` }, attachment, noteNode);
  }
  if (m.content) {
    return el('div', { class: `bubble${mentionsMe(m) ? ' mentions-me' : ''}` }, renderText(m.content, m.mentions));
  }
  return el('div', {
    class: 'bubble undecryptable',
    title: 'This message was encrypted with a key that was lost when Vault ran in development (in-memory) mode.',
  }, '🔒 This message can\'t be decrypted (its key was lost)');
}

function fileChip(m, file) {
  return el('div', { class: 'file-chip' },
    el('span', { class: 'file-icon' }, icon('file')),
    el('span', { class: 'file-info' },
      el('span', { class: 'file-name' }, file.filename),
      el('span', { class: 'file-size' }, formatSize(file.file_size))),
    el('button', { type: 'button', onclick: () => downloadFile(m.file_id, file.filename) }, 'Download'));
}

// Consecutive messages from the same person within this time are shown without repeating the name.
const GROUP_WINDOW_MS = 5 * 60 * 1000;

/**
 * Renders one message as a Slack-style row. Options: kind ('user' | 'group'), inThread, showSender
 * (false: a compact continuation of the previous message's sender).
 */
function messageNode(m, { kind, inThread = false, showSender = true, showReceipt = false }) {
  const mine = m.sender_id === me();
  const sender = m.sender || (mine ? state.session.user : null);
  const name = mine ? displayName(state.session.user) : displayName(sender);
  const metaParts = [
    m.is_edited ? el('span', { class: 'edited', title: m.edited_at ? `Edited ${new Date(m.edited_at).toLocaleString()}` : 'Edited' }, '(edited)') : null,
    mine && showReceipt ? receipt(m, kind, { withLabel: true }) : null,
  ].filter(Boolean);
  return el('div', {
    class: `msg${mine ? ' mine' : ''}${showSender ? '' : ' compact'}`,
    'data-id': m.id,
    oncontextmenu: (event) => showMessageMenu(event, m, { kind, inThread }),
  },
  el('div', { class: 'msg-gutter' },
    showSender ? avatarEl(name, m.sender_id) : el('span', { class: 'msg-hover-time' }, clockTime(m.created_at))),
  showSender ? el('div', { class: 'msg-head' },
    el('span', { class: 'msg-author' }, name),
    el('span', { class: 'msg-time', title: new Date(m.created_at).toLocaleString() }, clockTime(m.created_at))) : null,
  messageBubble(m, { inThread }),
  metaParts.length ? el('div', { class: 'msg-meta' }, metaParts) : null,
  kind === 'group' && !inThread && m.reply_count > 0 ? threadSummary(m) : null,
  el('button', {
    type: 'button', class: 'msg-actions', title: 'More actions', 'aria-label': 'More actions',
    onclick: (event) => showMessageMenu(event, m, { kind, inThread }),
  }, icon('more')));
}

// Whether message m continues the previous message's run (same sender, close in time).
function continuesRun(prev, m) {
  return !!prev && prev.message_type !== 'system' && prev.sender_id === m.sender_id
    && new Date(m.created_at) - new Date(prev.created_at) < GROUP_WINDOW_MS;
}

function threadSummary(m) {
  return el('button', { type: 'button', class: 'thread-summary', onclick: () => openThread(m) },
    `💬 ${m.reply_count} ${m.reply_count === 1 ? 'reply' : 'replies'}`,
    m.unread_reply_count > 0 ? el('span', { class: 'badge' }, `${m.unread_reply_count} new`) : null,
    m.last_reply_at ? el('span', { class: 'muted' }, `· last ${formatTime(m.last_reply_at)}`) : null);
}

function isNearBottom(container) {
  return container.scrollHeight - container.scrollTop - container.clientHeight < 80;
}

function renderMessages({ scrollTo } = {}) {
  if (!state.active) return;
  const container = $('#messages');
  const nearBottom = isNearBottom(container);
  const nodes = [];
  let lastDay = '';

  if (state.messages.length === 0) {
    const a = state.active;
    const intro = a.category === 'channel' ? `This is the very beginning of #${a.title}.`
      : a.category === 'group' ? `This is the start of the private group ${a.title}.`
        : `This is the beginning of your direct messages with ${a.title}.`;
    nodes.push(el('div', { class: 'chat-intro' },
      el('div', { class: 'chat-intro-icon' }, a.category === 'dm' ? avatarEl(a.title, a.id) : categoryIcon(a.category)),
      el('h3', {}, a.category === 'channel' ? `#${a.title}` : a.title),
      el('p', { class: 'muted' }, intro, ' Messages are encrypted at rest.')));
  }

  let prev = null;
  const lastMine = [...state.messages].reverse().find((m) => m.sender_id === me() && m.message_type !== 'system');
  for (const m of state.messages) {
    const day = new Date(m.created_at).toDateString();
    if (day !== lastDay) {
      nodes.push(el('div', { class: 'day-divider' }, new Date(m.created_at).toLocaleDateString([], { weekday: 'long', month: 'long', day: 'numeric' })));
      lastDay = day;
      prev = null;
    }
    if (m.message_type === 'system') {
      nodes.push(el('div', { class: 'system-msg', 'data-id': m.id }, m.content || 'Call', el('span', { class: 'muted' }, ` · ${clockTime(m.created_at)}`)));
      prev = null;
      continue;
    }
    if (m.id === state.firstUnreadId) {
      nodes.push(el('div', { class: 'unread-divider', id: 'unread-divider' }, el('span', {}, 'New messages')));
      prev = null;
    }
    nodes.push(messageNode(m, { kind: state.active.kind, showSender: !continuesRun(prev, m), showReceipt: m === lastMine }));
    prev = m;
  }

  container.replaceChildren(...nodes);
  if (scrollTo === 'unread' && $('#unread-divider')) {
    $('#unread-divider').scrollIntoView({ block: 'center' });
  } else if (scrollTo === 'bottom' || nearBottom || state.messages.length < 2) {
    container.scrollTop = container.scrollHeight;
  }
}

function addMessage(message) {
  if (state.messages.some((m) => m.id === message.id)) return;
  const container = $('#messages');
  const wasNearBottom = isNearBottom(container);
  state.messages.push(message);
  renderMessages();
  if (message.sender_id === me() || wasNearBottom) {
    container.scrollTop = container.scrollHeight;
  } else {
    state.pendingNew += 1;
    const jump = $('#jump-new');
    jump.textContent = `↓ ${state.pendingNew} new message${state.pendingNew === 1 ? '' : 's'}`;
    jump.hidden = false;
  }
}

function updateMessage(updated) {
  const lists = [state.messages, state.thread ? [state.thread.parent, ...state.thread.replies] : []];
  for (const list of lists) {
    const m = list.find((x) => x && x.id === updated.id);
    if (m) {
      Object.assign(m, {
        content: updated.content, is_edited: updated.is_edited, edited_at: updated.edited_at, mentions: updated.mentions || [],
      });
    }
  }
  renderMessages();
  renderThread();
}

// ---------- Attachments ----------

// Compressed previews are fetched once per file and kept as blob URLs for the session.
// thumbResults: file id -> blob URL, or null if the image cannot be previewed.
const thumbRequests = new Map();
const thumbResults = new Map();

function loadThumbnail(fileId) {
  if (!thumbRequests.has(fileId)) {
    thumbRequests.set(fileId, api(`/files/${fileId}/thumbnail`, { raw: true })
      .then((res) => res.blob())
      .then((blob) => URL.createObjectURL(blob))
      .catch(() => null)
      .then((url) => { thumbResults.set(fileId, url); return url; }));
  }
  return thumbRequests.get(fileId);
}

function imagePreview(m, file) {
  const img = el('img', { class: 'msg-image', alt: file.filename, title: 'Click to view full size' });
  const button = el('button', { type: 'button', class: 'image-button loading', onclick: () => openImage(m, file) }, img);
  img.addEventListener('load', () => {
    button.classList.remove('loading');
    const container = button.closest('.messages');
    if (container && container.scrollHeight - container.scrollTop - container.clientHeight < img.clientHeight + 120) {
      container.scrollTop = container.scrollHeight;
    }
  });
  const show = (url) => {
    if (url) img.src = url;
    else if (button.isConnected) button.replaceWith(fileChip(m, file));
  };
  if (thumbResults.has(m.file_id)) show(thumbResults.get(m.file_id));
  else loadThumbnail(m.file_id).then(show);
  return button;
}

// Object URL of the full-size image in the lightbox; revoked when the modal closes.
let lightboxUrl = null;

function revokeLightbox() {
  if (lightboxUrl) URL.revokeObjectURL(lightboxUrl);
  lightboxUrl = null;
}

// Releases every decrypted media blob held in memory (on sign-out, so the next user of a shared
// browser cannot reach the previous user's files).
function clearMediaCaches() {
  revokeLightbox();
  for (const url of thumbResults.values()) if (url) URL.revokeObjectURL(url);
  thumbResults.clear();
  thumbRequests.clear();
  for (const entry of mediaRequests.values()) entry.promise.then((url) => URL.revokeObjectURL(url)).catch(() => {});
  mediaRequests.clear();
  for (const node of mediaNodes.values()) node.querySelector('audio, video')?.pause();
  mediaNodes.clear();
}

// Full-size original in the modal, with its note and a download button.
async function openImage(m, file) {
  openModal(file.filename, el('p', { class: 'muted' }, 'Loading full size…'));
  $('#modal .modal-card').classList.add('wide');
  try {
    const res = await api(`/files/${m.file_id}`, { raw: true });
    revokeLightbox();
    const url = URL.createObjectURL(await res.blob());
    lightboxUrl = url;
    const img = el('img', { class: 'lightbox-img', alt: file.filename, src: url });
    const note = noteOf(m);
    openModal(file.filename, img,
      note ? el('p', { class: 'lightbox-note' }, renderText(note, m.mentions)) : null,
      el('div', { class: 'modal-actions' },
        el('span', { class: 'muted small' }, formatSize(file.file_size)),
        el('button', { class: 'primary', type: 'button', onclick: () => downloadFile(m.file_id, file.filename) }, 'Download original')));
    $('#modal .modal-card').classList.add('wide');
  } catch (err) {
    openModal('Image', el('p', { class: 'error' }, err.message));
  }
}

async function downloadFile(fileId, filename) {
  try {
    const res = await api(`/files/${fileId}`, { raw: true });
    const url = URL.createObjectURL(await res.blob());
    const link = el('a', { href: url, download: filename || 'download' });
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 10_000);
  } catch (err) {
    toast(err.status === 404 ? 'File is no longer available' : `Download failed: ${err.message}`, true);
  }
}

// ---------- Audio & video ----------

const MEDIA_AUTOLOAD_BYTES = 8 * 1024 * 1024; // larger files load when the user presses play
const mediaRequests = new Map(); // file id -> { promise, listeners: Set, progress }
// Player elements are reused across re-renders (keyed by pane + message), so playback is not
// interrupted when the chat re-renders, e.g. when a read receipt arrives.
const mediaNodes = new Map();

// Loads a media file once (shared by every player showing it) and reports progress 0..1.
function loadMedia(fileId, onProgress) {
  let entry = mediaRequests.get(fileId);
  if (!entry) {
    entry = { listeners: new Set(), progress: 0 };
    entry.promise = downloadWithProgress(`/files/${fileId}`, (p) => {
      entry.progress = p;
      entry.listeners.forEach((fn) => fn(p));
    }).then((blob) => URL.createObjectURL(blob));
    entry.promise.catch(() => mediaRequests.delete(fileId)); // allow a retry
    mediaRequests.set(fileId, entry);
  }
  if (onProgress) {
    entry.listeners.add(onProgress);
    onProgress(entry.progress);
    entry.promise.finally(() => entry.listeners.delete(onProgress)).catch(() => {});
  }
  return entry.promise;
}

function mediaPlayer(m, file, kind, key) {
  if (mediaNodes.has(key)) return mediaNodes.get(key);

  const media = el(kind, { class: `msg-${kind}`, controls: true, preload: 'metadata', playsinline: true });
  const status = el('span', { class: 'media-status' });
  const wrap = el('div', { class: `media-player ${kind}` },
    media,
    el('div', { class: 'media-info' },
      el('span', { class: 'media-icon' }, kind === 'video' ? '🎬' : '🎵'),
      el('span', { class: 'file-info' },
        el('span', { class: 'file-name' }, file.filename),
        el('span', { class: 'file-size' }, formatSize(file.file_size), status)),
      el('button', { type: 'button', onclick: () => downloadFile(m.file_id, file.filename) }, 'Download')));

  const start = (autoplay) => {
    wrap.classList.add('loading');
    const loadButton = wrap.querySelector('.media-load');
    const showProgress = (p) => {
      const pct = Math.floor(p * 100);
      status.textContent = ` · buffering ${pct}%`;
      if (loadButton) {
        loadButton.disabled = true;
        loadButton.querySelector('.media-load-label').textContent = `Buffering ${pct}%`;
        loadButton.querySelector('.progress-fill').style.width = `${pct}%`;
        loadButton.setAttribute('aria-valuenow', String(pct));
      }
    };
    loadMedia(m.file_id, showProgress).then((url) => {
      wrap.classList.remove('loading');
      status.textContent = '';
      wrap.querySelector('.media-load')?.remove();
      media.hidden = false;
      media.src = url;
      if (autoplay) media.play().catch(() => {});
    }).catch(() => {
      wrap.classList.remove('loading');
      status.textContent = ' · could not load';
    });
  };
  // The player grows when its media loads; stay pinned to the newest message if we were there.
  media.addEventListener('loadedmetadata', () => {
    const container = wrap.closest('.messages');
    if (container && container.scrollHeight - container.scrollTop - container.clientHeight < wrap.offsetHeight + 120) {
      container.scrollTop = container.scrollHeight;
    }
  });
  media.addEventListener('error', () => {
    if (media.src) status.textContent = ' · this format cannot be played in your browser; download it instead';
  });

  if (file.file_size <= MEDIA_AUTOLOAD_BYTES) {
    start(false);
  } else {
    media.hidden = true;
    wrap.prepend(el('button', {
      type: 'button', class: 'media-load', role: 'progressbar', 'aria-valuemin': 0, 'aria-valuemax': 100,
      onclick: () => start(true),
    },
    el('span', { class: 'media-load-label' }, `▶ Play ${kind} (${formatSize(file.file_size)})`),
    el('span', { class: 'progress' }, el('span', { class: 'progress-fill' }))));
  }
  mediaNodes.set(key, wrap);
  return wrap;
}

// ---------- Composer (shared by the chat and thread panes) ----------

/**
 * Builds a message composer with attachment staging (file + optional note) and @mention
 * autocomplete. options.target() returns { kind, id, parentId } for the message being written.
 */
function createComposer(mount, { placeholder, notePlaceholder, target, onSent }) {
  let staged = null; // { file, previewUrl }
  let popupItems = [];
  let popupIndex = 0;

  const input = el('textarea', { rows: 1, placeholder, maxlength: 10000, class: 'composer-input', 'aria-label': 'Message' });
  const fileInput = el('input', { type: 'file', class: 'file-input', hidden: true });
  const staging = el('div', { class: 'staging', hidden: true });
  const popup = el('ul', { class: 'mention-popup', role: 'listbox', hidden: true });
  const sendButton = el('button', { class: 'send-btn', type: 'submit', title: 'Send', 'aria-label': 'Send' }, icon('send'));
  const form = el('form', { class: 'composer' },
    el('div', { class: 'composer-box' },
      staging,
      el('div', { class: 'composer-row' },
        el('button', {
          type: 'button', class: 'attach-btn', title: 'Attach a file', 'aria-label': 'Attach a file',
          onclick: () => fileInput.click(),
        }, icon('clip')),
        fileInput,
        el('div', { class: 'input-wrap' }, input, popup),
        sendButton)));
  mount.replaceChildren(form);

  const autoGrow = () => {
    input.style.height = 'auto';
    input.style.height = `${Math.min(input.scrollHeight, 140)}px`;
  };

  function unstage() {
    if (staged && staged.previewUrl) URL.revokeObjectURL(staged.previewUrl);
    staged = null;
    staging.hidden = true;
    staging.replaceChildren();
    input.placeholder = placeholder;
  }

  function stage(file) {
    unstage();
    const isImage = file.type.startsWith('image/');
    staged = { file, previewUrl: isImage ? URL.createObjectURL(file) : null };
    staging.replaceChildren(
      staged.previewUrl ? el('img', { class: 'staging-thumb', src: staged.previewUrl, alt: '' })
        : el('span', { class: 'staging-icon' }, { video: '🎬', voice: '🎵' }[messageTypeFor(file)] || '📎'),
      el('div', { class: 'file-info' },
        el('span', { class: 'file-name' }, file.name),
        el('span', { class: 'file-size' }, `${formatSize(file.size)} · add a note below (optional)`)),
      el('button', { type: 'button', class: 'ghost small', 'aria-label': 'Remove attachment', onclick: () => { unstage(); input.focus(); } }, '✕'));
    staging.hidden = false;
    input.placeholder = notePlaceholder;
    input.focus();
  }

  fileInput.addEventListener('change', () => {
    const file = fileInput.files[0];
    fileInput.value = '';
    if (file) stage(file);
  });

  // ----- @mention autocomplete -----
  function mentionQuery() {
    const before = input.value.slice(0, input.selectionStart);
    const match = before.match(/(?:^|\s)@([A-Za-z0-9_.-]*)$/);
    return match ? match[1] : null;
  }

  function closePopup() {
    popup.hidden = true;
    popupItems = [];
  }

  function renderPopup() {
    popup.replaceChildren(...popupItems.map((u, i) => el('li', {
      class: `item${i === popupIndex ? ' active' : ''}`, role: 'option',
      onmousedown: (event) => { event.preventDefault(); insertMention(u); },
    },
    avatarEl(displayName(u), u.id, 'small-avatar'),
    el('div', { class: 'item-main' },
      el('div', { class: 'item-name' }, displayName(u)),
      el('div', { class: 'item-preview' }, `@${u.username}`)))));
    popup.hidden = popupItems.length === 0;
  }

  async function updatePopup() {
    const query = mentionQuery();
    if (query === null) {
      closePopup();
      return;
    }
    const q = query.toLowerCase();
    const candidates = await mentionCandidates();
    if (mentionQuery() !== query) return; // user kept typing meanwhile
    popupItems = candidates
      .filter((u) => u.username.toLowerCase().startsWith(q)
        || (u.full_name || '').toLowerCase().split(/\s+/).some((w) => w.startsWith(q)))
      .slice(0, 6);
    popupIndex = 0;
    renderPopup();
  }

  function insertMention(user) {
    const caret = input.selectionStart;
    const before = input.value.slice(0, caret).replace(/@([A-Za-z0-9_.-]*)$/, `@${user.username} `);
    input.value = before + input.value.slice(caret);
    input.selectionStart = input.selectionEnd = before.length;
    closePopup();
    input.focus();
    autoGrow();
  }

  input.addEventListener('input', () => { autoGrow(); updatePopup(); });
  input.addEventListener('blur', () => setTimeout(closePopup, 100));
  input.addEventListener('keydown', (event) => {
    if (!popup.hidden && popupItems.length) {
      if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
        event.preventDefault();
        popupIndex = (popupIndex + (event.key === 'ArrowDown' ? 1 : -1) + popupItems.length) % popupItems.length;
        renderPopup();
        return;
      }
      if (event.key === 'Enter' || event.key === 'Tab') {
        event.preventDefault();
        insertMention(popupItems[popupIndex]);
        return;
      }
      if (event.key === 'Escape') {
        event.preventDefault();
        closePopup();
        return;
      }
    }
    if (event.key === 'Enter' && !event.shiftKey && !event.isComposing) {
      event.preventDefault();
      form.requestSubmit();
    }
  });

  // ----- sending -----
  // A failed send that is retried unchanged reuses its client_id (so the server returns the
  // original message if the first attempt actually went through) and its uploaded file.
  let pending = null; // { key, clientId, fileId }
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const t = target();
    if (!t) return;
    const content = input.value.trim();
    if (!content && !staged) return;

    const file = staged && staged.file;
    const key = [t.kind, t.id, t.parentId || '', content, file ? `${file.name}:${file.size}:${file.lastModified}` : ''].join('|');
    if (!pending || pending.key !== key) pending = { key, clientId: crypto.randomUUID(), fileId: null };
    const body = {
      content,
      message_type: 'text',
      client_id: pending.clientId,
      ...(t.kind === 'user' ? { receiver_id: t.id } : { group_id: t.id }),
      ...(t.parentId ? { parent_id: t.parentId } : {}),
    };
    sendButton.disabled = true;
    try {
      if (file && pending.fileId) {
        body.file_id = pending.fileId;
        body.message_type = messageTypeFor(file);
      } else if (file) {
        const upload = new FormData();
        upload.append('file', file);
        staging.classList.add('uploading');
        staging.querySelector('button').disabled = true;
        const sizeLabel = staging.querySelector('.file-size');
        const bar = el('span', { class: 'progress' }, el('span', { class: 'progress-fill' }));
        staging.querySelector('.file-info').append(bar);
        const uploaded = await apiUpload('/files/upload', upload, (p) => {
          const pct = Math.floor(p * 100);
          sizeLabel.textContent = p < 1 ? `Uploading ${pct}% of ${formatSize(file.size)}` : 'Processing…';
          bar.firstChild.style.width = `${pct}%`;
        });
        body.file_id = uploaded.file.id;
        body.message_type = messageTypeFor(file);
        pending.fileId = uploaded.file.id;
      }
      const data = await api('/messages', { method: 'POST', body });
      pending = null;
      input.value = '';
      autoGrow();
      unstage();
      if (file) toast(`${file.name} sent`);
      onSent(data.message, t);
    } catch (err) {
      toast(`Message not sent: ${err.message}`, true);
      if (staged) stage(staged.file); // reset the staging chip so the user can retry
    } finally {
      sendButton.disabled = false;
    }
  });

  return {
    focus: () => input.focus(),
    reset: () => { input.value = ''; autoGrow(); unstage(); closePopup(); },
  };
}

let mainComposer;
let threadComposer;

// ---------- Threads (groups) ----------

async function openThread(parent) {
  if (!state.active || state.active.kind !== 'group') return;
  state.thread = { parent, replies: [], groupId: state.active.id, loading: true };
  $('#thread-pane').hidden = false;
  $('#app-view').classList.add('thread-open');
  $('#thread-subtitle').textContent = state.active.title;
  renderThread();
  threadComposer.reset();
  threadComposer.focus();

  try {
    const data = await api(`/messages/${parent.id}/thread`);
    if (!state.thread || state.thread.parent.id !== parent.id) return;
    state.thread = { parent: data.parent, replies: data.replies, groupId: state.thread.groupId };
    const inMain = state.messages.find((m) => m.id === parent.id);
    if (inMain) {
      if (!document.hidden) inMain.unread_reply_count = 0; // acknowledged just below
      inMain.reply_count = data.parent.reply_count;
    }
    renderThread({ scrollToBottom: true });
    renderMessages();
    markThreadRead();
  } catch (err) {
    toast(`Could not load thread: ${err.message}`, true);
  }
}

function closeThread() {
  state.thread = null;
  $('#thread-pane').hidden = true;
  $('#app-view').classList.remove('thread-open');
}

function renderThread({ scrollToBottom = false } = {}) {
  if (!state.thread) return;
  const container = $('#thread-messages');
  const nearBottom = isNearBottom(container);
  const { parent, replies, loading } = state.thread;
  const count = replies.length;
  const nodes = [
    messageNode(parent, { kind: 'group', inThread: true, showSender: true }),
    el('div', { class: 'thread-divider' }, el('span', {}, loading ? 'Loading replies…' : `${count} ${count === 1 ? 'reply' : 'replies'}`)),
    ...replies.map((r, i) => messageNode(r, {
      kind: 'group', inThread: true, showSender: !continuesRun(replies[i - 1], r),
      showReceipt: r.sender_id === me() && !replies.slice(i + 1).some((x) => x.sender_id === me()),
    })),
  ];
  if (!loading && count === 0) nodes.push(el('p', { class: 'muted day-divider' }, 'No replies yet. Start the thread below.'));
  container.replaceChildren(...nodes);
  if (scrollToBottom || nearBottom) container.scrollTop = container.scrollHeight;
}

// Acknowledges the thread replies on screen, up to the newest one. Debounced: a burst of
// incoming replies results in one request.
const markThreadRead = debounce(() => {
  const t = state.thread;
  if (!t || t.loading || document.hidden || !t.replies.length) return;
  const upTo = t.replies[t.replies.length - 1].id;
  api(`/messages/${t.parent.id}/thread/read`, { method: 'POST', body: { up_to: upTo } }).catch(() => {});
}, 400);

// ---------- Message actions ----------

function closeMenu() {
  document.querySelectorAll('.msg-menu').forEach((menu) => menu.remove());
}

function canEdit(m) {
  if (m.sender_id !== me()) return false;
  if (m.file_id) return true; // notes on attachments can always be edited
  return Date.now() - new Date(m.created_at).getTime() < EDIT_WINDOW_MS && !!m.content;
}

function showMessageMenu(event, m, { kind, inThread }) {
  const mine = m.sender_id === me();
  const items = [];
  if (kind === 'group' && !inThread && !m.parent_id) {
    items.push(['Reply in thread', () => openThread(m)]);
  }
  if (!mine) items.push(['Report…', () => showReport(m)]);
  if (mine) {
    items.push([kind === 'group' ? 'Read by…' : 'Message info', () => showMessageInfo(m, kind)]);
    if (canEdit(m)) items.push([m.file_id ? (noteOf(m) ? 'Edit note' : 'Add note') : 'Edit', () => editMessage(m)]);
    items.push(['Delete', () => deleteMessage(m), 'danger']);
  }
  if (items.length === 0) return; // keep the browser's own menu
  event.preventDefault();
  event.stopPropagation();
  closeMenu();

  const menu = el('div', { class: 'context-menu msg-menu', role: 'menu' },
    items.map(([label, action, cls]) => el('button', {
      type: 'button', role: 'menuitem', class: cls,
      onclick: () => { closeMenu(); action(); },
    }, label)));
  document.body.append(menu);
  const rect = event.currentTarget && event.currentTarget.getBoundingClientRect ? event.currentTarget.getBoundingClientRect() : null;
  const x = event.clientX || (rect ? rect.left : 0);
  const y = event.clientY || (rect ? rect.bottom : 0);
  menu.style.left = `${Math.max(8, Math.min(x, window.innerWidth - menu.offsetWidth - 8))}px`;
  menu.style.top = `${Math.max(8, Math.min(y, window.innerHeight - menu.offsetHeight - 8))}px`;
  menu.querySelector('button').focus();
}

function showReport(m) {
  const reasons = [
    ['spam', 'Spam or scam'],
    ['harassment', 'Harassment or bullying'],
    ['inappropriate', 'Inappropriate or offensive content'],
    ['other', 'Something else'],
  ];
  const file = attachmentOf(m);
  const form = el('form', { class: 'form', onsubmit: async (event) => {
    event.preventDefault();
    const values = Object.fromEntries(new FormData(form));
    try {
      await api('/reports', { method: 'POST', body: { message_id: m.id, reason: values.reason, details: values.details } });
      closeModal();
      toast('Thanks. Your report was sent to the administrators.');
    } catch (err) {
      toast(err.message, true);
    }
  } },
  el('div', { class: 'info-preview' }, `${displayName(m.sender)}: `, file ? `📎 ${file.filename} ` : '', noteOf(m) || m.content || ''),
  el('fieldset', { class: 'radio-group' },
    el('legend', {}, 'What is wrong with this message?'),
    reasons.map(([value, label], i) => el('label', { class: 'radio' },
      el('input', { type: 'radio', name: 'reason', value, required: true, checked: i === 0 }), label))),
  el('label', {}, 'Details (optional)', el('textarea', { name: 'details', rows: 3, maxlength: 2000, placeholder: 'Anything that helps the admins understand the problem' })),
  el('p', { class: 'muted small' }, 'Admins will see this message and who sent it. The sender is not told who reported it.'),
  el('div', { class: 'modal-actions' },
    el('button', { type: 'button', class: 'ghost', onclick: closeModal }, 'Cancel'),
    el('button', { type: 'submit', class: 'primary danger-btn' }, 'Send report')));
  openModal('Report message', form);
}

function editMessage(m) {
  const isNote = !!m.file_id;
  const file = attachmentOf(m);
  const textarea = el('textarea', { rows: 4, maxlength: 10000, class: 'edit-input' });
  textarea.value = isNote ? noteOf(m) : m.content;
  const form = el('form', { class: 'form', onsubmit: async (event) => {
    event.preventDefault();
    const content = textarea.value.trim();
    if (!isNote && !content) return;
    try {
      const { message } = await api(`/messages/${m.id}`, { method: 'PUT', body: { content } });
      closeModal();
      updateMessage(message);
    } catch (err) {
      toast(err.message, true);
    }
  } },
  isNote && file ? el('p', { class: 'muted small' }, `Note on ${file.filename}`) : null,
  textarea,
  el('div', { class: 'modal-actions' },
    el('button', { type: 'button', class: 'ghost', onclick: closeModal }, 'Cancel'),
    el('button', { type: 'submit', class: 'primary' }, 'Save')));
  openModal(isNote ? 'Note on attachment' : 'Edit message', form);
  textarea.focus();
  textarea.setSelectionRange(textarea.value.length, textarea.value.length);
}

async function deleteMessage(m) {
  if (!confirm('Delete this message for everyone?')) return;
  try {
    await api(`/messages/${m.id}`, { method: 'DELETE' });
    removeMessage(m.id, m.parent_id);
    reloadLists();
  } catch (err) {
    toast(err.message, true);
  }
}

function removeMessage(id, parentId) {
  state.messages = state.messages.filter((m) => m.id !== id);
  if (parentId) {
    const parent = state.messages.find((m) => m.id === parentId);
    if (parent && parent.reply_count > 0) parent.reply_count -= 1;
  }
  if (state.thread) {
    if (state.thread.parent.id === id) {
      closeThread();
      toast('The message this thread belongs to was deleted');
    } else {
      state.thread.replies = state.thread.replies.filter((r) => r.id !== id);
      renderThread();
    }
  }
  renderMessages();
}

async function showMessageInfo(m, kind) {
  state.infoMessageId = m.id;
  openModal(kind === 'group' ? 'Read by' : 'Message info', el('p', { class: 'muted' }, 'Loading…'));
  await refreshMessageInfo();
}

function findMessage(id) {
  return state.messages.find((m) => m.id === id)
    || (state.thread && (state.thread.parent.id === id ? state.thread.parent : state.thread.replies.find((r) => r.id === id)));
}

async function refreshMessageInfo() {
  const id = state.infoMessageId;
  const m = id && findMessage(id);
  if (!m) return;
  try {
    const info = await api(`/messages/${id}/reads`);
    if (state.infoMessageId !== id || $('#modal').hidden) return;
    const person = (r, detail) => el('li', { class: 'item' },
      el('div', { class: 'avatar' }, initials(displayName(r.user))),
      el('div', { class: 'item-main' },
        el('div', { class: 'item-name' }, displayName(r.user)),
        el('div', { class: 'item-preview' }, `@${r.user.username}`)),
      el('span', { class: 'role' }, detail));
    const readAt = (r) => {
      const d = new Date(r.read_at);
      return d.toDateString() === new Date().toDateString()
        ? d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
        : d.toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
    };
    const file = attachmentOf(m);
    const note = noteOf(m);
    const icon = m.message_type === 'image' ? '📷' : { video: '🎬', audio: '🎵' }[mediaKind(m, file)] || '📎';
    const preview = file ? `${icon} ${file.filename}${note ? ` — ${note}` : ''}` : m.content;
    openModal(m.group_id ? 'Read by' : 'Message info',
      el('div', { class: 'info-preview' }, preview || '🔒 Encrypted message'),
      el('p', { class: 'muted small' }, `Sent ${new Date(m.created_at).toLocaleString()}`),
      el('h3', {}, `✓✓ Read by ${info.read_by.length} of ${info.recipient_count}`),
      info.read_by.length
        ? el('ul', { class: 'list' }, info.read_by.map((r) => person(r, readAt(r))))
        : el('p', { class: 'muted small' }, 'No one has read it yet.'),
      info.not_read_by.length ? [
        el('h3', {}, `✓ Not read yet (${info.not_read_by.length})`),
        el('ul', { class: 'list' }, info.not_read_by.map((r) => person(r, 'Delivered'))),
      ] : null);
  } catch (err) {
    openModal('Message info', el('p', { class: 'error' }, err.message));
  }
}

// Acknowledges the messages on screen in the open conversation, up to the newest one, which sends
// their senders a live read receipt. Debounced so a burst of messages costs one request.
const markActiveChatRead = debounce(() => {
  if (!state.active || document.hidden || !state.messages.length) return;
  const upTo = state.messages[state.messages.length - 1].id;
  api(`/messages/${state.active.id}/read`, { method: 'POST', body: { up_to: upTo } }).catch(() => {});
}, 400);

// After a reconnect, events sent while the socket was down are lost: reload what is on screen.
async function resyncAfterReconnect() {
  loadLists();
  const chat = state.active;
  if (!chat) return;
  try {
    const data = await api(`/messages/${chat.id}?limit=100`);
    if (!isActive(chat.kind, chat.id)) return;
    state.messages = data.messages.reverse();
    renderMessages();
    markActiveChatRead();
  } catch {
    // The next event or reload will catch up.
  }
}

// ---------- Real-time ----------

function connectWS() {
  disconnectWS();
  if (!state.session) return;

  let reconnecting = false;
  const start = async () => {
    if (state.session.expiresAt - Date.now() < 30_000 && !(await refreshToken())) return;
    // A short-lived, single-use ticket opens the socket, so the access token never appears in a URL.
    let ticket;
    try {
      ({ ticket } = await api('/ws-ticket', { method: 'POST' }));
    } catch {
      if (state.session) state.wsRetry = setTimeout(start, 3000);
      return;
    }
    if (!state.session) return;
    const ws = new WebSocket(`wss://${location.host}/ws/chat/${state.session.user.id}?ticket=${encodeURIComponent(ticket)}`);
    state.ws = ws;

    ws.onopen = () => {
      state.wsPing = setInterval(() => ws.readyState === WebSocket.OPEN && ws.send('{"type":"ping"}'), 25_000);
      if (activity.idle) sendActivity();
      renderOwnPresence();
      refreshActiveCalls();
      if (reconnecting) resyncAfterReconnect();
      reconnecting = true;
    };
    ws.onmessage = (event) => {
      try { handleEvent(JSON.parse(event.data)); } catch (err) { console.warn('Bad event', err); }
    };
    ws.onclose = () => {
      clearInterval(state.wsPing);
      renderOwnPresence();
      if (state.ws === ws && state.session) {
        state.wsRetry = setTimeout(start, 3000);
      }
    };
  };
  start();
}

function disconnectWS() {
  clearTimeout(state.wsRetry);
  clearInterval(state.wsPing);
  if (state.ws) {
    const ws = state.ws;
    state.ws = null;
    ws.close();
  }
}

function applyReads(list, readIds, { groupId, readAt }) {
  let changed = false;
  for (const m of list) {
    if (!m || !readIds.has(m.id) || m.sender_id !== me()) continue;
    if (groupId) {
      m.read_count = (m.read_count || 0) + 1;
      changed = true;
    } else if (!m.read_at) {
      m.read_at = readAt;
      m.read_count = 1;
      changed = true;
    }
  }
  return changed;
}

function handleEvent(event) {
  if (event.type.startsWith('call.')) {
    handleCallEvent(event);
    return;
  }
  if (event.type.startsWith('presence.')) {
    handlePresenceEvent(event);
    return;
  }
  const myId = me();
  switch (event.type) {
    case 'message.new': {
      const m = event.data;
      const key = m.group_id
        ? chatKey('group', m.group_id)
        : chatKey('user', m.sender_id === myId ? m.receiver_id : m.sender_id);
      const [kind, id] = key.split(':');
      const fromOther = m.sender_id !== myId;

      if (m.parent_id) {
        // Thread reply: show it in the open thread, and update the parent's summary in the chat.
        const threadOpen = state.thread && state.thread.parent.id === m.parent_id;
        if (threadOpen && !state.thread.replies.some((r) => r.id === m.id)) {
          state.thread.replies.push(m);
          state.thread.parent.reply_count = state.thread.replies.length;
          renderThread();
          if (fromOther) markThreadRead();
        }
        const parent = isActive(kind, id) && state.messages.find((x) => x.id === m.parent_id);
        if (parent) {
          // With the thread open its reply list is authoritative (it may already hold our own reply).
          parent.reply_count = threadOpen ? state.thread.replies.length : (parent.reply_count || 0) + 1;
          parent.last_reply_at = m.created_at;
          if (fromOther && !threadOpen) parent.unread_reply_count = (parent.unread_reply_count || 0) + 1;
          renderMessages();
        }
        if (fromOther && mentionsMe(m)) reloadLists();
        break;
      }

      if (isActive(kind, id)) {
        addMessage(m);
        if (fromOther && !document.hidden) markActiveChatRead();
        else if (fromOther) state.unread[key] = (state.unread[key] || 0) + 1;
      } else if (fromOther) {
        state.unread[key] = (state.unread[key] || 0) + 1;
      }
      reloadLists();
      break;
    }
    case 'message.updated':
      updateMessage(event.data);
      reloadLists();
      break;
    case 'messages.read': {
      // Sent once per (reader, newly read messages), so group counts can simply be incremented.
      const { message_ids: ids, read_at: readAt, group_id: groupId, reader_id: readerId } = event.data;
      if (readerId === myId) { // read on another of my tabs/devices
        reloadLists();
        break;
      }
      const readIds = new Set(ids);
      if (applyReads(state.messages, readIds, { groupId, readAt })) renderMessages();
      if (state.thread && applyReads([state.thread.parent, ...state.thread.replies], readIds, { groupId, readAt })) renderThread();
      if (state.infoMessageId && readIds.has(state.infoMessageId) && !$('#modal').hidden) refreshMessageInfo();
      if (!groupId) reloadLists();
      break;
    }
    case 'message.deleted':
      if (findMessage(event.data.id)) removeMessage(event.data.id, event.data.parent_id);
      reloadLists();
      break;
    case 'group.member_removed': {
      const { group_id: groupId, user_id: userId, removed_by: removedBy } = event.data;
      if (userId === me()) {
        const group = state.groups.find((g) => g.id === groupId);
        delete state.members[groupId];
        delete state.groupRoles[groupId];
        if (isActive('group', groupId)) {
          closeModal();
          closeChat();
        }
        if (removedBy) toast(`You were removed from ${group ? group.name : 'a group'}`);
      } else {
        loadMembers(groupId, true);
      }
      reloadLists();
      break;
    }
    case 'group.member_added':
    case 'group.updated':
      if (event.data.group_id) loadMembers(event.data.group_id, true);
      reloadLists();
      break;
    case 'account.suspended':
      signOut('Your account was suspended by an administrator.', { revoke: false });
      break;
    case 'account.password_reset':
      signOut('An administrator reset your password. Sign in with the temporary password you were given.', { revoke: false });
      break;
    case 'account.company_inactive':
      signOut('Your company\'s workspace is no longer active. Contact your workspace owner.', { revoke: false });
      break;
    case 'account.updated':
      api('/auth/me').then(({ user, company }) => {
        state.session.user = user;
        state.company = company;
        saveSessionUser();
        const canAdmin = isCompanyAdmin(user) || isPlatformAdmin(user);
        $('#admin-btn').hidden = !canAdmin;
        if (!canAdmin && !$('#admin-view').hidden) closeAdmin();
        if (canAdmin) refreshAdminBadge();
        renderWorkspaceHeader();
      }).catch(() => {});
      break;
    case 'report.new':
      refreshAdminBadge();
      if (!$('#admin-view').hidden && adminUI.tab === 'reports') showAdminTab('reports');
      break;
    default:
      break;
  }
}

// ---------- Presence ----------
//
// Everyone is Active while connected and using the app, Away after 10 minutes without input (or
// when they choose Away), and Offline when disconnected (or when they choose to appear offline).

const IDLE_AFTER_MS = 10 * 60 * 1000;
const presenceLabels = { active: 'Active', away: 'Away', offline: 'Offline' };
const activity = { last: Date.now(), idle: false };

function presenceOf(userId) {
  return state.presence.get(userId) || 'offline';
}

function presenceDot(userId) {
  const status = presenceOf(userId);
  return el('span', { class: 'presence-dot', 'data-presence-user': userId, 'data-status': status, title: presenceLabels[status] });
}

function avatarWithPresence(name, userId) {
  return el('span', { class: 'avatar-wrap' }, avatarEl(name, userId), presenceDot(userId));
}

function applyPresence(userId) {
  const status = presenceOf(userId);
  document.querySelectorAll(`[data-presence-user="${userId}"]`).forEach((node) => {
    node.dataset.status = status;
    node.title = presenceLabels[status];
  });
  if (state.active && state.active.kind === 'user' && state.active.id === userId) renderChatSubtitle();
  if (state.session && userId === me()) renderOwnPresence();
}

function renderChatSubtitle() {
  const chat = state.active;
  if (!chat) return;
  const node = $('#chat-subtitle');
  if (chat.kind !== 'user') {
    node.textContent = chat.subtitle || '';
    return;
  }
  node.replaceChildren(presenceDot(chat.id), ` ${presenceLabels[presenceOf(chat.id)]} · ${chat.subtitle || ''}`);
}

function renderOwnPresence() {
  if (!state.session) return;
  const connected = !!state.ws && state.ws.readyState === WebSocket.OPEN;
  const pref = state.presencePref;
  const status = connected ? presenceOf(me()) : 'offline';
  let label = 'Active';
  if (!connected) label = 'Connecting…';
  else if (pref === 'offline') label = 'Appearing offline';
  else if (pref === 'away') label = 'Away';
  else if (status === 'away') label = 'Away · idle';
  $('#me-presence').dataset.status = status;
  $('#me-status').textContent = label;
  $('#account-btn').title = connected ? `${label}: click to set your status` : 'Disconnected: reconnecting…';
  document.querySelectorAll('.status-option').forEach((b) => {
    b.setAttribute('aria-checked', String(b.dataset.pref === pref));
    b.classList.toggle('selected', b.dataset.pref === pref);
  });
}

async function setPresencePreference(pref) {
  closeAccountMenu();
  const previous = state.presencePref;
  state.presencePref = pref;
  renderOwnPresence();
  try {
    await api('/presence', { method: 'PUT', body: { preference: pref } });
  } catch (err) {
    state.presencePref = previous;
    renderOwnPresence();
    toast(err.message, true);
  }
}

function handlePresenceEvent(event) {
  const d = event.data;
  switch (event.type) {
    case 'presence.snapshot':
      state.presence = new Map(Object.entries(d.statuses || {}));
      state.presencePref = d.preference || 'auto';
      document.querySelectorAll('[data-presence-user]').forEach((node) => {
        node.dataset.status = presenceOf(node.dataset.presenceUser);
        node.title = presenceLabels[node.dataset.status];
      });
      renderChatSubtitle();
      renderOwnPresence();
      break;
    case 'presence.updated':
      if (d.status === 'offline') state.presence.delete(d.user_id);
      else state.presence.set(d.user_id, d.status);
      applyPresence(d.user_id);
      break;
    case 'presence.preference':
      state.presencePref = d.preference;
      renderOwnPresence();
      break;
    default:
      break;
  }
}

function sendActivity() {
  if (state.ws && state.ws.readyState === WebSocket.OPEN) {
    state.ws.send(JSON.stringify({ type: 'presence.activity', idle: activity.idle }));
  }
}

function noteActivity() {
  activity.last = Date.now();
  if (activity.idle) {
    activity.idle = false;
    sendActivity();
  }
}

function checkIdle() {
  if (calls.current) activity.last = Date.now(); // being in a call counts as active
  if (!activity.idle && Date.now() - activity.last > IDLE_AFTER_MS) {
    activity.idle = true;
    sendActivity();
  }
}

// ---------- Modals ----------

function openModal(title, ...content) {
  $('#modal-title').textContent = title;
  $('#modal-body').replaceChildren(...content.flat(Infinity).filter((c) => c !== null && c !== undefined && c !== false));
  $('#modal').hidden = false;
}

function closeModal() {
  revokeLightbox();
  $('#modal').hidden = true;
  $('#modal .modal-card').classList.remove('wide');
  $('#modal-body').replaceChildren();
  state.infoMessageId = null;
}

async function showStatus() {
  openModal('Encryption status', el('p', { class: 'muted' }, 'Checking…'));
  // Vault details are only shown to admins; everyone else sees overall health and algorithms.
  const isAdmin = isPlatformAdmin();
  try {
    const [status, key] = await Promise.all([
      api(isAdmin ? '/platform/encryption/status' : '/encryption/status').catch((err) => {
        if (err.status === 503) return { status: 'degraded', vault: {}, transit_keys: [], algorithms: {}, data_keys: [] };
        throw err;
      }),
      api('/encryption/public-key'),
    ]);
    const ok = status.status === 'operational';
    const v = status.vault || {};
    openModal('Encryption status',
      el('h3', {}, 'Overall'),
      el('span', { class: `pill ${ok ? 'ok' : 'bad'}` }, ok ? 'Operational' : 'Degraded'),
      isAdmin ? [
        el('h3', {}, 'Vault'),
        el('dl', { class: 'kv' },
          el('dt', {}, 'Reachable'), el('dd', {}, v.reachable ? 'Yes' : 'No'),
          el('dt', {}, 'Sealed'), el('dd', {}, v.sealed ? 'Yes' : 'No'),
          el('dt', {}, 'Storage'), el('dd', {},
            v.persistent ? `${v.storage_type} (persistent: keys survive restarts)` : `${v.storage_type || '–'} (in-memory: keys are lost on restart!)`),
          el('dt', {}, 'Version'), el('dd', {}, v.version || '–'),
          el('dt', {}, 'Transit key'), el('dd', {}, v.transit_key_version ? `database-encryption v${v.transit_key_version}` : '–'),
          v.error ? [el('dt', {}, 'Error'), el('dd', {}, v.error)] : null),
        el('h3', {}, 'Data keys'),
        (status.data_keys || []).length ? el('dl', { class: 'kv' }, status.data_keys.map((k) => [
          el('dt', {}, `Version ${k.version}`),
          el('dd', {}, [
            k.active ? 'Active for new messages' : 'Decrypt only',
            k.available ? '' : ' · UNAVAILABLE',
            ` · created ${new Date(k.created_at).toLocaleDateString()}`,
          ].join('')),
        ])) : el('p', { class: 'muted small' }, '–'),
      ] : null,
      el('h3', {}, 'Algorithms'),
      el('dl', { class: 'kv' }, Object.entries(status.algorithms || {}).map(([k, val]) => [
        el('dt', {}, k.replace(/_/g, ' ')), el('dd', {}, val)])),
      el('h3', {}, 'Server public key'),
      el('dl', { class: 'kv' },
        el('dt', {}, 'Algorithm'), el('dd', {}, `${key.algorithm} / ${key.hash}, ${key.key_size}-bit`),
        el('dt', {}, 'Fingerprint'), el('dd', { class: 'mono' }, key.fingerprint)));
  } catch (err) {
    openModal('Encryption status', el('p', { class: 'error' }, err.message));
  }
}

function groupEntry(g) {
  return {
    kind: 'group', category: g.category || (g.group_type === 'channel' ? 'channel' : 'group'), id: g.id, title: g.name,
    subtitle: g.description || `${g.member_count} member${g.member_count === 1 ? '' : 's'}`,
    memberCount: g.member_count, ownerId: g.owner && g.owner.id,
  };
}

// Create a channel (open to the whole company) or a private group.
function showNewGroup(category = 'group') {
  const choice = (value, iconName, title, text) => el('label', { class: 'choice' },
    el('input', { type: 'radio', name: 'category', value, checked: value === category }),
    el('span', {}, el('strong', {}, icon(iconName), title), el('span', { class: 'muted small' }, text)));
  const nameInput = el('input', { name: 'name', required: true, maxlength: 80, placeholder: 'e.g. marketing' });
  const form = el('form', { class: 'form', onsubmit: async (event) => {
    event.preventDefault();
    const data = Object.fromEntries(new FormData(form));
    const isChannel = data.category === 'channel';
    let name = data.name.trim();
    if (isChannel) name = name.toLowerCase().replace(/^#/, '').replace(/\s+/g, '-');
    try {
      const res = await api('/groups', {
        method: 'POST', body: { name, description: data.description, group_type: isChannel ? 'channel' : 'team' },
      });
      closeModal();
      await loadLists();
      openChat(groupEntry(res.group));
      toast(isChannel ? `#${name} created. Everyone in your company can find and join it.` : `${name} created. Add people from Members.`);
    } catch (err) {
      toast(err.message, true);
    }
  } },
  el('div', { class: 'choice-grid' },
    choice('channel', 'hash', 'Channel', 'Open to everyone in your company. Anyone can find and join it.'),
    choice('group', 'lock', 'Private group', 'Only people you add can see it.')),
  el('label', {}, 'Name', nameInput),
  el('label', {}, 'Description (optional)', el('input', { name: 'description', maxlength: 250, placeholder: 'What is it about?' })),
  el('div', { class: 'modal-actions' },
    el('button', { class: 'ghost', type: 'button', onclick: closeModal }, 'Cancel'),
    el('button', { class: 'primary', type: 'submit' }, 'Create')));
  openModal(category === 'channel' ? 'Create a channel' : 'Create a group', form);
  nameInput.focus();
}

// All channels of the company, to join or open.
async function showBrowseChannels() {
  openModal('Channels', el('p', { class: 'muted' }, 'Loading…'));
  try {
    const { channels } = await api('/channels');
    const list = el('div', {}, channels.length ? channels.map((ch) => el('div', { class: 'channel-row' },
      icon('hash'),
      el('div', { class: 'item-main' },
        el('div', { class: 'item-name' }, ch.name),
        el('div', { class: 'item-preview' }, `${ch.member_count} member${ch.member_count === 1 ? '' : 's'}${ch.description ? ` · ${ch.description}` : ''}`)),
      ch.is_member
        ? el('button', { type: 'button', class: 'ghost small', onclick: () => { closeModal(); openChat(groupEntry(ch)); } }, 'Open')
        : el('button', { type: 'button', class: 'primary small', onclick: async () => {
          try {
            const res = await api(`/groups/${ch.id}/join`, { method: 'POST' });
            closeModal();
            await loadLists();
            openChat(groupEntry(res.group));
            toast(`You joined #${ch.name}`);
          } catch (err) {
            toast(err.message, true);
          }
        } }, 'Join'))) : el('p', { class: 'muted' }, 'No channels yet. Create the first one!'));
    openModal('Channels', list,
      el('div', { class: 'modal-actions' },
        el('button', { type: 'button', class: 'primary', onclick: () => showNewGroup('channel') }, icon('plus'), 'Create channel')));
  } catch (err) {
    openModal('Channels', el('p', { class: 'error' }, err.message));
  }
}

// Pick a colleague to message.
function showNewDM() {
  const results = el('ul', { class: 'list' });
  const search = el('input', { type: 'search', placeholder: 'Type a name or @username', autocomplete: 'off' });
  const run = debounce(async () => {
    const q = search.value.trim();
    if (!q) { results.replaceChildren(); return; }
    try {
      const data = await api(`/users/search?q=${encodeURIComponent(q)}&limit=10`);
      const users = data.users.filter((u) => u.id !== me());
      results.replaceChildren(...(users.length ? users.map((u) => el('li', {
        class: 'item', onclick: () => { closeModal(); openChat({ kind: 'user', category: 'dm', id: u.id, title: displayName(u), subtitle: `@${u.username}`, username: u.username }); },
      }, avatarWithPresence(displayName(u), u.id),
      el('div', { class: 'item-main' }, el('div', { class: 'item-name' }, displayName(u)), el('div', { class: 'item-preview' }, `@${u.username}`))))
        : [el('li', { class: 'muted empty-hint' }, 'No one in your company matches')]));
    } catch (err) {
      toast(err.message, true);
    }
  }, 250);
  search.addEventListener('input', run);
  openModal('New message', el('p', { class: 'muted small' }, `You can message anyone in ${state.company ? state.company.name : 'your company'}.`), search, results);
  search.focus();
}

async function leaveActiveGroup() {
  const chat = state.active;
  if (!chat || chat.kind !== 'group') return;
  const what = chat.category === 'channel' ? `#${chat.title}` : chat.title;
  if (!window.confirm(`Leave ${what}?${chat.category === 'group' ? ' You will need to be added again to come back.' : ''}`)) return;
  try {
    await api(`/groups/${chat.id}/leave`, { method: 'POST' });
    closeChat();
    await loadLists();
    toast(`You left ${what}`);
  } catch (err) {
    toast(err.message, true);
  }
}

async function showMembers() {
  const groupId = state.active.id;
  openModal('Members', el('p', { class: 'muted' }, 'Loading…'));
  try {
    const { group } = await api(`/groups/${groupId}`);
    rememberGroup(group);
    const memberIds = new Set(group.members.map((m) => m.user.id));
    const results = el('ul', { class: 'list' });
    const search = el('input', { type: 'search', placeholder: 'Search people to add…', autocomplete: 'off' });

    search.addEventListener('input', debounce(async () => {
      const q = search.value.trim();
      if (!q) { results.replaceChildren(); return; }
      try {
        const data = await api(`/users/search?q=${encodeURIComponent(q)}&limit=8`);
        const candidates = data.users.filter((u) => !memberIds.has(u.id));
        results.replaceChildren(...(candidates.length ? candidates.map((u) => el('li', { class: 'item' },
          avatarEl(displayName(u), u.id),
          el('div', { class: 'item-main' },
            el('div', { class: 'item-name' }, displayName(u)),
            el('div', { class: 'item-preview' }, `@${u.username}`)),
          el('button', { class: 'ghost small', type: 'button', onclick: async () => {
            try {
              await api(`/groups/${groupId}/members`, { method: 'POST', body: { user_id: u.id, role: 'member' } });
              toast(`${displayName(u)} added`);
              showMembers();
            } catch (err) {
              toast(err.message, true);
            }
          } }, 'Add'))) : [el('li', { class: 'muted empty-hint' }, 'No one to add')]));
      } catch (err) {
        toast(err.message, true);
      }
    }, 250));

    openModal(`${group.name} · members`,
      el('ul', { class: 'list' }, group.members.map((m) => el('li', { class: 'item' },
        avatarWithPresence(displayName(m.user), m.user.id),
        el('div', { class: 'item-main' },
          el('div', { class: 'item-name' }, displayName(m.user) + (m.user.id === me() ? ' (you)' : '')),
          el('div', { class: 'item-preview' }, `@${m.user.username}`)),
        el('span', { class: 'role' }, m.user.id === (group.owner && group.owner.id) ? 'owner' : m.role),
        canModerate(groupId, m.user.id)
          ? el('button', { class: 'ghost small danger-text', type: 'button', onclick: () => removeMember(group, m.user) }, 'Remove')
          : null))),
      el('h3', {}, 'Add people'),
      search,
      results);
    $('#members-count').textContent = group.member_count;
  } catch (err) {
    openModal('Members', el('p', { class: 'error' }, err.message));
  }
}

async function removeMember(group, user) {
  if (!window.confirm(`Remove ${displayName(user)} from ${group.name}? They will no longer see new messages in this group.`)) return;
  try {
    await api(`/groups/${group.id}/members/${user.id}`, { method: 'DELETE' });
    toast(`${displayName(user)} was removed from the group`);
    showMembers();
  } catch (err) {
    toast(err.message, true);
  }
}

// ---------- Voice & video calls (WebRTC) ----------
//
// Media flows directly between browsers (peer-to-peer, encrypted with DTLS-SRTP). Group calls are a
// full mesh: every participant connects to every other one, which suits small groups. The server
// only keeps call state and relays signaling (offers, answers, ICE candidates) over the WebSocket.
// Whoever joins a call sends an offer to each participant already in it.
//
// Every connection negotiates one audio and one video channel up front, so a camera or a screen
// share can be switched on and off later (replaceTrack) without renegotiating. Participants tell
// each other what they are sending ({type: 'state'} signals) so tiles show video or an avatar.

const calls = {
  current: null,            // the call this tab is in
  incoming: null,           // call DTO ringing on this device
  active: new Map(),        // chat key -> ongoing call DTO in that chat
  timer: null,
  ringer: null,
};

const SPEAKING_LEVEL = 0.035; // RMS level above which someone counts as speaking

function callChatKey(dto) {
  if (dto.group_id) return chatKey('group', dto.group_id);
  const other = dto.initiator && dto.initiator.id !== me() ? dto.initiator.id : dto.receiver_id;
  return chatKey('user', other);
}

function callTitleFor(dto) {
  if (dto.group_id) return (state.groups.find((g) => g.id === dto.group_id) || {}).name || 'Group call';
  if (dto.initiator && dto.initiator.id !== me()) return displayName(dto.initiator);
  const conv = state.conversations.find((c) => c.other_user.id === dto.receiver_id);
  return conv ? displayName(conv.other_user) : (state.active && state.active.title) || 'Call';
}

function mediaErrorMessage(err) {
  if (err && (err.name === 'NotAllowedError' || err.name === 'SecurityError')) {
    return 'Allow access to your microphone/camera in the browser to make calls.';
  }
  if (err && err.name === 'NotFoundError') return 'No microphone/camera was found.';
  return `Could not start your microphone/camera: ${err && err.message}`;
}

async function getLocalMedia(media) {
  return navigator.mediaDevices.getUserMedia({
    audio: { echoCancellation: true, noiseSuppression: true },
    video: media === 'video' ? { width: { ideal: 640 }, height: { ideal: 360 } } : false,
  });
}

function stopTracks(stream) {
  stream.getTracks().forEach((t) => t.stop());
}

function localVideoTrack(c) {
  return c.screenTrack || c.camTrack || null;
}

// Starts a call in the open chat. If one is already going on there, joins it instead.
async function startCall(media) {
  if (!state.active) return;
  if (calls.current) {
    toast('You are already in a call', true);
    return;
  }
  const chat = state.active;
  const key = chatKey(chat.kind, chat.id);
  const ongoing = calls.active.get(key);
  if (ongoing && ongoing.participants.length) {
    joinCall(ongoing, media);
    return;
  }
  let stream;
  try {
    stream = await getLocalMedia(media);
  } catch (err) {
    toast(mediaErrorMessage(err), true);
    return;
  }
  try {
    const target = chat.kind === 'user' ? { receiver_id: chat.id } : { group_id: chat.id };
    const { call } = await api('/calls', { method: 'POST', body: { media, ...target } });
    const waiting = chat.kind === 'user' ? `Calling ${chat.title}…` : 'Waiting for others to join…';
    setupCall(call, stream, chat.title, waiting);
  } catch (err) {
    stopTracks(stream);
    if (err.status === 409) { // something is already going on in this chat: join it
      await refreshActiveCalls();
      const existing = calls.active.get(key);
      if (existing) {
        joinCall(existing, media);
        return;
      }
    }
    toast(err.message, true);
  }
}

async function joinCall(dto, media) {
  if (calls.current) {
    toast('You are already in a call', true);
    return;
  }
  hideIncoming();
  let stream;
  try {
    stream = await getLocalMedia(media);
  } catch (err) {
    toast(mediaErrorMessage(err), true);
    return;
  }
  try {
    const { call } = await api(`/calls/${dto.id}/join`, { method: 'POST' });
    setupCall(call, stream, callTitleFor(call), 'Connecting…');
    for (const user of call.participants) {
      if (user.id !== me()) sendOffer(user);
    }
  } catch (err) {
    stopTracks(stream);
    toast(err.message, true);
  }
}

function setupCall(dto, stream, title, status) {
  const c = {
    id: dto.id, dto, title, chatKey: callChatKey(dto),
    stream: new MediaStream(stream.getAudioTracks()), // the audio every peer receives
    camTrack: stream.getVideoTracks()[0] || null,
    screenTrack: null,
    preview: new MediaStream(),                        // your own video, shown on your tile
    peers: new Map(),                                  // user id -> { pc, user, remote, state, tile, videoSender, pending }
    users: new Map(dto.participants.map((u) => [u.id, u])),
    startedAt: dto.started_at ? new Date(dto.started_at) : null,
    status, muted: false,
    signalChain: Promise.resolve(),
    speaking: new Map(),                               // user id -> { analyser, data, until, on }
    audioCtx: null, levelTimer: null, busy: false,
  };
  calls.current = c;
  calls.active.set(c.chatKey, dto);
  try {
    c.audioCtx = new AudioContext();
    c.audioCtx.resume().catch(() => {});
  } catch { /* speaking indicators unavailable */ }

  $('#call-title').textContent = title;
  $('#call-grid').replaceChildren();
  c.selfTile = addTile(me(), 'You', c.preview, true);
  watchSpeaking(c, me(), c.stream.getAudioTracks()[0]);
  $('#call-view').hidden = false;
  $('#call-screen').hidden = !(navigator.mediaDevices && navigator.mediaDevices.getDisplayMedia);

  refreshLocalVideo();
  updateCallStatus();
  if (dto.group_id) loadMembers(dto.group_id, true);
  clearInterval(calls.timer);
  calls.timer = setInterval(updateCallStatus, 1000);
  callsChanged();
}

function updateCallStatus() {
  const c = calls.current;
  if (!c) return;
  const connected = [...c.peers.values()].filter((p) => p.pc.connectionState === 'connected').length;
  let text = c.status;
  if (c.startedAt && connected) {
    const secs = Math.floor((Date.now() - c.startedAt.getTime()) / 1000);
    text = `${Math.floor(secs / 60)}:${String(secs % 60).padStart(2, '0')}`;
    if (c.dto.group_id) text += ` · ${connected + 1} in call`;
  }
  $('#call-status').textContent = text;
}

function addTile(userId, name, stream, isSelf) {
  const video = el('video', { autoplay: true, playsinline: true });
  video.muted = isSelf; // never play your own microphone back
  video.srcObject = stream;
  const tile = el('div', { class: `call-tile${isSelf ? ' self' : ''}`, 'data-user': userId },
    video,
    el('div', { class: 'tile-avatar' }, el('div', { class: 'avatar' }, initials(isSelf ? displayName(state.session.user) : name))),
    el('div', { class: 'tile-label' },
      el('span', { class: 'tile-muted', title: 'Muted' }, '🔇'),
      el('span', { class: 'tile-name' }, name),
      el('span', { class: 'tile-state' }, isSelf ? '' : 'connecting…')),
    isSelf ? null : el('button', {
      class: 'tile-mute-btn', type: 'button', hidden: true, title: `Mute ${name}`, 'aria-label': `Mute ${name}`,
      onclick: () => muteParticipant(userId, name),
    }, '🔇 Mute'));
  tile.video = video;
  $('#call-grid').append(tile);
  $('#call-grid').dataset.count = String($('#call-grid').children.length);
  return tile;
}

function updatePeerTile(peer) {
  const live = peer.remote.getVideoTracks().some((t) => t.readyState === 'live');
  peer.tile.classList.toggle('has-video', peer.state.video && live);
  peer.tile.classList.toggle('screen', peer.state.video && peer.state.screen);
  peer.tile.classList.toggle('muted', peer.state.muted);
  refreshModerationControls();
}

// Shows "Mute" on the tiles of people a group admin may mute (and who are not muted already).
function refreshModerationControls() {
  const c = calls.current;
  if (!c) return;
  for (const peer of c.peers.values()) {
    const btn = peer.tile.querySelector('.tile-mute-btn');
    if (btn) btn.hidden = !c.dto.group_id || peer.state.muted || !canModerate(c.dto.group_id, peer.user.id);
  }
}

async function muteParticipant(userId, name) {
  const c = calls.current;
  if (!c) return;
  try {
    await api(`/calls/${c.id}/mute`, { method: 'POST', body: { user_id: userId } });
    toast(`${name} was muted`);
  } catch (err) {
    toast(err.message, true);
  }
}

function createPeer(user, offerer) {
  const c = calls.current;
  const pc = new RTCPeerConnection({ iceServers: c.dto.ice_servers });
  const remote = new MediaStream();
  const peer = {
    pc, user, remote, pending: [], videoSender: null,
    state: { video: false, screen: false, muted: false }, // what this participant says they are sending
    tile: addTile(user.id, displayName(user), remote, false),
  };
  c.stream.getAudioTracks().forEach((track) => pc.addTrack(track, c.stream));
  if (offerer) {
    // The answerer takes over this video channel when it applies the offer (see applySignal).
    peer.videoSender = pc.addTransceiver(localVideoTrack(c) || 'video', { direction: 'sendrecv' }).sender;
  }
  pc.ontrack = (event) => {
    const track = event.track;
    if (!remote.getTracks().includes(track)) remote.addTrack(track);
    if (track.kind === 'audio') watchSpeaking(c, user.id, track);
    for (const type of ['unmute', 'mute', 'ended']) track.addEventListener(type, () => updatePeerTile(peer));
    updatePeerTile(peer);
    peer.tile.video.play().catch(() => {});
  };
  pc.onicecandidate = (event) => {
    if (event.candidate) sendSignal(user.id, { type: 'candidate', candidate: event.candidate.toJSON() });
  };
  pc.onconnectionstatechange = () => {
    const stateLabel = { connected: '', connecting: 'connecting…', disconnected: 'reconnecting…', failed: 'connection failed', new: 'connecting…' };
    peer.tile.querySelector('.tile-state').textContent = stateLabel[pc.connectionState] ?? '';
    if (pc.connectionState === 'connected') {
      if (!c.startedAt) c.startedAt = new Date();
      stopRinging();
      sendState(peer);
    }
    if (pc.connectionState === 'failed') toast(`Could not connect to ${displayName(user)} (a TURN server may be needed on this network)`, true);
    updateCallStatus();
  };
  c.peers.set(user.id, peer);
  return peer;
}

function sendSignal(to, data) {
  const c = calls.current;
  if (c && state.ws && state.ws.readyState === WebSocket.OPEN) {
    state.ws.send(JSON.stringify({ type: 'call.signal', call_id: c.id, to, data }));
  }
}

// Tells one peer (or all of them) whether you are muted and sending camera or screen video.
function sendState(peer) {
  const c = calls.current;
  if (!c) return;
  const data = { type: 'state', video: !!localVideoTrack(c), screen: !!c.screenTrack, muted: c.muted };
  for (const p of peer ? [peer] : c.peers.values()) {
    if (p.pc.connectionState === 'connected') sendSignal(p.user.id, data);
  }
}

async function sendOffer(user) {
  const peer = calls.current.peers.get(user.id) || createPeer(user, true);
  const offer = await peer.pc.createOffer();
  await peer.pc.setLocalDescription(offer);
  sendSignal(user.id, { type: 'offer', sdp: peer.pc.localDescription.sdp });
}

// Signals are applied strictly in order (an ICE candidate must not overtake its offer/answer).
function handleSignal({ call_id: callId, from, data }) {
  const c = calls.current;
  if (!c || c.id !== callId) return;
  c.signalChain = c.signalChain.then(() => applySignal(c, from, data)).catch((err) => console.warn('signal', err));
}

async function applySignal(c, from, data) {
  if (calls.current !== c) return;
  let peer = c.peers.get(from);
  const unknown = () => c.users.get(from) || { id: from, username: 'participant' };
  if (data.type === 'offer') {
    if (!peer) peer = createPeer(unknown(), false);
    await peer.pc.setRemoteDescription({ type: 'offer', sdp: data.sdp });
    if (!peer.videoSender) {
      const t = peer.pc.getTransceivers().find((x) => x.receiver.track.kind === 'video');
      if (t) {
        t.direction = 'sendrecv';
        peer.videoSender = t.sender;
        const v = localVideoTrack(c);
        if (v) await t.sender.replaceTrack(v);
      }
    }
    await flushCandidates(peer);
    const answer = await peer.pc.createAnswer();
    await peer.pc.setLocalDescription(answer);
    sendSignal(from, { type: 'answer', sdp: peer.pc.localDescription.sdp });
  } else if (data.type === 'answer' && peer) {
    await peer.pc.setRemoteDescription({ type: 'answer', sdp: data.sdp });
    await flushCandidates(peer);
  } else if (data.type === 'candidate') {
    if (peer && peer.pc.remoteDescription) await peer.pc.addIceCandidate(data.candidate);
    else {
      if (!peer) peer = createPeer(unknown(), false);
      peer.pending.push(data.candidate);
    }
  } else if (data.type === 'state' && peer) {
    peer.state = { video: !!data.video, screen: !!data.screen, muted: !!data.muted };
    updatePeerTile(peer);
  }
}

async function flushCandidates(peer) {
  while (peer.pending.length) await peer.pc.addIceCandidate(peer.pending.shift());
}

function removePeer(userId) {
  const c = calls.current;
  const peer = c && c.peers.get(userId);
  if (!peer) return;
  peer.pc.close();
  peer.tile.remove();
  c.peers.delete(userId);
  c.speaking.delete(userId);
  $('#call-grid').dataset.count = String($('#call-grid').children.length);
  updateCallStatus();
}

function cleanupCall(message) {
  const c = calls.current;
  if (!c) return;
  c.peers.forEach((peer) => peer.pc.close());
  for (const track of [...c.stream.getTracks(), c.camTrack, c.screenTrack]) if (track) track.stop();
  clearInterval(c.levelTimer);
  if (c.audioCtx) c.audioCtx.close().catch(() => {});
  calls.current = null;
  clearInterval(calls.timer);
  stopRinging();
  $('#call-view').hidden = true;
  $('#call-grid').replaceChildren();
  callsChanged();
  if (message) toast(message);
}

async function hangUp() {
  const c = calls.current;
  if (!c) return;
  cleanupCall();
  api(`/calls/${c.id}/leave`, { method: 'POST' }).catch(() => {});
}

// ----- your microphone, camera and screen -----

// Puts the current camera/screen track (or none) on your tile and on every connection.
async function refreshLocalVideo() {
  const c = calls.current;
  if (!c) return;
  const v = localVideoTrack(c);
  for (const t of c.preview.getVideoTracks()) if (t !== v) c.preview.removeTrack(t);
  if (v && !c.preview.getVideoTracks().includes(v)) c.preview.addTrack(v);
  c.selfTile.classList.toggle('has-video', !!v);
  c.selfTile.classList.toggle('screen', !!c.screenTrack);
  c.selfTile.classList.toggle('muted', c.muted);
  c.selfTile.video.play().catch(() => {});
  await Promise.all([...c.peers.values()].map((p) => p.videoSender && p.videoSender.replaceTrack(v).catch((err) => console.warn('replaceTrack', err))));
  if (calls.current !== c) return;
  sendState();
  syncCallControls();
}

function syncCallControls() {
  const c = calls.current;
  if (!c) return;
  const set = (id, on, cls, title) => {
    $(id).classList.toggle(cls, on);
    $(id).title = title;
    $(id).setAttribute('aria-label', title);
  };
  set('#call-mute', c.muted, 'off', c.muted ? 'Unmute microphone' : 'Mute microphone');
  set('#call-camera', !!c.camTrack, 'active', c.camTrack ? 'Turn camera off' : 'Turn camera on');
  set('#call-screen', !!c.screenTrack, 'active', c.screenTrack ? 'Stop sharing your screen' : 'Share your screen');
}

function toggleMute() {
  const c = calls.current;
  if (!c) return;
  c.muted = !c.muted;
  c.stream.getAudioTracks().forEach((t) => { t.enabled = !c.muted; });
  c.selfTile.classList.toggle('muted', c.muted);
  sendState();
  syncCallControls();
}

async function toggleCamera() {
  const c = calls.current;
  if (!c || c.busy) return;
  c.busy = true;
  try {
    if (c.camTrack) {
      c.camTrack.stop();
      c.camTrack = null;
    } else {
      const s = await navigator.mediaDevices.getUserMedia({ video: { width: { ideal: 640 }, height: { ideal: 360 } } });
      if (calls.current !== c) {
        stopTracks(s);
        return;
      }
      c.camTrack = s.getVideoTracks()[0];
    }
    await refreshLocalVideo();
  } catch (err) {
    toast(mediaErrorMessage(err), true);
  } finally {
    c.busy = false;
  }
}

async function toggleScreen() {
  const c = calls.current;
  if (!c || c.busy) return;
  if (c.screenTrack) {
    stopScreenShare(c);
    return;
  }
  c.busy = true;
  try {
    const s = await navigator.mediaDevices.getDisplayMedia({ video: { frameRate: { ideal: 15 } }, audio: false });
    const track = s.getVideoTracks()[0];
    if (calls.current !== c) {
      stopTracks(s);
      return;
    }
    track.contentHint = 'detail';
    // The browser's own "Stop sharing" button ends the track.
    track.addEventListener('ended', () => { if (c.screenTrack === track) stopScreenShare(c); });
    c.screenTrack = track;
    await refreshLocalVideo();
  } catch (err) {
    if (err.name !== 'NotAllowedError' && err.name !== 'AbortError') toast(`Could not share your screen: ${err.message}`, true);
  } finally {
    c.busy = false;
  }
}

function stopScreenShare(c) {
  if (!c.screenTrack) return;
  c.screenTrack.stop();
  c.screenTrack = null;
  if (calls.current === c) refreshLocalVideo();
}

// ----- speaking indicators & sounds -----

function watchSpeaking(c, userId, track) {
  if (!c.audioCtx || !track) return;
  try {
    const analyser = c.audioCtx.createAnalyser();
    analyser.fftSize = 512;
    c.audioCtx.createMediaStreamSource(new MediaStream([track])).connect(analyser);
    c.speaking.set(userId, { analyser, data: new Uint8Array(analyser.fftSize), until: 0, on: false });
  } catch {
    return;
  }
  if (!c.levelTimer) c.levelTimer = setInterval(updateSpeaking, 150);
}

function updateSpeaking() {
  const c = calls.current;
  if (!c) return;
  const now = Date.now();
  for (const [userId, s] of c.speaking) {
    s.analyser.getByteTimeDomainData(s.data);
    let sum = 0;
    for (const v of s.data) sum += ((v - 128) / 128) ** 2;
    const muted = userId === me() ? c.muted : !!(c.peers.get(userId) && c.peers.get(userId).state.muted);
    if (!muted && Math.sqrt(sum / s.data.length) > SPEAKING_LEVEL) s.until = now + 400;
    const on = now < s.until;
    if (on !== s.on) {
      s.on = on;
      document.querySelectorAll(`.call-tile[data-user="${userId}"]`)
        .forEach((n) => n.classList.toggle('speaking', on));
    }
  }
}

// ----- ringing -----

function startRinging() {
  stopRinging();
  try {
    const ctx = new AudioContext();
    const beep = () => {
      for (const [offset, freq] of [[0, 440], [0.35, 480]]) {
        const osc = ctx.createOscillator();
        const gain = ctx.createGain();
        osc.frequency.value = freq;
        gain.gain.value = 0.08;
        osc.connect(gain).connect(ctx.destination);
        osc.start(ctx.currentTime + offset);
        osc.stop(ctx.currentTime + offset + 0.3);
      }
    };
    beep();
    const interval = setInterval(beep, 2000);
    calls.ringer = { ctx, interval };
  } catch { /* audio not available */ }
}

function stopRinging() {
  if (calls.ringer) {
    clearInterval(calls.ringer.interval);
    calls.ringer.ctx.close().catch(() => {});
    calls.ringer = null;
  }
}

function showIncoming(dto) {
  calls.incoming = dto;
  const name = displayName(dto.initiator);
  const elsewhere = calls.current ? ' (you are in another call)' : '';
  $('#incoming-avatar').textContent = dto.group_id ? '#' : initials(name);
  $('#incoming-title').textContent = dto.group_id ? `${name} · ${callTitleFor(dto)}` : name;
  $('#incoming-subtitle').textContent = `Incoming ${dto.media === 'video' ? 'video' : 'voice'} call${elsewhere}`;
  $('#incoming-accept-video').hidden = dto.media !== 'video';
  $('#incoming-call').hidden = false;
  startRinging();
}

function hideIncoming() {
  calls.incoming = null;
  $('#incoming-call').hidden = true;
  if (!calls.current) stopRinging();
}

async function declineIncoming() {
  const dto = calls.incoming;
  hideIncoming();
  if (dto) api(`/calls/${dto.id}/decline`, { method: 'POST' }).catch(() => {});
}

// ----- what is going on in each chat: sidebar indicators, the "Join" banner, header buttons -----

async function refreshActiveCalls() {
  try {
    const { calls: list } = await api('/calls/active');
    const next = new Map(list.map((dto) => [callChatKey(dto), dto]));
    if (calls.current) next.set(calls.current.chatKey, calls.current.dto); // keep the live copy
    calls.active = next;
  } catch {
    return;
  }
  callsChanged();
}

function findActiveCall(callId) {
  for (const [key, dto] of calls.active) if (dto.id === callId) return [key, dto];
  return [null, null];
}

function callsChanged() {
  renderCallBanner();
  updateCallButtons();
  renderChatList();
}

function renderCallBanner() {
  const banner = $('#call-banner');
  const dto = state.active && calls.active.get(chatKey(state.active.kind, state.active.id));
  // Direct calls ring instead; the banner is for group calls you can drop into.
  if (!dto || !dto.participants.length || (calls.current && calls.current.id === dto.id) || !dto.group_id) {
    banner.hidden = true;
    return;
  }
  const names = dto.participants.map((u) => (u.id === me() ? 'You' : displayName(u)));
  const who = names.length <= 3 ? names.join(', ') : `${names.slice(0, 2).join(', ')} and ${names.length - 2} others`;
  const what = `${dto.media === 'video' ? '🎥 Video' : '📞 Voice'} call`;
  banner.replaceChildren(
    el('span', { class: 'banner-text' }, `${what} in progress · ${who}`),
    el('button', { type: 'button', class: 'primary small', onclick: () => joinCall(dto, dto.media) }, 'Join'));
  banner.hidden = false;
}

function updateCallButtons() {
  const c = calls.current;
  for (const id of ['#voice-call-btn', '#video-call-btn']) $(id).disabled = !!c;
}

function handleCallEvent(event) {
  const d = event.data;
  const c = calls.current;
  switch (event.type) {
    case 'call.incoming':
      calls.active.set(callChatKey(d), d);
      callsChanged();
      if (d.initiator.id !== me()) showIncoming(d);
      break;
    case 'call.participant_joined': {
      const [, dto] = findActiveCall(d.call_id);
      if (dto && d.user && !dto.participants.some((u) => u.id === d.user.id)) dto.participants.push(d.user);
      if (calls.incoming && calls.incoming.id === d.call_id && d.user && d.user.id === me()) hideIncoming(); // answered on another device
      if (c && c.id === d.call_id && d.user && d.user.id !== me()) {
        c.users.set(d.user.id, d.user);
        if (!c.startedAt && d.started_at) c.startedAt = new Date(d.started_at);
        c.status = 'Connecting…';
        updateCallStatus();
      }
      callsChanged();
      break;
    }
    case 'call.participant_left': {
      const [, dto] = findActiveCall(d.call_id);
      if (dto) dto.participants = dto.participants.filter((u) => u.id !== d.user_id);
      if (c && c.id === d.call_id && d.user_id !== me()) removePeer(d.user_id);
      callsChanged();
      break;
    }
    case 'call.ended': {
      const [key] = findActiveCall(d.call_id);
      if (key) calls.active.delete(key);
      if (calls.incoming && calls.incoming.id === d.call_id) hideIncoming();
      if (c && c.id === d.call_id) {
        cleanupCall({ missed: 'No answer', declined: 'Call declined', cancelled: 'Call cancelled', removed: 'You were removed from the group' }[d.reason] || 'Call ended');
      }
      callsChanged();
      break;
    }
    case 'call.muted':
      if (c && c.id === d.call_id && d.user_id === me() && !c.muted) {
        toggleMute();
        toast(`${d.by ? displayName(d.by) : 'A group admin'} muted your microphone. You can unmute yourself.`);
      }
      break;
    case 'call.dismissed':
      if (calls.incoming && calls.incoming.id === d.call_id) hideIncoming();
      break;
    case 'call.signal':
      handleSignal(d);
      break;
    default:
      break;
  }
}

// ---------- Admin console ----------
//
// Company owners and admins manage their own workspace (members, invitations, billing, reports).
// Platform admins also manage every company, the plans and the payments.

const adminUI = { tab: 'overview', reportStatus: 'open', userQuery: '', userStatus: '', companyStatus: '' };

function closeAccountMenu() {
  $('#account-menu').hidden = true;
  $('#account-btn').setAttribute('aria-expanded', 'false');
}

async function refreshAdminBadge() {
  if (!state.session || !(isCompanyAdmin() || isPlatformAdmin())) return;
  try {
    const stats = await api('/admin/stats');
    state.openReports = stats.open_reports;
    state.pendingCompanies = stats.pending_companies || 0;
  } catch {
    return;
  }
  const total = state.openReports + (isPlatformAdmin() ? state.pendingCompanies : 0);
  $('#admin-badge').textContent = total;
  $('#admin-badge').hidden = total === 0;
  for (const [id, n] of [['#admin-tab-reports-count', state.openReports], ['#admin-tab-companies-count', state.pendingCompanies]]) {
    const node = document.querySelector(id);
    if (node) { node.textContent = n; node.hidden = !n; }
  }
}

function adminTabs() {
  const tabs = [
    { group: state.company ? state.company.name : 'Workspace' },
    { id: 'overview', label: 'Overview', icon: 'grid' },
    { id: 'members', label: 'Members', icon: 'users' },
    { id: 'invitations', label: 'Invitations', icon: 'mail' },
    { id: 'billing', label: 'Billing', icon: 'card' },
    { id: 'reports', label: 'Reports', icon: 'flag', badge: 'admin-tab-reports-count' },
    { id: 'audit', label: 'Activity log', icon: 'activity' },
  ];
  if (isPlatformAdmin()) {
    tabs.push({ group: 'Platform' },
      { id: 'companies', label: 'Companies', icon: 'building', badge: 'admin-tab-companies-count' },
      { id: 'plans', label: 'Plans', icon: 'tag' },
      { id: 'payments', label: 'Payments', icon: 'card' },
      { id: 'allusers', label: 'All users', icon: 'user' });
  }
  return tabs;
}

function openAdmin() {
  closeAccountMenu();
  showOnly('admin-view');
  const user = state.session.user;
  $('#admin-whoami').textContent = `${displayName(user)} · ${isPlatformAdmin() ? 'platform admin' : `${user.company_role} of ${state.company ? state.company.name : 'your company'}`}`;
  $('#admin-scope-title').textContent = 'Administration';
  $('#admin-tabs').replaceChildren(...adminTabs().map((t) => t.group
    ? el('div', { class: 'admin-tab-group' }, t.group)
    : el('button', { type: 'button', class: 'admin-tab', 'data-tab': t.id, role: 'tab', onclick: () => showAdminTab(t.id) },
      icon(t.icon), t.label, t.badge ? el('span', { id: t.badge, class: 'badge', hidden: true }) : null)));
  document.title = 'Admin · BinTalk';
  showAdminTab(adminUI.tab);
  refreshAdminBadge();
}

function closeAdmin() {
  showOnly('app-view');
  renderChatList();
}

const adminTitles = {
  overview: 'Overview', members: 'Members', invitations: 'Invitations', billing: 'Billing & subscription',
  reports: 'Reports', audit: 'Activity log', companies: 'Companies', plans: 'Plans', payments: 'Payments', allusers: 'All users',
};

function showAdminTab(tab) {
  if (!adminTitles[tab] || (['companies', 'plans', 'payments', 'allusers'].includes(tab) && !isPlatformAdmin())) tab = 'overview';
  adminUI.tab = tab;
  adminUI.token = {};
  document.querySelectorAll('.admin-tab').forEach((t) => t.classList.toggle('active', t.dataset.tab === tab));
  $('#admin-heading').textContent = adminTitles[tab];
  const render = {
    overview: renderAdminOverview, members: () => renderAdminUsers(false), invitations: renderAdminInvitations,
    billing: renderAdminBilling, reports: renderAdminReports, audit: renderAdminAudit, companies: renderAdminCompanies,
    plans: renderAdminPlans, payments: renderAdminPayments, allusers: () => renderAdminUsers(true),
  }[tab];
  render();
}

function adminContent(...nodes) {
  $('#admin-content').replaceChildren(...nodes.flat(Infinity).filter(Boolean));
}

// A writer for the current tab's content that ignores results arriving after the admin moved on.
function adminView() {
  const token = adminUI.token;
  return (...nodes) => { if (adminUI.token === token) adminContent(...nodes); };
}

function pill(text, kind = '') {
  return el('span', { class: `pill ${kind}` }, text);
}

const companyStatusPill = {
  active: 'ok', pending_payment: 'warn', pending_approval: 'accent', suspended: 'bad', expired: 'bad', rejected: 'bad',
};

function statusPill(status) {
  return pill(status.replace('_', ' '), companyStatusPill[status] || '');
}

function personLine(user) {
  if (!user) return el('span', { class: 'muted' }, 'deleted account');
  return el('span', { class: 'person' },
    el('strong', {}, displayName(user)), ' ', el('span', { class: 'muted' }, `@${user.username}`),
    user.status && user.status !== 'active' ? [' ', pill(user.status, 'bad')] : null);
}

const reasonLabels = { spam: 'Spam', harassment: 'Harassment', inappropriate: 'Inappropriate', other: 'Other' };

async function renderAdminReports() {
  const view = adminView();
  const statusSelect = el('select', { 'aria-label': 'Report status', onchange: () => { adminUI.reportStatus = statusSelect.value; renderAdminReports(); } },
    [['open', 'Open'], ['resolved', 'Resolved'], ['dismissed', 'Dismissed'], ['all', 'All']].map(([v, l]) =>
      el('option', { value: v, selected: v === adminUI.reportStatus }, l)));
  const toolbar = el('div', { class: 'admin-toolbar' }, statusSelect,
    el('button', { class: 'ghost small', type: 'button', onclick: renderAdminReports }, '↻ Refresh'));
  view(toolbar, el('p', { class: 'muted' }, 'Loading reports…'));

  try {
    const { reports } = await api(`/admin/reports?status=${adminUI.reportStatus}&limit=100`);
    refreshAdminBadge();
    view(toolbar, reports.length
      ? el('div', { class: 'admin-list' }, reports.map(reportCard))
      : el('div', { class: 'admin-empty' }, adminUI.reportStatus === 'open' ? '🎉 No open reports.' : 'No reports.'));
  } catch (err) {
    view(toolbar, el('p', { class: 'error' }, err.message));
  }
}

function reportCard(r) {
  const msg = r.message;
  const file = msg && msg.attachments && msg.attachments[0];
  const where = msg ? (msg.group_name ? `in group "${msg.group_name}"${msg.in_thread ? ' (thread reply)' : ''}` : 'in a direct message') : '';

  const messageBox = msg ? el('div', { class: 'reported-message' },
    el('div', { class: 'muted small' }, `Message ${where} · ${new Date(msg.created_at).toLocaleString()}`,
      msg.is_deleted ? [' · ', pill('deleted', 'bad')] : null),
    file ? el('div', {}, `${msg.message_type === 'image' ? '📷' : '📎'} ${file.filename}`) : null,
    el('div', { class: 'reported-text' }, msg.content || (file ? '' : '🔒 (cannot be decrypted)')))
    : el('div', { class: 'reported-message muted' }, 'Report about the user (no specific message).');

  const card = el('article', { class: 'admin-card report-card' },
    el('header', { class: 'admin-card-head' },
      pill(reasonLabels[r.reason] || r.reason, 'warn'),
      pill(r.status, r.status === 'open' ? 'accent' : 'ok'),
      r.report_count > 1 && r.status === 'open' ? pill(`${r.report_count} open reports about this`, 'bad') : null,
      el('span', { class: 'muted small spacer' }, new Date(r.created_at).toLocaleString())),
    el('dl', { class: 'kv' },
      el('dt', {}, 'Reported'), el('dd', {}, personLine(r.reported_user)),
      el('dt', {}, 'Reported by'), el('dd', {}, personLine(r.reporter)),
      r.details ? [el('dt', {}, 'Details'), el('dd', {}, `“${r.details}”`)] : null),
    messageBox);

  if (r.status !== 'open') {
    card.append(el('p', { class: 'muted small resolution' },
      `${r.status === 'resolved' ? 'Resolved' : 'Dismissed'} by ${r.resolved_by ? `@${r.resolved_by.username}` : 'an admin'}`,
      r.resolved_at ? ` on ${new Date(r.resolved_at).toLocaleString()}` : '',
      r.action_taken ? ` · ${r.action_taken.split(',').map((a) => a.replace('_', ' ')).join(', ')}` : '',
      r.resolution_note ? ` · “${r.resolution_note}”` : ''));
    return card;
  }

  const deleteBox = el('input', { type: 'checkbox', name: 'delete_message', disabled: !msg || msg.is_deleted });
  const suspendBox = el('input', { type: 'checkbox', name: 'suspend_user', disabled: !r.reported_user || r.reported_user.status === 'suspended' });
  const note = el('input', { type: 'text', placeholder: 'Note for the record (optional)', maxlength: 2000 });
  const act = async (status) => {
    const actions = [deleteBox.checked && 'delete the message', suspendBox.checked && `suspend @${r.reported_user.username}`].filter(Boolean);
    if (actions.length && !confirm(`This will ${actions.join(' and ')}. Continue?`)) return;
    try {
      await api(`/admin/reports/${r.id}`, {
        method: 'PUT',
        body: { status, note: note.value, delete_message: deleteBox.checked, suspend_user: suspendBox.checked },
      });
      toast(status === 'resolved' ? 'Report resolved' : 'Report dismissed');
      renderAdminReports();
    } catch (err) {
      toast(err.message, true);
    }
  };
  card.append(el('div', { class: 'report-actions' },
    el('label', { class: 'check' }, deleteBox, 'Delete the message'),
    el('label', { class: 'check' }, suspendBox, r.reported_user ? `Suspend @${r.reported_user.username}` : 'Suspend user'),
    note,
    el('div', { class: 'button-row' },
      el('button', { type: 'button', class: 'primary', onclick: () => act('resolved') }, 'Resolve'),
      el('button', { type: 'button', class: 'ghost', onclick: () => act('dismissed') }, 'Dismiss (no problem)'))));
  return card;
}

// Mirrors the server rule (handlers.canManage).
function canManageUser(u) {
  const a = state.session.user;
  if (u.id === a.id) return false;
  if (isPlatformAdmin(a)) return true;
  return isCompanyAdmin(a) && u.company_id === a.company_id && u.company_role !== 'owner' && u.role !== 'admin';
}

async function renderAdminUsers(all) {
  const view = adminView();
  const search = el('input', { type: 'search', placeholder: 'Search name, username or email…', value: adminUI.userQuery, 'aria-label': 'Search users' });
  const status = el('select', { 'aria-label': 'Status filter' },
    [['', 'All statuses'], ['active', 'Active'], ['suspended', 'Suspended']].map(([v, l]) =>
      el('option', { value: v, selected: v === adminUI.userStatus }, l)));
  const list = el('div', { class: 'admin-list' }, el('p', { class: 'muted' }, 'Loading…'));
  const summary = el('p', { class: 'muted small' });
  const scope = all || !state.company ? '' : `&company_id=${state.company.id}`;

  const load = async () => {
    adminUI.userQuery = search.value.trim();
    adminUI.userStatus = status.value;
    try {
      const data = await api(`/admin/users?limit=100&q=${encodeURIComponent(adminUI.userQuery)}&status=${adminUI.userStatus}${scope}`);
      summary.textContent = `${data.total} account${data.total === 1 ? '' : 's'}${data.total > data.users.length ? ` (showing ${data.users.length})` : ''}`;
      list.replaceChildren(...(data.users.length ? data.users.map((u) => userCard(u, all)) : [el('div', { class: 'admin-empty' }, 'No matching accounts.')]));
    } catch (err) {
      list.replaceChildren(el('p', { class: 'error' }, err.message));
    }
  };
  search.addEventListener('input', debounce(load, 300));
  status.addEventListener('change', load);
  view(el('div', { class: 'admin-toolbar' }, search, status,
    all ? null : el('button', { type: 'button', class: 'primary small', onclick: () => showAdminTab('invitations') }, icon('plus'), 'Invite people')),
  summary, list);
  load();
}

function userCard(u, showCompany) {
  const self = u.id === me();
  const suspended = u.status === 'suspended';
  const manage = canManageUser(u);
  const rerender = () => showAdminTab(adminUI.tab);
  const update = async (body, question) => {
    if (question && !confirm(question)) return;
    try {
      await api(`/admin/users/${u.id}`, { method: 'PUT', body });
      toast('Account updated');
      rerender();
    } catch (err) {
      toast(err.message, true);
    }
  };
  return el('article', { class: `admin-card user-card${suspended ? ' is-suspended' : ''}` },
    avatarEl(displayName(u), u.id),
    el('div', { class: 'user-main' },
      el('div', { class: 'user-name' }, el('strong', {}, displayName(u)), ' ', el('span', { class: 'muted' }, `@${u.username}`),
        u.company_role === 'owner' ? pill('owner', 'brand') : u.company_role === 'admin' ? pill('admin', 'accent') : null,
        u.role === 'admin' ? pill('platform admin', 'brand') : null,
        suspended ? pill('suspended', 'bad') : null,
        u.must_change_password ? pill('must change password', 'warn') : null,
        u.open_reports_against > 0 ? pill(`${u.open_reports_against} open report${u.open_reports_against === 1 ? '' : 's'}`, 'bad') : null,
        self ? pill('you') : null),
      el('div', { class: 'muted small' }, u.email, showCompany && u.company_name ? ` · ${u.company_name}` : ''),
      el('div', { class: 'muted small' },
        `Joined ${new Date(u.created_at).toLocaleDateString()} · `,
        u.last_login_at ? `last sign-in ${formatTime(u.last_login_at)}` : 'never signed in',
        ` · ${u.message_count} message${u.message_count === 1 ? '' : 's'}`)),
    manage ? el('div', { class: 'user-actions' },
      el('button', { type: 'button', class: 'ghost small', onclick: () => showAdminResetPassword(u) }, 'Reset password'),
      u.company_role !== 'owner' ? el('button', {
        type: 'button', class: 'ghost small',
        onclick: () => update({ company_role: u.company_role === 'admin' ? 'member' : 'admin' },
          u.company_role === 'admin' ? `Make @${u.username} a regular member?` : `Make @${u.username} a company admin? They can invite and manage members and billing.`),
      }, u.company_role === 'admin' ? 'Make member' : 'Make admin') : null,
      el('button', {
        type: 'button', class: `ghost small${suspended ? '' : ' danger'}`,
        onclick: () => update({ status: suspended ? 'active' : 'suspended' },
          suspended ? null : `Suspend @${u.username}? They will be signed out everywhere and cannot sign in.`),
      }, suspended ? 'Reactivate' : 'Suspend'),
      isPlatformAdmin() ? el('button', {
        type: 'button', class: 'ghost small',
        onclick: () => update({ role: u.role === 'admin' ? 'user' : 'admin' },
          u.role === 'admin' ? `Remove platform admin rights from @${u.username}?` : `Make @${u.username} a platform admin? They will control every company.`),
      }, u.role === 'admin' ? 'Remove platform admin' : 'Platform admin') : null) : null);
}

// ----- invitations -----

function copyRow(value) {
  const input = el('input', { type: 'text', readonly: true, value });
  return el('div', { class: 'copy-row' }, input,
    el('button', { type: 'button', class: 'ghost small', onclick: async () => {
      try { await navigator.clipboard.writeText(value); toast('Copied'); } catch { input.select(); }
    } }, 'Copy'));
}

async function renderAdminInvitations() {
  const view = adminView();
  const email = el('input', { type: 'email', name: 'email', required: true, placeholder: 'colleague@company.com' });
  const role = el('select', { name: 'company_role' }, el('option', { value: 'member' }, 'Member'), el('option', { value: 'admin' }, 'Admin'));
  const result = el('div');
  const seats = el('p', { class: 'muted small' });
  const list = el('div', { class: 'table-wrap' }, el('p', { class: 'muted' }, 'Loading…'));
  const form = el('form', { class: 'admin-card', onsubmit: async (event) => {
    event.preventDefault();
    try {
      const res = await api('/admin/invitations', { method: 'POST', body: { email: email.value, company_role: role.value } });
      email.value = '';
      result.replaceChildren(el('p', { class: 'info' }, `Invitation sent to ${res.invitation.email}. You can also share this link (valid for 7 days):`), copyRow(res.invite_link));
      load();
    } catch (err) {
      toast(err.message, true);
    }
  } },
  el('h3', {}, 'Invite people to your workspace'),
  el('div', { class: 'admin-toolbar' }, email, role, el('button', { type: 'submit', class: 'primary' }, icon('mail'), 'Send invitation')),
  seats, result);

  const load = async () => {
    try {
      const data = await api('/admin/invitations');
      seats.textContent = data.seats_left < 0 ? 'Your plan has unlimited seats.' : `${data.seats_left} seat${data.seats_left === 1 ? '' : 's'} left on your plan (members plus open invitations).`;
      list.replaceChildren(data.invitations.length ? el('table', { class: 'data-table' },
        el('thead', {}, el('tr', {}, ['Email', 'Role', 'Status', 'Invited by', 'Expires', ''].map((h) => el('th', {}, h)))),
        el('tbody', {}, data.invitations.map((inv) => el('tr', {},
          el('td', {}, inv.email), el('td', {}, inv.company_role),
          el('td', {}, pill(inv.status, { pending: 'accent', accepted: 'ok', revoked: '', expired: 'warn' }[inv.status])),
          el('td', {}, inv.invited_by ? `@${inv.invited_by.username}` : '–'),
          el('td', {}, new Date(inv.expires_at).toLocaleDateString()),
          el('td', {}, inv.status === 'pending' ? el('button', { type: 'button', class: 'ghost small danger', onclick: async () => {
            try { await api(`/admin/invitations/${inv.id}`, { method: 'DELETE' }); toast('Invitation revoked'); load(); } catch (err) { toast(err.message, true); }
          } }, 'Revoke') : null)))))
        : el('div', { class: 'admin-empty' }, 'No invitations yet.'));
    } catch (err) {
      list.replaceChildren(el('p', { class: 'error' }, err.message));
    }
  };
  view(form, el('h3', {}, 'Invitations'), list);
  load();
}

// ----- billing -----

async function renderAdminBilling() {
  const view = adminView();
  view(el('p', { class: 'muted' }, 'Loading…'));
  try {
    const data = await api('/admin/company');
    const co = data.company;
    state.company = co;
    const plan = co.plan;
    const max = plan && plan.max_users;
    const used = co.member_count;
    const planSelect = el('select', {}, data.plans.map((p) => el('option', { value: p.code, selected: plan && p.code === plan.code },
      `${p.name} · ${planSeats(p)} · ${money(p.price_monthly, p.currency)}/mo or ${money(p.price_yearly, p.currency)}/yr`)));
    const cycleSelect = el('select', {}, ['monthly', 'yearly'].map((c) => el('option', { value: c, selected: c === co.billing_cycle }, c[0].toUpperCase() + c.slice(1))));
    const tile = (label, value, sub) => el('div', { class: 'stat-tile' }, el('div', { class: 'muted small' }, label), el('div', { class: 'stat-value' }, value), sub);
    view(
      el('div', { class: 'billing-hero' },
        tile('Status', statusPill(co.status), null),
        tile('Plan', plan ? plan.name : '–', el('div', { class: 'muted small' }, co.billing_cycle)),
        tile('Members', max ? `${used} / ${max}` : `${used}`, max ? el('div', { class: 'meter' }, el('span', { style: `width:${Math.min(100, (used / max) * 100)}%` })) : el('div', { class: 'muted small' }, 'Unlimited')),
        tile('Paid until', co.current_period_end ? new Date(co.current_period_end).toLocaleDateString() : 'No expiry', null)),
      data.online_payment && isCompanyAdmin() ? el('div', { class: 'admin-card' },
        el('h3', {}, 'Renew or change your plan'),
        el('p', { class: 'muted small' }, 'Payment is made securely with Chapa (Telebirr, CBE Birr, cards). A new payment extends your subscription from its current end date.'),
        el('div', { class: 'admin-toolbar' }, planSelect, cycleSelect,
          el('button', { type: 'button', class: 'primary', onclick: async () => {
            try {
              const res = await api('/admin/company/checkout', { method: 'POST', body: { plan_code: planSelect.value, billing_cycle: cycleSelect.value } });
              location.assign(res.checkout_url);
            } catch (err) {
              toast(err.message, true);
            }
          } }, icon('card'), 'Pay with Chapa'))) : el('div', { class: 'admin-card muted' }, 'Contact BinTalk to renew or change your plan.'),
      el('h3', {}, 'Payments'),
      data.payments.length ? paymentsTable(data.payments, false) : el('div', { class: 'admin-empty' }, 'No payments yet.'));
  } catch (err) {
    view(el('p', { class: 'error' }, err.message));
  }
}

function paymentsTable(payments, showCompany) {
  return el('div', { class: 'table-wrap' }, el('table', { class: 'data-table' },
    el('thead', {}, el('tr', {}, [showCompany ? 'Company' : null, 'Date', 'Plan', 'Amount', 'Status', 'Reference'].filter(Boolean).map((h) => el('th', {}, h)))),
    el('tbody', {}, payments.map((p) => el('tr', {},
      showCompany ? el('td', {}, p.company_name) : null,
      el('td', {}, new Date(p.created_at).toLocaleString()),
      el('td', {}, `${p.plan_name} · ${p.billing_cycle}`),
      el('td', {}, money(p.amount, p.currency)),
      el('td', {}, pill(p.status, { success: 'ok', pending: 'warn', failed: 'bad' }[p.status])),
      el('td', { class: 'mono' }, p.provider_reference || p.tx_ref))))));
}

// ----- platform: companies, plans, payments -----

async function renderAdminCompanies() {
  const view = adminView();
  const statusSelect = el('select', { 'aria-label': 'Company status', onchange: () => { adminUI.companyStatus = statusSelect.value; load(); } },
    [['', 'All companies'], ['pending_approval', 'Waiting for approval'], ['pending_payment', 'Waiting for payment'], ['active', 'Active'], ['expired', 'Expired'], ['suspended', 'Suspended'], ['rejected', 'Rejected']]
      .map(([v, l]) => el('option', { value: v, selected: v === adminUI.companyStatus }, l)));
  const search = el('input', { type: 'search', placeholder: 'Search companies…' });
  const list = el('div', { class: 'admin-list' }, el('p', { class: 'muted' }, 'Loading…'));
  let plans = [];
  const load = async () => {
    try {
      const [data, planData] = await Promise.all([
        api(`/platform/companies?status=${adminUI.companyStatus}&q=${encodeURIComponent(search.value.trim())}`),
        plans.length ? { plans } : api('/platform/plans')]);
      plans = planData.plans;
      list.replaceChildren(...(data.companies.length ? data.companies.map((co) => companyCard(co, plans, load)) : [el('div', { class: 'admin-empty' }, 'No companies.')]));
      refreshAdminBadge();
    } catch (err) {
      list.replaceChildren(el('p', { class: 'error' }, err.message));
    }
  };
  search.addEventListener('input', debounce(load, 300));
  view(el('div', { class: 'admin-toolbar' }, search, statusSelect,
    el('button', { type: 'button', class: 'primary small', onclick: () => showCreateCompany(plans, load) }, icon('plus'), 'Register company')), list);
  load();
}

function companyCard(co, plans, reload) {
  const update = async (body, question) => {
    if (question && !confirm(question)) return;
    try {
      await api(`/platform/companies/${co.id}`, { method: 'PUT', body });
      toast('Company updated');
      reload();
    } catch (err) {
      toast(err.message, true);
    }
  };
  const planSelect = el('select', { 'aria-label': 'Plan', onchange: () => update({ plan_code: planSelect.value }) },
    plans.map((p) => el('option', { value: p.code, selected: co.plan && co.plan.code === p.code }, p.name)));
  const active = co.status === 'active';
  return el('article', { class: 'admin-card' },
    el('div', { class: 'admin-card-head' },
      el('span', { class: 'avatar', 'data-hue': '', style: `--hue:${hueOf(co.id)}` }, initials(co.name)),
      el('div', {}, el('strong', {}, co.name), el('div', { class: 'muted small' }, `${co.slug} · ${co.contact_email}${co.contact_phone ? ` · ${co.contact_phone}` : ''}`)),
      el('span', { class: 'spacer' }), statusPill(co.status)),
    el('dl', { class: 'kv' },
      el('dt', {}, 'Plan'), el('dd', {}, co.plan ? `${co.plan.name} (${planSeats(co.plan)}) · ${co.billing_cycle}` : '–'),
      el('dt', {}, 'Members'), el('dd', {}, String(co.member_count)),
      el('dt', {}, 'Paid until'), el('dd', {}, co.current_period_end ? new Date(co.current_period_end).toLocaleString() : 'No expiry'),
      el('dt', {}, 'Registered'), el('dd', {}, new Date(co.created_at).toLocaleString())),
    el('div', { class: 'report-actions' }, el('div', { class: 'button-row' },
      !active && co.status !== 'rejected' ? el('button', { type: 'button', class: 'primary small', onclick: () => update({ status: 'active' }, `Activate ${co.name}? Its members can sign in.`) }, icon('check'), co.status.startsWith('pending') ? 'Approve' : 'Reactivate') : null,
      co.status.startsWith('pending') ? el('button', { type: 'button', class: 'ghost small danger', onclick: () => update({ status: 'rejected' }, `Reject ${co.name}?`) }, 'Reject') : null,
      active ? el('button', { type: 'button', class: 'ghost small danger', onclick: () => update({ status: 'suspended' }, `Suspend ${co.name}? All its members are signed out immediately.`) }, 'Suspend') : null,
      el('button', { type: 'button', class: 'ghost small', onclick: () => update({ extend_months: 1 }) }, '+1 month'),
      el('button', { type: 'button', class: 'ghost small', onclick: () => update({ extend_months: 12 }) }, '+1 year'),
      el('button', { type: 'button', class: 'ghost small', onclick: () => update({ current_period_end: '' }, `Remove the expiry date of ${co.name}? It will never expire.`) }, 'No expiry'),
      planSelect)));
}

function showCreateCompany(plans, reload) {
  const form = el('form', { class: 'form', onsubmit: async (event) => {
    event.preventDefault();
    const data = Object.fromEntries(new FormData(form));
    data.period_months = Number(data.period_months) || 0;
    try {
      const res = await api('/platform/companies', { method: 'POST', body: data });
      reload();
      openModal('Company registered',
        el('p', {}, el('strong', {}, res.company.name), ' is active. Give its owner these sign-in details:'),
        el('dl', { class: 'kv' }, el('dt', {}, 'Email'), el('dd', {}, res.owner.email)),
        el('div', { class: 'temp-password-row' }, el('code', { class: 'temp-password' }, res.temporary_password)),
        el('p', { class: 'muted small' }, 'They must choose a new password at first sign-in. The temporary password is shown only once.'),
        el('div', { class: 'modal-actions' }, el('button', { type: 'button', class: 'primary', onclick: closeModal }, 'Done')));
    } catch (err) {
      toast(err.message, true);
    }
  } },
  el('label', {}, 'Company name', el('input', { name: 'name', required: true, maxlength: 150 })),
  el('div', { class: 'form-row' },
    el('label', {}, 'Plan', el('select', { name: 'plan_code' }, plans.map((p) => el('option', { value: p.code }, p.name)))),
    el('label', {}, 'Paid period', el('select', { name: 'period_months' },
      el('option', { value: '1' }, '1 month'), el('option', { value: '12' }, '1 year'), el('option', { value: '0' }, 'No expiry')))),
  el('h3', {}, 'Owner'),
  el('div', { class: 'form-row' },
    el('label', {}, 'Full name', el('input', { name: 'owner_full_name', required: true })),
    el('label', {}, 'Username', el('input', { name: 'owner_username', required: true, minlength: 3, maxlength: 50 }))),
  el('label', {}, 'Email', el('input', { name: 'owner_email', type: 'email', required: true })),
  el('div', { class: 'modal-actions' },
    el('button', { type: 'button', class: 'ghost', onclick: closeModal }, 'Cancel'),
    el('button', { type: 'submit', class: 'primary' }, 'Register company')));
  openModal('Register a company', form);
}

async function renderAdminPlans() {
  const view = adminView();
  view(el('p', { class: 'muted' }, 'Loading…'));
  try {
    const { plans } = await api('/platform/plans');
    view(
      el('div', { class: 'admin-toolbar' }, el('span', { class: 'muted small' }, 'Prices apply to new payments. Retired plans are hidden from the landing page.'),
        el('span', { class: 'spacer' }), el('button', { type: 'button', class: 'primary small', onclick: () => showPlanForm(null) }, icon('plus'), 'New plan')),
      el('div', { class: 'table-wrap' }, el('table', { class: 'data-table' },
        el('thead', {}, el('tr', {}, ['Plan', 'Seats', 'Monthly', 'Yearly', 'Status', ''].map((h) => el('th', {}, h)))),
        el('tbody', {}, plans.map((p) => el('tr', {},
          el('td', {}, el('strong', {}, p.name), el('div', { class: 'muted small' }, p.code)),
          el('td', {}, planSeats(p)),
          el('td', {}, money(p.price_monthly, p.currency)),
          el('td', {}, money(p.price_yearly, p.currency)),
          el('td', {}, p.is_active ? pill('offered', 'ok') : pill('retired')),
          el('td', {}, el('button', { type: 'button', class: 'ghost small', onclick: () => showPlanForm(p) }, 'Edit'))))))));
  } catch (err) {
    view(el('p', { class: 'error' }, err.message));
  }
}

function showPlanForm(plan) {
  const v = plan || { code: '', name: '', description: '', max_users: '', price_monthly: '', price_yearly: '', is_active: true, sort_order: 0 };
  const form = el('form', { class: 'form', onsubmit: async (event) => {
    event.preventDefault();
    const d = Object.fromEntries(new FormData(form));
    const body = {
      name: d.name, description: d.description, max_users: Number(d.max_users) || 0,
      price_monthly: Number(d.price_monthly), price_yearly: Number(d.price_yearly), is_active: form.elements.is_active.checked,
      sort_order: Number(d.sort_order) || 0,
    };
    try {
      if (plan) await api(`/platform/plans/${plan.id}`, { method: 'PUT', body });
      else await api('/platform/plans', { method: 'POST', body: { ...body, code: d.code } });
      closeModal();
      plansLoaded = null;
      renderAdminPlans();
      toast('Plan saved');
    } catch (err) {
      toast(err.message, true);
    }
  } },
  plan ? null : el('label', {}, 'Code (lowercase, used in links)', el('input', { name: 'code', required: true, pattern: '[a-z0-9_-]{2,50}' })),
  el('label', {}, 'Name', el('input', { name: 'name', required: true, value: v.name })),
  el('label', {}, 'Description', el('input', { name: 'description', value: v.description })),
  el('div', { class: 'form-row' },
    el('label', {}, 'Monthly price (ETB)', el('input', { name: 'price_monthly', type: 'number', min: 0, step: '0.01', required: true, value: v.price_monthly })),
    el('label', {}, 'Yearly price (ETB)', el('input', { name: 'price_yearly', type: 'number', min: 0, step: '0.01', required: true, value: v.price_yearly }))),
  el('div', { class: 'form-row' },
    el('label', {}, 'Max members (0 = unlimited)', el('input', { name: 'max_users', type: 'number', min: 0, value: v.max_users || 0 })),
    el('label', {}, 'Sort order', el('input', { name: 'sort_order', type: 'number', value: v.sort_order }))),
  el('label', { class: 'check' }, el('input', { type: 'checkbox', name: 'is_active', checked: v.is_active }), 'Offered on the landing page'),
  el('div', { class: 'modal-actions' },
    el('button', { type: 'button', class: 'ghost', onclick: closeModal }, 'Cancel'),
    el('button', { type: 'submit', class: 'primary' }, 'Save plan')));
  openModal(plan ? `Edit ${plan.name}` : 'New plan', form);
}

async function renderAdminPayments() {
  const view = adminView();
  view(el('p', { class: 'muted' }, 'Loading…'));
  try {
    const { payments } = await api('/platform/payments?limit=100');
    view(payments.length ? paymentsTable(payments, true) : el('div', { class: 'admin-empty' }, 'No payments yet.'));
  } catch (err) {
    view(el('p', { class: 'error' }, err.message));
  }
}

function showAdminResetPassword(u) {
  const custom = el('input', { type: 'text', name: 'password', minlength: 8, maxlength: 72, placeholder: 'Leave empty to generate one', autocomplete: 'off' });
  const form = el('form', { class: 'form', onsubmit: async (event) => {
    event.preventDefault();
    try {
      const res = await api(`/admin/users/${u.id}/reset-password`, { method: 'POST', body: custom.value ? { password: custom.value } : {} });
      const pwBox = el('code', { class: 'temp-password' }, res.temporary_password);
      openModal('Temporary password',
        el('p', {}, `Give this temporary password to `, el('strong', {}, `@${u.username}`), ':'),
        el('div', { class: 'temp-password-row' }, pwBox,
          el('button', { type: 'button', class: 'ghost small', onclick: async () => {
            try {
              await navigator.clipboard.writeText(res.temporary_password);
              toast('Copied');
            } catch {
              toast('Copy failed; select and copy it manually', true);
            }
          } }, 'Copy')),
        el('p', { class: 'muted small' }, 'They have been signed out of all devices and must choose a new password when they sign in. This password is shown only once.'),
        el('div', { class: 'modal-actions' }, el('button', { type: 'button', class: 'primary', onclick: closeModal }, 'Done')));
      if (adminUI.tab === 'users') renderAdminUsers();
    } catch (err) {
      toast(err.message, true);
    }
  } },
  el('p', {}, `Set a temporary password for `, el('strong', {}, `${displayName(u)} (@${u.username})`), '.'),
  el('label', {}, 'Temporary password', custom),
  el('p', { class: 'muted small' }, 'They will be signed out everywhere and must change it at their next sign-in.'),
  el('div', { class: 'modal-actions' },
    el('button', { type: 'button', class: 'ghost', onclick: closeModal }, 'Cancel'),
    el('button', { type: 'submit', class: 'primary' }, 'Reset password')));
  openModal('Reset password', form);
}

async function renderAdminOverview() {
  const view = adminView();
  view(el('p', { class: 'muted' }, 'Loading…'));
  try {
    const s = await api('/admin/stats');
    const tile = (label, value, sub, onclick) => el(onclick ? 'button' : 'div', { class: 'stat-tile', type: onclick ? 'button' : undefined, onclick },
      el('div', { class: 'stat-value' }, value.toLocaleString()), el('div', { class: 'stat-label' }, label), sub ? el('div', { class: 'muted small' }, sub) : null);
    const email = s.email || {};
    const mailpitLink = el('a', { href: 'http://localhost:8025', target: '_blank', rel: 'noopener' }, 'Mailpit');
    const localDomain = (email.from || '').endsWith('.local');
    const emailNotice = s.platform ? el('div', { class: `admin-card email-status${email.kind === 'local' && !localDomain ? '' : ' warn'}` },
      el('strong', {}, 'Email delivery: '),
      email.kind === 'mailpit'
        ? ['Development only. Emails go to the local ', mailpitLink, ' inbox and do not reach real inboxes.']
        : email.kind === 'local'
          ? [`Local mail server, delivering directly to recipients' mail servers from ${email.from}. A copy of every email is in `, mailpitLink, '.',
            localDomain ? ' Gmail, Outlook and most providers will reject or spam these emails until MAIL_DOMAIN in .env is a real domain with SPF, DKIM and DMARC records (see README).' : '']
          : `via ${email.host}:${email.port}, from ${email.from}.`) : null;
    view(emailNotice, el('div', { class: 'stat-grid' },
      s.platform ? tile('Companies', s.companies, s.pending_companies ? `${s.pending_companies} waiting for approval` : 'All approved', () => showAdminTab('companies')) : null,
      tile('Open reports', s.open_reports, s.open_reports ? 'Needs attention' : 'All clear', () => showAdminTab('reports')),
      tile(s.platform ? 'Accounts (all companies)' : 'Members', s.users, `${s.active_users} active · ${s.suspended_users} suspended`, () => showAdminTab(s.platform ? 'allusers' : 'members')),
      tile('Signed in today', s.active_today, 'last 24 hours'),
      tile(s.platform ? 'Platform admins' : 'Admins', s.admins),
      tile('Messages', s.messages, `${s.messages_24h} in the last 24 hours`),
      tile('Channels & groups', s.groups),
      tile('Files', s.files)));
  } catch (err) {
    view(el('p', { class: 'error' }, err.message));
  }
}

function describeAudit(e) {
  const d = e.details || {};
  const who = (user) => (user ? `@${user.username}` : 'someone');
  if (e.resource_type === 'user') {
    const parts = [];
    if (d.status && d.status.from !== d.status.to) parts.push(`status ${d.status.from} → ${d.status.to}`);
    if (d.role && d.role.from !== d.role.to) parts.push(`platform role ${d.role.from} → ${d.role.to}`);
    if (d.company_role && d.company_role.from !== d.company_role.to) parts.push(`role ${d.company_role.from} → ${d.company_role.to}`);
    return `changed @${d.username}: ${parts.join(', ') || 'no changes'}`;
  }
  if (e.resource_type === 'user_password') {
    return {
      admin_password_reset: `reset the password of @${d.username}`,
      password_changed: 'changed their password',
      password_reset_requested: 'requested a password reset email',
      password_reset_completed: 'reset their password from an email link',
    }[d.event] || 'password event';
  }
  if (e.resource_type === 'company') {
    if (d.event === 'company_signup') return `registered ${d.company} (${d.plan}, ${d.billing_cycle})`;
    if (d.event === 'company_created') return `registered ${d.company}`;
    return `updated ${d.company}${d.status && d.status.from !== d.status.to ? `: ${d.status.from} → ${d.status.to}` : ''}`;
  }
  if (e.resource_type === 'payment') return `${d.event === 'payment_success' ? 'payment received' : 'payment failed'} from ${d.company} (${d.amount})`;
  if (e.resource_type === 'invitation') return `invited ${d.email} as ${d.company_role}`;
  if (e.resource_type === 'abuse_report') {
    const actions = (d.actions || []).map((a) => a.replace('_', ' ')).join(', ');
    return `${d.status === 'dismissed' ? 'dismissed' : d.status === 'open' ? 'reopened' : 'resolved'} a report${actions ? ` (${actions})` : ''}${d.note ? ` · “${d.note}”` : ''}`;
  }
  return `${e.action} ${e.resource_type}`;
}

async function renderAdminAudit() {
  const view = adminView();
  view(el('p', { class: 'muted' }, 'Loading…'));
  try {
    const { entries } = await api('/admin/audit?limit=100');
    view(entries.length ? el('ol', { class: 'audit-list' }, entries.map((e) => el('li', {},
      el('span', { class: 'audit-time muted small' }, new Date(e.created_at).toLocaleString()),
      el('span', {}, el('strong', {}, e.actor ? `@${e.actor.username}` : 'system'), ' ', describeAudit(e)),
      e.ip_address ? el('span', { class: 'muted small' }, e.ip_address) : null)))
      : el('div', { class: 'admin-empty' }, 'No activity yet.'));
  } catch (err) {
    view(el('p', { class: 'error' }, err.message));
  }
}

// ---------- Wiring ----------

function init() {
  $('#year').textContent = new Date().getFullYear();
  // Landing and auth navigation: any [data-open] button opens that screen.
  document.addEventListener('click', (event) => {
    const opener = event.target.closest('[data-open]');
    if (!opener) return;
    event.preventDefault();
    const screen = opener.dataset.open;
    if (screen === 'signup') openSignup();
    else showAuth(screen);
  });
  document.querySelectorAll('.cycle').forEach((b) => b.addEventListener('click', () => {
    state.cycle = b.dataset.cycle;
    document.querySelectorAll('.cycle').forEach((x) => { x.classList.toggle('active', x === b); x.setAttribute('aria-checked', String(x === b)); });
    renderPlans();
  }));
  $('#auth-home').addEventListener('click', () => { history.replaceState(null, '', location.pathname); showLanding(); });
  $('#auth-logo').addEventListener('click', (event) => { event.preventDefault(); showLanding(); });
  $('#signup-plan').addEventListener('change', updateSignupTotal);
  $('#signup-cycle').addEventListener('change', updateSignupTotal);
  $('#checkout-plan').addEventListener('change', () => { $('#checkout-plan').dataset.touched = '1'; });
  $('#login-form').addEventListener('submit', handleLogin);
  $('#signup-form').addEventListener('submit', handleSignup);
  $('#invite-form').addEventListener('submit', handleInvite);
  $('#checkout-form').addEventListener('submit', handleCheckout);
  $('#payment-retry').addEventListener('click', () => checkPayment());
  $('#menu-logout-btn').addEventListener('click', confirmSignOut);
  document.querySelectorAll('.status-option').forEach((b) => b.addEventListener('click', () => setPresencePreference(b.dataset.pref)));
  $('#status-btn').addEventListener('click', () => { closeAccountMenu(); showStatus(); });
  $('#change-password-btn').addEventListener('click', () => { closeAccountMenu(); showChangePassword(); });
  $('#account-btn').addEventListener('click', (event) => {
    event.stopPropagation();
    const menu = $('#account-menu');
    menu.hidden = !menu.hidden;
    $('#account-btn').setAttribute('aria-expanded', String(!menu.hidden));
  });
  $('#forgot-link').addEventListener('click', () => setAuthTab('forgot'));
  document.querySelectorAll('.back-to-login').forEach((b) => b.addEventListener('click', () => setAuthTab('login')));
  $('#forgot-form').addEventListener('submit', handleForgot);
  $('#reset-form').addEventListener('submit', handleReset);
  $('#force-change-form').addEventListener('submit', handleForcedChange);
  $('#force-signout').addEventListener('click', () => signOut());
  $('#admin-btn').addEventListener('click', openAdmin);
  $('#voice-call-btn').addEventListener('click', () => startCall('audio'));
  $('#video-call-btn').addEventListener('click', () => startCall('video'));
  $('#call-hangup').addEventListener('click', hangUp);
  $('#call-mute').addEventListener('click', toggleMute);
  $('#call-camera').addEventListener('click', toggleCamera);
  $('#call-screen').addEventListener('click', toggleScreen);
  $('#incoming-decline').addEventListener('click', declineIncoming);
  $('#incoming-accept-audio').addEventListener('click', () => calls.incoming && joinCall(calls.incoming, 'audio'));
  $('#incoming-accept-video').addEventListener('click', () => calls.incoming && joinCall(calls.incoming, 'video'));
  // Leaving the page hangs up (keepalive lets the request finish while the page unloads).
  window.addEventListener('pagehide', () => {
    if (calls.current && state.session) {
      fetch(`${API}/calls/${calls.current.id}/leave`, {
        method: 'POST', keepalive: true, headers: { Authorization: `Bearer ${state.session.token}` },
      }).catch(() => {});
    }
  });
  $('#admin-back').addEventListener('click', closeAdmin);
  document.querySelectorAll('.admin-tab').forEach((t) => t.addEventListener('click', () => showAdminTab(t.dataset.tab)));
  $('#new-group-btn').addEventListener('click', () => showNewGroup('group'));
  $('#browse-channels-btn').addEventListener('click', showBrowseChannels);
  $('#new-dm-btn').addEventListener('click', showNewDM);
  $('#new-dm-btn-2').addEventListener('click', showNewDM);
  $('#empty-browse').addEventListener('click', showBrowseChannels);
  $('#empty-group').addEventListener('click', () => showNewGroup('group'));
  $('#empty-dm').addEventListener('click', showNewDM);
  $('#leave-btn').addEventListener('click', leaveActiveGroup);
  document.querySelectorAll('.section-toggle').forEach((toggle) => toggle.addEventListener('click', () => {
    const section = toggle.closest('.side-section');
    const collapsed = section.classList.toggle('collapsed');
    toggle.setAttribute('aria-expanded', String(!collapsed));
  }));
  $('#members-btn').addEventListener('click', showMembers);
  $('#back-btn').addEventListener('click', closeChat);
  $('#thread-close').addEventListener('click', closeThread);
  $('#modal-close').addEventListener('click', closeModal);
  $('#modal').addEventListener('click', (event) => { if (event.target.id === 'modal') closeModal(); });

  mainComposer = createComposer($('#main-composer'), {
    placeholder: 'Write a message… (@ to mention)',
    notePlaceholder: 'Add a note about this file… (optional)',
    target: () => state.active && { kind: state.active.kind, id: state.active.id },
    onSent: (message, t) => {
      state.firstUnreadId = null;
      if (isActive(t.kind, t.id)) addMessage(message);
      reloadLists();
    },
  });
  threadComposer = createComposer($('#thread-composer'), {
    placeholder: 'Reply in thread… (@ to mention)',
    notePlaceholder: 'Add a note about this file… (optional)',
    target: () => state.thread && { kind: 'group', id: state.thread.groupId, parentId: state.thread.parent.id },
    onSent: (message) => {
      if (!state.thread || state.thread.parent.id !== message.parent_id) return;
      if (!state.thread.replies.some((r) => r.id === message.id)) {
        state.thread.replies.push(message);
        state.thread.parent.reply_count = state.thread.replies.length;
        renderThread({ scrollToBottom: true });
      }
      const parent = state.messages.find((m) => m.id === message.parent_id);
      if (parent) {
        parent.reply_count = state.thread.replies.length;
        parent.last_reply_at = message.created_at;
        renderMessages();
      }
    },
  });

  const messages = $('#messages');
  messages.addEventListener('scroll', () => {
    closeMenu();
    if (isNearBottom(messages)) {
      state.pendingNew = 0;
      $('#jump-new').hidden = true;
    }
  });
  $('#thread-messages').addEventListener('scroll', closeMenu);
  $('#jump-new').addEventListener('click', () => {
    messages.scrollTo({ top: messages.scrollHeight, behavior: 'smooth' });
    state.pendingNew = 0;
    $('#jump-new').hidden = true;
  });

  document.addEventListener('keydown', (event) => {
    if (event.key !== 'Escape') return;
    closeMenu();
    if (!$('#modal').hidden) closeModal();
  });
  document.addEventListener('click', (event) => {
    if (!event.target.closest('.account-menu-wrap')) closeAccountMenu();
    if (!event.target.closest('.context-menu') && !event.target.closest('.msg-actions')) closeMenu();
    if (!event.target.closest('.search')) $('#search-results').hidden = true;
  });
  window.addEventListener('resize', closeMenu);

  // Presence: any input marks you active again; 10 minutes without input marks you away.
  for (const type of ['pointerdown', 'pointermove', 'keydown', 'wheel', 'touchstart', 'focus']) {
    window.addEventListener(type, noteActivity, { passive: true });
  }
  setInterval(checkIdle, 30_000);

  // Messages that arrived while the tab was in the background are read when it is shown again.
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden && state.session) {
      markActiveChatRead();
      markThreadRead();
      if (state.active) {
        delete state.unread[chatKey(state.active.kind, state.active.id)];
        renderChatList();
      }
    }
  });

  const search = $('#search-input');
  search.addEventListener('input', () => searchUsers(search.value.trim()));

  // Links: #reset=<token> (password reset), #invite=<token> (invitation),
  // #payment=<tx_ref> (return from Chapa). They work on load and when pasted into an open tab.
  const openLink = () => {
    let match = location.hash.match(/^#reset=([A-Za-z0-9_-]+)$/);
    if (match) {
      state.resetToken = match[1];
      if (state.session) signOut();
      showAuth('reset');
      return true;
    }
    match = location.hash.match(/^#invite=([A-Za-z0-9_-]+)$/);
    if (match) {
      if (state.session) signOut();
      openInvite(match[1]);
      return true;
    }
    match = location.hash.match(/^#payment=([A-Za-z0-9_.-]+)$/);
    if (match) {
      state.paymentRef = match[1];
      checkPayment();
      return true;
    }
    return false;
  };
  window.addEventListener('hashchange', openLink);
  if (openLink()) return;

  const saved = loadSession();
  if (saved && saved.refresh_token) {
    state.session = saved;
    scheduleRefresh();
    // Validate the stored session (refreshing it if the access token expired) before showing the app.
    api('/auth/me')
      .then(({ user, company }) => {
        state.session.user = user;
        state.company = company;
        saveSessionUser();
        if (user.must_change_password) showPasswordView();
        else startApp();
      })
      .catch(() => { if (state.session && $('#password-view').hidden) signOut(); });
  } else {
    showLanding();
  }
}

init();
