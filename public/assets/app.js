import { bindSegmentedThumb, createInteractiveSheet } from './spring.js';
import { initMagicSpotlights, initSidebarCollapse } from './magic.js';

const state = {
  user: null,
  csrfToken: null,
  notes: [],
  selectedNoteId: null,
  isCreatingNewNote: false,
  noteLimits: { maxNotes: 50, maxTitleLength: 150, maxContentLength: 10000 },
  revealTimer: null,
  toastTimer: null,
};

const NOTE_TEMPLATES = {
  recovery: {
    title: 'Códigos de respaldo de cuentas',
    content:
      'Servicio: \nCuenta: \nCódigos de recuperación de un solo uso:\n- \n- \n- \nÚltima verificación: ',
  },
  wifi: {
    title: 'Credenciales de red Wi-Fi privada',
    content: 'SSID: \nSeguridad: WPA3-Personal\nContraseña: \nRouter (IP local): 192.168.1.1\nNotas: ',
  },
  document: {
    title: 'Referencia de documento oficial',
    content: 'Tipo de documento: \nNúmero / Folio: \nVigencia: \nUbicación física: ',
  },
};

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

function cleanText(val) {
  const str = String(val ?? '');
  if (window.DOMPurify) {
    return window.DOMPurify.sanitize(str, { ALLOWED_TAGS: [], ALLOWED_ATTR: [] });
  }
  return str;
}

function getCookie(name) {
  const match = document.cookie.match(new RegExp(`(?:^|; )${name}=([^;]*)`));
  return match ? decodeURIComponent(match[1]) : null;
}

async function api(path, { method = 'GET', body = undefined } = {}) {
  const headers = { Accept: 'application/json' };
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
  }
  if (method !== 'GET' && method !== 'HEAD') {
    const csrf = state.csrfToken || getCookie('sv_csrf');
    if (csrf) headers['X-CSRF-Token'] = csrf;
  }

  const res = await fetch(path, {
    method,
    credentials: 'same-origin',
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });

  let data = {};
  try {
    data = await res.json();
  } catch {
    data = {};
  }

  if (data.csrfToken) {
    state.csrfToken = data.csrfToken;
  }

  if (!res.ok) {
    const err = new Error(data.message || 'No fue posible completar la solicitud.');
    err.status = res.status;
    err.code = data.error || 'ERROR';
    throw err;
  }
  return data;
}

function showToast(message, { isError = false } = {}) {
  const toast = $('#toast');
  clearTimeout(state.toastTimer);
  toast.textContent = cleanText(message);
  toast.classList.toggle('is-error', isError);
  toast.hidden = false;
  requestAnimationFrame(() => toast.classList.add('is-visible'));

  state.toastTimer = setTimeout(() => {
    toast.classList.remove('is-visible');
    setTimeout(() => {
      toast.hidden = true;
    }, 220);
  }, 3200);
}

function showAuthFeedback(message, type = 'error') {
  const el = $('#auth-feedback');
  if (!message) {
    el.hidden = true;
    el.textContent = '';
    return;
  }
  el.textContent = cleanText(message);
  el.className = `inline-alert ${type === 'success' ? 'is-success' : 'is-error'}`;
  el.hidden = false;
}

function formatDate(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toLocaleString('es-MX', {
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function initTheme() {
  const saved = localStorage.getItem('sv_theme');
  const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
  const initialDark = saved ? saved === 'dark' : prefersDark;

  if (saved === 'light' || saved === 'dark') {
    document.documentElement.dataset.theme = saved;
  }

  const switches = $$('.theme-switch-input');
  const syncSwitches = (isDark) => {
    switches.forEach((inp) => {
      inp.checked = isDark;
    });
  };
  syncSwitches(initialDark);

  switches.forEach((inp) => {
    inp.addEventListener('change', () => {
      const next = inp.checked ? 'dark' : 'light';
      document.documentElement.dataset.theme = next;
      localStorage.setItem('sv_theme', next);
      syncSwitches(inp.checked);
    });
  });
}

async function checkHealth() {
  const pills = [
    { pill: $('#auth-health-pill'), text: $('#auth-health-text') },
    { pill: $('#app-health-pill'), text: $('#app-health-text') },
  ];
  try {
    const res = await fetch('/health', { cache: 'no-store' });
    const data = await res.json();
    const ok = res.ok && data.status === 'ok';
    for (const { pill, text } of pills) {
      if (!pill || !text) continue;
      pill.classList.toggle('is-ok', ok);
      pill.classList.toggle('is-degraded', !ok);
      text.textContent = ok ? 'Servicio operativo' : 'Servicio degradado';
    }
  } catch {
    for (const { pill, text } of pills) {
      if (!pill || !text) continue;
      pill.classList.remove('is-ok');
      pill.classList.add('is-degraded');
      text.textContent = 'Sin conexión';
    }
  }
}

const sheet = createInteractiveSheet($('#sheet-backdrop'), $('#sheet-panel'), $('#sheet-drag-handle'));

function openSheet({ title, buildBody }) {
  $('#sheet-title').textContent = title;
  const body = $('#sheet-body');
  body.textContent = '';
  buildBody(body);
  sheet.open();
}

const authSegmented = bindSegmentedThumb($('#auth-segmented'));
const adminSegmented = bindSegmentedThumb($('#admin-segmented'));

function setAuthTab(tab) {
  showAuthFeedback('');
  $$('[data-auth-tab]').forEach((btn) => {
    const active = btn.dataset.authTab === tab;
    btn.classList.toggle('is-active', active);
    btn.setAttribute('aria-selected', String(active));
  });
  $('#login-form').hidden = tab !== 'login';
  $('#mfa-login-form').hidden = true;
  $('#register-form').hidden = tab !== 'register';
  $('#recovery-panel').hidden = tab !== 'recovery';
  authSegmented.sync(false);
}

function setAdminTab(tab) {
  $$('[data-admin-tab]').forEach((btn) => {
    const active = btn.dataset.adminTab === tab;
    btn.classList.toggle('is-active', active);
    btn.setAttribute('aria-selected', String(active));
  });
  $('#admin-tab-users').hidden = tab !== 'users';
  $('#admin-tab-logs').hidden = tab !== 'logs';
  $('#admin-tab-alerts').hidden = tab !== 'alerts';
  adminSegmented.sync(false);
}

function bindPasswordStrength() {
  const input = $('#reg-password');
  const rules = {
    length: (v) => v.length >= 12,
    upper: (v) => /[A-Z]/.test(v),
    lower: (v) => /[a-z]/.test(v),
    number: (v) => /[0-9]/.test(v),
    symbol: (v) => /[^A-Za-z0-9]/.test(v),
  };

  input.addEventListener('input', () => {
    const val = input.value;
    Object.entries(rules).forEach(([key, test]) => {
      const li = $(`#password-rules li[data-rule="${key}"]`);
      if (li) li.classList.toggle('is-met', test(val));
    });
  });
}

function updatePostureUI() {
  if (!state.user) return;
  const count = state.notes.length;
  const max = state.noteLimits.maxNotes || 50;
  const pct = Math.min(100, Math.round((count / max) * 100));

  $('#sidebar-notes-count').textContent = String(count);
  $('#list-pane-count').textContent = String(count);
  $('#notes-quota-label').textContent = `${count} de ${max} notas · Cifrado autenticado en reposo`;
  $('#sidebar-quota-caption').textContent = `${count} de ${max} notas`;
  $('#sidebar-quota-fill').style.width = `${pct}%`;

  $('#tile-notes-value').textContent = count === 1 ? '1 nota cifrada' : `${count} notas cifradas`;

  $('#tile-mfa-value').textContent = state.user.mfaEnabled ? 'MFA TOTP activo' : 'MFA desactivado';
  $('#tile-mfa-sub').textContent = state.user.mfaEnabled
    ? 'Protegido con RFC 6238'
    : 'Recomendado · Configurar';

  $('#tile-phone-value').textContent = state.user.phoneMasked || 'Sin dato sensible';
}

function switchView(viewName) {
  $$('.nav-item').forEach((btn) => {
    btn.classList.toggle('is-active', btn.dataset.view === viewName);
  });
  $('#view-notes').hidden = viewName !== 'notes';
  $('#view-profile').hidden = viewName !== 'profile';
  $('#view-admin').hidden = viewName !== 'admin';

  if (viewName === 'profile') loadProfile();
  if (viewName === 'admin' && state.user?.role === 'admin') {
    loadAdminData();
    requestAnimationFrame(() => adminSegmented.sync(true));
  }
}

function renderNotesList() {
  const list = $('#notes-list');
  const empty = $('#notes-empty-list');
  const query = ($('#notes-search').value || '').trim().toLowerCase();

  const filtered = state.notes.filter(
    (n) => n.title.toLowerCase().includes(query) || n.content.toLowerCase().includes(query)
  );

  updatePostureUI();

  list.textContent = '';
  empty.hidden = filtered.length > 0;

  for (const note of filtered) {
    const li = document.createElement('li');
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'note-list-btn';
    if (!state.isCreatingNewNote && note.id === state.selectedNoteId) {
      btn.classList.add('is-selected');
    }

    const titleEl = document.createElement('span');
    titleEl.className = 'note-item-title';
    titleEl.textContent = note.title;

    const previewEl = document.createElement('span');
    previewEl.className = 'note-item-preview';
    previewEl.textContent = note.content.slice(0, 96);

    const metaEl = document.createElement('span');
    metaEl.className = 'note-item-meta';
    metaEl.textContent = `${formatDate(note.updatedAt)} · Llave v${note.keyVersion}`;

    btn.append(titleEl, previewEl, metaEl);
    btn.addEventListener('click', () => selectNote(note.id));
    li.appendChild(btn);
    list.appendChild(li);
  }
}

function updateCharCounter() {
  const len = $('#note-content-input').value.length;
  $('#editor-char-count').textContent = `${len.toLocaleString('es-MX')} / ${state.noteLimits.maxContentLength.toLocaleString('es-MX')}`;
}

function selectNote(noteId) {
  const note = state.notes.find((n) => n.id === noteId);
  if (!note) return;
  state.selectedNoteId = note.id;
  state.isCreatingNewNote = false;

  $('#quick-templates-bar').hidden = true;
  $('#inspect-crypto-btn').hidden = false;
  $('#inspector-key-version').textContent = `v${note.keyVersion}`;
  $('#inspector-mac').textContent = note.integrityMac || '—';
  $('#note-title-input').value = note.title;
  $('#note-content-input').value = note.content;
  $('#editor-crypto-text').textContent = `AES-256-GCM · Llave v${note.keyVersion}`;
  $('#editor-updated-at').textContent = `Guardada ${formatDate(note.updatedAt)}`;
  $('#delete-note-btn').hidden = false;
  $('#save-note-btn span').textContent = 'Guardar cambios';
  updateCharCounter();
  renderNotesList();
}

function startNewNote() {
  state.isCreatingNewNote = true;
  state.selectedNoteId = null;
  $('#quick-templates-bar').hidden = false;
  $('#inspect-crypto-btn').hidden = true;
  $('#crypto-inspector').hidden = true;
  $('#inspect-crypto-btn').setAttribute('aria-expanded', 'false');
  $('#note-title-input').value = '';
  $('#note-content-input').value = '';
  $('#editor-crypto-text').textContent = 'AES-256-GCM · IV único al guardar';
  $('#editor-updated-at').textContent = 'Borrador sin guardar';
  $('#delete-note-btn').hidden = true;
  $('#save-note-btn span').textContent = 'Guardar y cifrar';
  updateCharCounter();
  renderNotesList();
  $('#note-title-input').focus();
}

async function loadNotes() {
  const data = await api('/api/notes');
  state.notes = data.notes || [];
  if (data.limits) state.noteLimits = data.limits;

  if (state.notes.length > 0 && !state.isCreatingNewNote) {
    const keep = state.notes.find((n) => n.id === state.selectedNoteId);
    selectNote(keep ? keep.id : state.notes[0].id);
  } else if (state.notes.length === 0) {
    startNewNote();
  } else {
    renderNotesList();
  }
}

async function loadProfile() {
  const { profile } = await api('/api/profile');
  state.user = {
    ...state.user,
    name: profile.name,
    mfaEnabled: profile.mfaEnabled,
    phoneMasked: profile.phoneMasked,
  };
  updatePostureUI();

  $('#profile-name').value = profile.name;
  $('#profile-banner-name').textContent = profile.name;
  $('#profile-avatar-lg').textContent = (profile.name || 'U').slice(0, 1).toUpperCase();
  $('#profile-email-display').textContent = profile.email;
  $('#profile-role-pill').textContent = profile.role === 'admin' ? 'Administrador' : 'Usuario';
  $('#profile-phone').value = '';
  $('#profile-phone-masked').textContent = profile.phoneMasked || 'No registrado';
  $('#reveal-phone-btn').hidden = !profile.hasSensitiveData;

  const badge = $('#mfa-status-badge');
  const pill = $('#profile-mfa-pill');
  badge.textContent = profile.mfaEnabled ? 'Activo' : 'Desactivado';
  badge.classList.toggle('is-active', profile.mfaEnabled);
  pill.textContent = profile.mfaEnabled ? 'MFA TOTP activo' : 'MFA desactivado';
  pill.classList.toggle('is-active', profile.mfaEnabled);

  $('#mfa-setup-btn').hidden = profile.mfaEnabled;
  $('#mfa-disable-open-btn').hidden = !profile.mfaEnabled;
}

async function openMfaSetupSheet() {
  try {
    const data = await api('/api/auth/mfa/setup', { method: 'POST' });
    openSheet({
      title: 'Activar verificación en dos pasos',
      buildBody: (container) => {
        const p1 = document.createElement('p');
        p1.textContent = 'Agrega esta clave secreta en Apple Passwords, 1Password o Google Authenticator:';

        const secretBox = document.createElement('div');
        secretBox.className = 'secret-box';
        secretBox.textContent = data.secret;

        const uriHint = document.createElement('p');
        uriHint.className = 'field-hint';
        uriHint.textContent = `URI otpauth: ${data.otpauthUri}`;

        const form = document.createElement('form');
        form.className = 'stack-sm';

        const label = document.createElement('label');
        label.textContent = 'Código de confirmación (6 dígitos)';
        label.htmlFor = 'sheet-mfa-code';

        const input = document.createElement('input');
        input.id = 'sheet-mfa-code';
        input.type = 'text';
        input.inputMode = 'numeric';
        input.maxLength = 6;
        input.placeholder = '000000';
        input.className = 'input-code';
        input.required = true;

        const actions = document.createElement('div');
        actions.className = 'sheet-actions';

        const cancelBtn = document.createElement('button');
        cancelBtn.type = 'button';
        cancelBtn.className = 'btn btn-secondary';
        cancelBtn.textContent = 'Cancelar';
        cancelBtn.addEventListener('click', () => sheet.close());

        const confirmBtn = document.createElement('button');
        confirmBtn.type = 'submit';
        confirmBtn.className = 'btn btn-primary btn-shimmer';
        confirmBtn.textContent = 'Activar MFA';

        actions.append(cancelBtn, confirmBtn);
        form.append(label, input, actions);

        form.addEventListener('submit', async (e) => {
          e.preventDefault();
          try {
            await api('/api/auth/mfa/enable', {
              method: 'POST',
              body: { code: input.value.trim() },
            });
            sheet.close();
            showToast('Verificación en dos pasos activada.');
            await loadProfile();
          } catch (err) {
            showToast(err.message, { isError: true });
          }
        });

        container.append(p1, secretBox, uriHint, form);
        requestAnimationFrame(() => input.focus());
      },
    });
  } catch (err) {
    showToast(err.message, { isError: true });
  }
}

function openMfaDisableSheet() {
  openSheet({
    title: 'Desactivar verificación en dos pasos',
    buildBody: (container) => {
      const p = document.createElement('p');
      p.textContent = 'Ingresa un código actual de 6 dígitos para confirmar la desactivación de TOTP.';

      const form = document.createElement('form');
      form.className = 'stack-sm';

      const input = document.createElement('input');
      input.type = 'text';
      input.inputMode = 'numeric';
      input.maxLength = 6;
      input.placeholder = '000000';
      input.className = 'input-code';
      input.required = true;

      const actions = document.createElement('div');
      actions.className = 'sheet-actions';

      const cancelBtn = document.createElement('button');
      cancelBtn.type = 'button';
      cancelBtn.className = 'btn btn-secondary';
      cancelBtn.textContent = 'Cancelar';
      cancelBtn.addEventListener('click', () => sheet.close());

      const disableBtn = document.createElement('button');
      disableBtn.type = 'submit';
      disableBtn.className = 'btn btn-danger';
      disableBtn.textContent = 'Desactivar MFA';

      actions.append(cancelBtn, disableBtn);
      form.append(input, actions);

      form.addEventListener('submit', async (e) => {
        e.preventDefault();
        try {
          await api('/api/auth/mfa/disable', {
            method: 'POST',
            body: { code: input.value.trim() },
          });
          sheet.close();
          showToast('MFA desactivado.');
          await loadProfile();
        } catch (err) {
          showToast(err.message, { isError: true });
        }
      });

      container.append(p, form);
      requestAnimationFrame(() => input.focus());
    },
  });
}

async function loadAdminData() {
  const filter = $('#audit-filter-select').value;
  const logUrl = filter
    ? `/api/admin/audit-logs?eventType=${encodeURIComponent(filter)}&limit=100`
    : '/api/admin/audit-logs?limit=100';

  const [usersData, logsData, alertsData] = await Promise.all([
    api('/api/admin/users'),
    api(logUrl),
    api('/api/admin/alerts'),
  ]);

  $('#key-version-info').textContent = `Versión activa: v${usersData.activeEncryptionKeyVersion} · Llaves cargadas: ${usersData.loadedKeyVersions.map((v) => `v${v}`).join(', ')}`;

  const usersBody = $('#admin-users-tbody');
  usersBody.textContent = '';
  for (const u of usersData.users) {
    const tr = document.createElement('tr');

    const tdUser = document.createElement('td');
    const nameDiv = document.createElement('div');
    nameDiv.className = 'cell-primary';
    nameDiv.textContent = u.name;
    const emailDiv = document.createElement('div');
    emailDiv.className = 'cell-secondary';
    emailDiv.textContent = u.email;
    tdUser.append(nameDiv, emailDiv);

    const tdPhone = document.createElement('td');
    tdPhone.className = 'cell-code';
    tdPhone.textContent = u.phoneMasked || '—';

    const tdRole = document.createElement('td');
    const roleBadge = document.createElement('span');
    roleBadge.className = `status-badge ${u.role === 'admin' ? 'is-active' : ''}`;
    roleBadge.textContent = u.role === 'admin' ? 'Administrador' : 'Usuario';
    tdRole.appendChild(roleBadge);

    const tdMfa = document.createElement('td');
    tdMfa.textContent = u.mfaEnabled ? 'TOTP activo' : 'No';

    const tdState = document.createElement('td');
    const locked = u.lockedUntil && new Date(u.lockedUntil).getTime() > Date.now();
    tdState.textContent = locked ? 'Bloqueado' : 'Normal';

    const tdAction = document.createElement('td');
    const toggleBtn = document.createElement('button');
    toggleBtn.type = 'button';
    toggleBtn.className = 'btn btn-secondary btn-sm';
    const nextRole = u.role === 'admin' ? 'user' : 'admin';
    toggleBtn.textContent = nextRole === 'admin' ? 'Hacer admin' : 'Pasar a usuario';
    toggleBtn.addEventListener('click', async () => {
      try {
        await api(`/api/admin/users/${encodeURIComponent(u.id)}/role`, {
          method: 'PATCH',
          body: { role: nextRole },
        });
        showToast(`Rol de ${u.email} actualizado a ${nextRole}.`);
        await loadAdminData();
      } catch (err) {
        showToast(err.message, { isError: true });
      }
    });
    tdAction.appendChild(toggleBtn);

    tr.append(tdUser, tdPhone, tdRole, tdMfa, tdState, tdAction);
    usersBody.appendChild(tr);
  }

  const logsBody = $('#admin-logs-tbody');
  logsBody.textContent = '';
  for (const ev of logsData.events) {
    const tr = document.createElement('tr');

    const tdDate = document.createElement('td');
    tdDate.textContent = formatDate(ev.createdAt);

    const tdType = document.createElement('td');
    tdType.className = 'cell-code';
    tdType.textContent = ev.eventType;

    const tdSev = document.createElement('td');
    const sevBadge = document.createElement('span');
    sevBadge.className = `status-badge sev-${ev.severity}`;
    sevBadge.textContent = ev.severity;
    tdSev.appendChild(sevBadge);

    const tdActor = document.createElement('td');
    tdActor.textContent = ev.actorEmail || 'Anónimo';

    const tdIp = document.createElement('td');
    tdIp.className = 'cell-code';
    tdIp.textContent = ev.ipAddress || '—';

    const tdDet = document.createElement('td');
    tdDet.className = 'cell-code';
    tdDet.textContent = JSON.stringify(ev.details);

    tr.append(tdDate, tdType, tdSev, tdActor, tdIp, tdDet);
    logsBody.appendChild(tr);
  }

  const alertsBody = $('#admin-alerts-tbody');
  alertsBody.textContent = '';
  if (alertsData.alerts.length === 0) {
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 6;
    td.className = 'cell-secondary';
    td.textContent = 'Sin alertas de seguridad abiertas.';
    tr.appendChild(td);
    alertsBody.appendChild(tr);
  } else {
    for (const al of alertsData.alerts) {
      const tr = document.createElement('tr');

      const tdDate = document.createElement('td');
      tdDate.textContent = formatDate(al.createdAt);

      const tdType = document.createElement('td');
      tdType.className = 'cell-code';
      tdType.textContent = al.alertType;

      const tdSev = document.createElement('td');
      const sevBadge = document.createElement('span');
      sevBadge.className = `status-badge sev-${al.severity}`;
      sevBadge.textContent = al.severity;
      tdSev.appendChild(sevBadge);

      const tdSum = document.createElement('td');
      tdSum.textContent = al.summary;

      const tdSt = document.createElement('td');
      tdSt.textContent = al.status === 'open' ? 'Abierta' : 'Atendida';

      const tdAct = document.createElement('td');
      if (al.status === 'open') {
        const ackBtn = document.createElement('button');
        ackBtn.type = 'button';
        ackBtn.className = 'btn btn-secondary btn-sm';
        ackBtn.textContent = 'Marcar atendida';
        ackBtn.addEventListener('click', async () => {
          try {
            await api(`/api/admin/alerts/${encodeURIComponent(al.id)}/ack`, { method: 'PATCH' });
            showToast('Alerta marcada como atendida.');
            await loadAdminData();
          } catch (err) {
            showToast(err.message, { isError: true });
          }
        });
        tdAct.appendChild(ackBtn);
      } else {
        tdAct.textContent = '—';
      }

      tr.append(tdDate, tdType, tdSev, tdSum, tdSt, tdAct);
      alertsBody.appendChild(tr);
    }
  }
}

async function enterVault(user) {
  state.user = user;
  $('#auth-screen').hidden = true;
  $('#app-shell').hidden = false;

  $('#sidebar-user-name').textContent = user.name;
  $('#sidebar-user-role').textContent = user.role === 'admin' ? 'Administrador' : 'Usuario';
  $('#sidebar-avatar').textContent = (user.name || 'U').slice(0, 1).toUpperCase();
  $('#nav-admin-btn').hidden = user.role !== 'admin';

  updatePostureUI();
  switchView('notes');
  await loadNotes();
}

function exitVault() {
  state.user = null;
  state.csrfToken = null;
  state.notes = [];
  state.selectedNoteId = null;
  $('#app-shell').hidden = true;
  $('#auth-screen').hidden = false;
  setAuthTab('login');
  requestAnimationFrame(() => authSegmented.sync(true));
}

function wireEvents() {
  $$('[data-auth-tab]').forEach((btn) => {
    btn.addEventListener('click', () => setAuthTab(btn.dataset.authTab));
  });

  $$('[data-admin-tab]').forEach((btn) => {
    btn.addEventListener('click', () => setAdminTab(btn.dataset.adminTab));
  });

  $$('.nav-item').forEach((btn) => {
    btn.addEventListener('click', () => switchView(btn.dataset.view));
  });

  $('#tile-notes-shortcut').addEventListener('click', () => startNewNote());
  $('#tile-mfa-shortcut').addEventListener('click', () => switchView('profile'));
  $('#tile-phone-shortcut').addEventListener('click', () => switchView('profile'));

  $('#inspect-crypto-btn').addEventListener('click', () => {
    const panel = $('#crypto-inspector');
    const nextHidden = !panel.hidden;
    panel.hidden = nextHidden;
    $('#inspect-crypto-btn').setAttribute('aria-expanded', String(!nextHidden));
  });

  $$('.template-chip').forEach((chip) => {
    chip.addEventListener('click', () => {
      const tpl = NOTE_TEMPLATES[chip.dataset.template];
      if (!tpl) return;
      $('#note-title-input').value = tpl.title;
      $('#note-content-input').value = tpl.content;
      updateCharCounter();
      $('#note-content-input').focus();
    });
  });

  $('#copy-note-btn').addEventListener('click', async () => {
    const content = $('#note-content-input').value;
    if (!content) {
      showToast('No hay contenido para copiar.', { isError: true });
      return;
    }
    try {
      await navigator.clipboard.writeText(content);
      showToast('Contenido copiado al portapapeles.');
    } catch {
      showToast('No fue posible acceder al portapapeles.', { isError: true });
    }
  });

  $('#login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    showAuthFeedback('');
    const btn = $('#login-submit');
    btn.disabled = true;
    try {
      const data = await api('/api/auth/login', {
        method: 'POST',
        body: {
          email: $('#login-email').value.trim(),
          password: $('#login-password').value,
        },
      });

      if (data.mfaRequired) {
        $('#login-form').hidden = true;
        $('#mfa-login-form').hidden = false;
        $('#mfa-login-code').value = '';
        $('#mfa-login-code').focus();
      } else {
        $('#login-password').value = '';
        await enterVault(data.user);
      }
    } catch (err) {
      showAuthFeedback(err.message, 'error');
    } finally {
      btn.disabled = false;
    }
  });

  $('#mfa-back-btn').addEventListener('click', () => {
    $('#mfa-login-form').hidden = true;
    $('#login-form').hidden = false;
    showAuthFeedback('');
  });

  $('#mfa-login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    showAuthFeedback('');
    const btn = $('#mfa-verify-btn');
    btn.disabled = true;
    try {
      const data = await api('/api/auth/mfa/login', {
        method: 'POST',
        body: { code: $('#mfa-login-code').value.trim() },
      });
      await enterVault(data.user);
    } catch (err) {
      showAuthFeedback(err.message, 'error');
    } finally {
      btn.disabled = false;
    }
  });

  $('#register-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    showAuthFeedback('');
    const btn = $('#register-submit');
    btn.disabled = true;
    try {
      const payload = {
        name: $('#reg-name').value.trim(),
        email: $('#reg-email').value.trim(),
        password: $('#reg-password').value,
      };
      const phone = $('#reg-phone').value.trim();
      if (phone) payload.phone = phone;

      const data = await api('/api/auth/register', { method: 'POST', body: payload });
      $('#reg-password').value = '';
      showToast('Bóveda personal creada correctamente.');
      await enterVault(data.user);
    } catch (err) {
      showAuthFeedback(err.message, 'error');
    } finally {
      btn.disabled = false;
    }
  });

  $('#forgot-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    showAuthFeedback('');
    try {
      const data = await api('/api/auth/forgot-password', {
        method: 'POST',
        body: { email: $('#forgot-email').value.trim() },
      });
      showAuthFeedback(data.message, 'success');
    } catch (err) {
      showAuthFeedback(err.message, 'error');
    }
  });

  $('#reset-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    showAuthFeedback('');
    try {
      const data = await api('/api/auth/reset-password', {
        method: 'POST',
        body: {
          token: $('#reset-token').value.trim(),
          newPassword: $('#reset-password').value,
        },
      });
      $('#reset-token').value = '';
      $('#reset-password').value = '';
      setAuthTab('login');
      showAuthFeedback(data.message, 'success');
    } catch (err) {
      showAuthFeedback(err.message, 'error');
    }
  });

  $('#logout-btn').addEventListener('click', async () => {
    try {
      await api('/api/auth/logout', { method: 'POST' });
    } catch {
      // Clear state regardless
    }
    exitVault();
    showToast('Sesión cerrada.');
  });

  $('#notes-search').addEventListener('input', renderNotesList);
  $('#new-note-btn').addEventListener('click', startNewNote);
  $('#note-content-input').addEventListener('input', updateCharCounter);

  $('#note-editor-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const title = $('#note-title-input').value.trim();
    const content = $('#note-content-input').value;
    if (!title || !content) {
      showToast('Escribe un título y contenido para la nota.', { isError: true });
      return;
    }

    const btn = $('#save-note-btn');
    btn.disabled = true;
    try {
      if (state.isCreatingNewNote || !state.selectedNoteId) {
        const { note } = await api('/api/notes', { method: 'POST', body: { title, content } });
        state.notes.unshift(note);
        selectNote(note.id);
        showToast('Nota cifrada y guardada.');
      } else {
        const { note } = await api(`/api/notes/${encodeURIComponent(state.selectedNoteId)}`, {
          method: 'PATCH',
          body: { title, content },
        });
        const idx = state.notes.findIndex((n) => n.id === note.id);
        if (idx !== -1) state.notes[idx] = note;
        selectNote(note.id);
        showToast('Cambios guardados y re-cifrados.');
      }
    } catch (err) {
      showToast(err.message, { isError: true });
    } finally {
      btn.disabled = false;
    }
  });

  $('#delete-note-btn').addEventListener('click', () => {
    if (!state.selectedNoteId) return;
    const note = state.notes.find((n) => n.id === state.selectedNoteId);
    openSheet({
      title: 'Eliminar nota privada',
      buildBody: (container) => {
        const p = document.createElement('p');
        p.textContent = `¿Seguro que deseas eliminar "${note?.title || 'esta nota'}"? Esta acción es permanente y no se puede deshacer.`;

        const actions = document.createElement('div');
        actions.className = 'sheet-actions';

        const cancelBtn = document.createElement('button');
        cancelBtn.type = 'button';
        cancelBtn.className = 'btn btn-secondary';
        cancelBtn.textContent = 'Cancelar';
        cancelBtn.addEventListener('click', () => sheet.close());

        const delBtn = document.createElement('button');
        delBtn.type = 'button';
        delBtn.className = 'btn btn-danger';
        delBtn.textContent = 'Eliminar nota';
        delBtn.addEventListener('click', async () => {
          try {
            await api(`/api/notes/${encodeURIComponent(state.selectedNoteId)}`, { method: 'DELETE' });
            state.notes = state.notes.filter((n) => n.id !== state.selectedNoteId);
            sheet.close();
            showToast('Nota eliminada.');
            if (state.notes.length > 0) {
              selectNote(state.notes[0].id);
            } else {
              startNewNote();
            }
          } catch (err) {
            showToast(err.message, { isError: true });
          }
        });

        actions.append(cancelBtn, delBtn);
        container.append(p, actions);
      },
    });
  });

  $('#profile-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const payload = { name: $('#profile-name').value.trim() };
    const phoneVal = $('#profile-phone').value.trim();
    if (phoneVal !== '') payload.phone = phoneVal;

    try {
      const { profile } = await api('/api/profile', { method: 'PATCH', body: payload });
      state.user.name = profile.name;
      state.user.phoneMasked = profile.phoneMasked;
      $('#sidebar-user-name').textContent = profile.name;
      $('#sidebar-avatar').textContent = profile.name.slice(0, 1).toUpperCase();
      $('#profile-banner-name').textContent = profile.name;
      $('#profile-avatar-lg').textContent = profile.name.slice(0, 1).toUpperCase();
      $('#profile-phone').value = '';
      $('#profile-phone-masked').textContent = profile.phoneMasked || 'No registrado';
      $('#reveal-phone-btn').hidden = !profile.hasSensitiveData;
      updatePostureUI();
      showToast('Perfil actualizado.');
    } catch (err) {
      showToast(err.message, { isError: true });
    }
  });

  $('#reveal-phone-btn').addEventListener('click', async () => {
    try {
      const { phone } = await api('/api/profile/reveal', { method: 'POST' });
      $('#profile-phone-masked').textContent = phone;
      showToast('Dato revelado temporalmente (15 s). Evento auditado.');
      clearTimeout(state.revealTimer);
      state.revealTimer = setTimeout(() => loadProfile().catch(() => {}), 15_000);
    } catch (err) {
      showToast(err.message, { isError: true });
    }
  });

  $('#mfa-setup-btn').addEventListener('click', openMfaSetupSheet);
  $('#mfa-disable-open-btn').addEventListener('click', openMfaDisableSheet);

  $('#admin-refresh-btn').addEventListener('click', () => {
    loadAdminData()
      .then(() => showToast('Datos actualizados.'))
      .catch((err) => showToast(err.message, { isError: true }));
  });
  $('#audit-filter-select').addEventListener('change', () => {
    loadAdminData().catch((err) => showToast(err.message, { isError: true }));
  });
  $('#rotate-keys-btn').addEventListener('click', async () => {
    try {
      const { summary } = await api('/api/admin/rotate-keys', { method: 'POST' });
      showToast(
        `Rotación a v${summary.targetVersion}: ${summary.notesRotated} notas, ${summary.phonesRotated} perfiles, ${summary.mfaSecretsRotated} secretos MFA.`
      );
      await loadAdminData();
    } catch (err) {
      showToast(err.message, { isError: true });
    }
  });
}

async function bootstrap() {
  initTheme();
  initMagicSpotlights();
  initSidebarCollapse();
  bindPasswordStrength();
  wireEvents();
  checkHealth();
  requestAnimationFrame(() => authSegmented.sync(true));

  try {
    const data = await api('/api/auth/me');
    await enterVault(data.user);
  } catch {
    exitVault();
  }
}

bootstrap();
