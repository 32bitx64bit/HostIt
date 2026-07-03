var $ = function (s, r) { return (r || document).querySelector(s); };
var $$ = function (s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); };
function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c]; }); }
function cssVar(n) { return getComputedStyle(document.documentElement).getPropertyValue(n).trim(); }
function pad(n) { return n < 10 ? '0' + n : '' + n; }
function nowClock() { var d = new Date(); return pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds()); }

var CSRF = (function () { var m = document.querySelector('meta[name="csrf-token"]'); return m ? m.content : ''; })();

var _reloadTimer;
function scheduleReload() { if (_reloadTimer) return; _reloadTimer = setTimeout(function () { location.reload(); }, 1500); }

function apiData(payload) {
  if (payload && payload.status === 'ok' && payload.data !== undefined) return payload.data;
  if (payload && payload.status === 'error') throw new Error(payload.message || 'API error');
  return payload;
}
async function readAPI(res) { return apiData(await res.json()); }

async function fetchJSON(url, timeoutMs) {
  var ctl = new AbortController();
  var timer = setTimeout(function () { ctl.abort(); }, timeoutMs || 5000);
  try {
    var res = await fetch(url, { cache: 'no-store', headers: { 'Accept': 'application/json' }, signal: ctl.signal });
    var ct = res.headers.get('content-type') || '';
    if (res.redirected || ct.indexOf('application/json') < 0) { scheduleReload(); throw new Error('dashboard response changed'); }
    if (!res.ok) throw new Error('http ' + res.status);
    return await readAPI(res);
  } finally { clearTimeout(timer); }
}

async function pollJSON(url, timeoutMs) {
  var ctl = new AbortController();
  var timer = setTimeout(function () { ctl.abort(); }, timeoutMs || 8000);
  try {
    var res = await fetch(url, { cache: 'no-store', headers: { 'Accept': 'application/json' }, signal: ctl.signal });
    if (!res.ok || res.redirected) return null;
    var ct = res.headers.get('content-type') || '';
    if (ct.indexOf('application/json') < 0) return null;
    return await readAPI(res);
  } catch (e) { return null; } finally { clearTimeout(timer); }
}

function apiPost(url, data) {
  var body = new URLSearchParams();
  body.set('csrf', CSRF);
  if (data) for (var k in data) body.set(k, data[k]);
  return fetch(url, { method: 'POST', headers: { 'X-CSRF-Token': CSRF, 'Content-Type': 'application/x-www-form-urlencoded' }, body: body.toString() });
}

function initLogout(btnId) {
  var btn = $('#' + (btnId || 'logoutBtn'));
  if (!btn) return;
  btn.addEventListener('click', function () {
    var f = document.createElement('form');
    f.method = 'POST'; f.action = '/logout';
    var i = document.createElement('input');
    i.type = 'hidden'; i.name = 'csrf'; i.value = CSRF;
    f.appendChild(i);
    document.body.appendChild(f);
    f.submit();
  });
}

function setStatus(id, text, kind) {
  var el = typeof id === 'string' ? $('#' + id) : id;
  if (!el) return;
  var span = el.querySelector('span:last-child');
  if (span) span.textContent = text;
  el.classList.remove('flash', 'err');
  if (kind === 'ok') el.classList.add('flash');
  if (kind === 'err') el.classList.add('err');
  clearTimeout(el._t);
  el._t = setTimeout(function () { el.classList.remove('flash', 'err'); }, 2200);
}

function drawBars(cfg) {
  var svg = $('#' + cfg.svg); if (!svg) return;
  var W = 400, H = 120, padT = 6, padB = 6, padL = 30;
  var data = cfg.data;
  var max = Math.max.apply(null, data) * 1.15 || 1;
  var n = data.length, bw = (W - padL) / n;
  var color = cssVar('--yellow') || '#fabd2f';
  var grid = cssVar('--bg4') || '#7c6f64';
  var inner = '';
  var fracs = [1, 0.75, 0.5, 0.25, 0];
  fracs.forEach(function (f) {
    var gy = padT + (H - padT - padB) * (1 - f);
    var op = (f === 0) ? '0.7' : '0.5';
    var dash = (f === 0) ? '' : ' stroke-dasharray="3 4"';
    inner += '<line x1="' + padL + '" y1="' + gy.toFixed(1) + '" x2="' + W + '" y2="' + gy.toFixed(1) + '" stroke="' + grid + '" stroke-opacity="' + op + '"' + dash + ' stroke-width="1"/>';
  });
  data.forEach(function (v, idx) {
    var h = (H - padT - padB) * (v / max);
    var x = padL + idx * bw;
    var y = H - padB - h;
    inner += '<rect class="bbar" x="' + (x + 0.5).toFixed(1) + '" y="' + y.toFixed(1) + '" width="' + Math.max(1, bw - 1).toFixed(1) + '" height="' + h.toFixed(1) + '" fill="' + color + '" opacity="0.85" data-v="' + v.toFixed(2) + '" data-unit="' + cfg.unit + '"/>';
  });
  svg.innerHTML = inner;
  var last = data[data.length - 1];
  $('#' + cfg.readout).textContent = cfg.fmt(last) + ' ' + cfg.unit;
  $('#' + cfg.big).textContent = cfg.bigfmt(last);
  var axis = $('#' + cfg.axis);
  if (axis) {
    var ah = '';
    fracs.forEach(function (f) {
      var val = max * f, ay = padT + (H - padT - padB) * (1 - f);
      ah += '<span style="top:' + (ay - 5).toFixed(1) + 'px">' + cfg.axisfmt(val) + '</span>';
    });
    axis.innerHTML = ah;
  }
}

function styleSelects(root) {
  var sels = (root || document).querySelectorAll('select.select:not([data-dd="1"])');
  Array.prototype.forEach.call(sels, function (sel) {
    sel.setAttribute('data-dd', '1');
    sel.style.display = 'none';
    var wrap = document.createElement('div');
    wrap.className = 'dd';
    sel.parentNode.insertBefore(wrap, sel);
    wrap.appendChild(sel);
    var btn = document.createElement('div');
    btn.className = 'dd-btn'; btn.tabIndex = 0;
    btn.setAttribute('role', 'button'); btn.setAttribute('aria-haspopup', 'listbox');
    var lbl = document.createElement('span'); lbl.className = 'dd-label';
    var caret = document.createElement('span'); caret.className = 'dd-caret'; caret.innerHTML = '&#9662;';
    btn.appendChild(lbl); btn.appendChild(caret);
    var menu = document.createElement('div'); menu.className = 'dd-menu';
    wrap.appendChild(btn); wrap.appendChild(menu);
    function sync() {
      var o = sel.options[sel.selectedIndex];
      lbl.textContent = o ? o.textContent : '';
      for (var i = 0; i < menu.children.length; i++)
        menu.children[i].classList.toggle('sel', menu.children[i].getAttribute('data-val') === sel.value);
    }
    function build() {
      menu.innerHTML = '';
      Array.prototype.forEach.call(sel.options, function (o) {
        var item = document.createElement('div');
        item.className = 'dd-opt'; item.setAttribute('data-val', o.value); item.textContent = o.textContent;
        item.addEventListener('click', function (e) {
          e.stopPropagation(); sel.value = o.value; sel.dispatchEvent(new Event('change', { bubbles: true }));
          sync(); wrap.classList.remove('open');
        });
        menu.appendChild(item);
      });
      sync();
    }
    btn.addEventListener('click', function (e) { e.stopPropagation(); wrap.classList.toggle('open'); });
    btn.addEventListener('keydown', function (e) {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); e.stopPropagation(); wrap.classList.toggle('open'); }
      else if (e.key === 'Escape') wrap.classList.remove('open');
    });
    sel.addEventListener('change', sync);
    build();
  });
  if (!window._ddDocBound) {
    window._ddDocBound = true;
    document.addEventListener('click', function () { $$('.dd.open').forEach(function (d) { d.classList.remove('open'); }); });
    document.addEventListener('keydown', function (e) { if (e.key === 'Escape') $$('.dd.open').forEach(function (d) { d.classList.remove('open'); }); });
  }
}

function initTheme(btnId, key) {
  var btn = $('#' + btnId);
  if (!btn) return;
  function label() { btn.textContent = document.documentElement.getAttribute('data-theme'); }
  label();
  btn.addEventListener('click', function () {
    var cur = document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark';
    var next = cur === 'light' ? 'dark' : 'light';
    document.documentElement.setAttribute('data-theme', next);
    try { localStorage.setItem(key, next); } catch (e) {}
    label();
  });
}

function initChartTooltip() {
  document.addEventListener('mousemove', function (e) {
    var tip = $('#tip');
    if (!tip) return;
    if (e.target && e.target.classList && e.target.classList.contains('bbar')) {
      tip.style.display = 'block';
      var u = e.target.getAttribute('data-unit') || 'MiB';
      var dv = parseFloat(e.target.getAttribute('data-v'));
      tip.textContent = (u === 'MiB' ? dv.toFixed(2) : '' + Math.round(dv)) + ' ' + u;
      tip.style.left = (e.clientX + 12) + 'px';
      tip.style.top = (e.clientY - 28) + 'px';
    } else { tip.style.display = 'none'; }
  });
}

function initClock(sbClockId) {
  var el = $('#' + sbClockId);
  if (!el) return;
  el.textContent = nowClock();
  setInterval(function () { el.textContent = nowClock(); }, 1000);
}

function bindToggleLabel(swId, lblId, on, off) {
  var sw = $('#' + swId), lbl = $('#' + lblId);
  if (!sw || !lbl) return;
  function up() { lbl.textContent = sw.checked ? on : off; }
  sw.addEventListener('change', up);
  up();
}

function renderMailChecks(report) {
  var el = $('#checkResults'); if (!el) return;
  if (!report) { el.innerHTML = '<div class="muted">No report.</div>'; return; }
  var html = '';
  if (report.summary) html += '<div class="statusline"><span class="gt">&gt;</span> <span>' + esc(report.summary) + '</span></div>';
  if (report.counts) {
    html += '<div class="btn-row" style="margin:8px 0;">'
      + Ember.badge({ text: 'ok ' + report.counts.ok, state: 'good' })
      + Ember.badge({ text: 'warn ' + report.counts.warn, state: 'warn' })
      + Ember.badge({ text: 'fail ' + report.counts.fail, state: 'bad' })
      + '</div>';
  }
  var checks = report.checks || [];
  if (!checks.length) html += '<div class="muted">No checks ran.</div>';
  else html += checks.map(function (c) {
    return Ember.checkItem({ name: c.name, status: c.status, summary: c.summary, fix: c.fix, details: c.details });
  }).join('');
  el.innerHTML = html;
}

function initMailChecks(statusId) {
  var btn = $('#runChecksBtn'); if (!btn) return;
  btn.addEventListener('click', async function () {
    btn.disabled = true;
    setStatus(statusId, 'running mail checks...', 'ok');
    var el = $('#checkResults'); if (el) el.innerHTML = '<div class="muted">checking...</div>';
    try {
      var res = await apiPost('/api/email/check', {});
      if (res.ok) { renderMailChecks(await res.json()); setStatus(statusId, 'checks complete', 'ok'); }
      else {
        var t = await res.text();
        if (el) el.innerHTML = '<div class="statusline err"><span class="gt">&gt;</span> <span>' + esc(t.slice(0, 200)) + '</span></div>';
        setStatus(statusId, 'check error', 'err');
      }
    } catch (e) {
      if (el) el.innerHTML = '<div class="muted">error: ' + esc(e.message) + '</div>';
      setStatus(statusId, 'error: ' + e.message, 'err');
    } finally { btn.disabled = false; }
  });
}

function parseVersionTag(s) {
  s = String(s || '').trim();
  if (!s) return null;
  if (s.charAt(0) === 'v' || s.charAt(0) === 'V') s = s.slice(1);
  var parts = s.split('.');
  if (!parts.length || parts.length > 3) return null;
  var out = [0, 0, 0];
  for (var i = 0; i < parts.length; i++) {
    if (!/^\d+$/.test(parts[i])) return null;
    out[i] = Number(parts[i]);
  }
  return out;
}

function compareVersionTags(a, b) {
  a = parseVersionTag(a); b = parseVersionTag(b);
  if (!a || !b) return 0;
  for (var i = 0; i < 3; i++) {
    if (a[i] < b[i]) return -1;
    if (a[i] > b[i]) return 1;
  }
  return 0;
}

function isNewerVersion(available, current) {
  return compareVersionTags(available, current) > 0;
}
