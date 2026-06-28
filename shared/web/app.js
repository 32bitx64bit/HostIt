var $ = function (s, r) { return (r || document).querySelector(s); };
var $$ = function (s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); };
function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c]; }); }
function cssVar(n) { return getComputedStyle(document.documentElement).getPropertyValue(n).trim(); }
function pad(n) { return n < 10 ? '0' + n : '' + n; }
function nowClock() { var d = new Date(); return pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds()); }
function randHex(n) { var h = ''; for (var i = 0; i < (n || 8); i++) h += '0123456789abcdef'[Math.floor(Math.random() * 16)]; return h; }

function protoTag(p) {
  return '<span class="tag ' + p + '">' + p.toUpperCase() + '</span>';
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

function logHtml(cls, src, msg) {
  return '<div class="ln"><span class="ts">' + nowClock() + '</span> <span class="' + cls + '">' + src + '</span> ' + esc(msg) + '</div>';
}

function pushLog(id, html, cap) {
  var c = $('#' + id); if (!c) return;
  c.insertAdjacentHTML('beforeend', html);
  while (c.childNodes.length > (cap || 90)) c.removeChild(c.firstChild);
  c.scrollTop = c.scrollHeight;
}

var RANGE = { '1H': 12, '6H': 24, '12H': 36, '24H': 48 };

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

function makeChartSeries(n, base, amp, noise) {
  var arr = [];
  for (var i = 0; i < n; i++) arr.push(base + Math.sin(i / 4) * amp + Math.random() * noise);
  return arr;
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

function initTabs(tabSelector, sectionPrefix, winId) {
  var tabs = $$(tabSelector);
  tabs.forEach(function (t) {
    t.addEventListener('click', function () {
      var id = t.getAttribute('data-tab');
      tabs.forEach(function (x) { x.classList.toggle('active', x === t); });
      $$(sectionPrefix).forEach(function (s) { s.classList.toggle('active', s.id === 'sec-' + id); });
      if (winId) { var w = $('#' + winId); if (w) w.textContent = id; }
    });
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

function initChartScales(target, getRange, setRange, render) {
  $$('.chip[data-target="' + target + '"]').forEach(function (c) {
    c.addEventListener('click', function () {
      var rng = c.getAttribute('data-range');
      $$('.chip[data-target="' + target + '"]').forEach(function (x) { x.classList.toggle('active', x === c); });
      setRange(rng); render();
    });
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
