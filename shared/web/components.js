var Ember = (function () {
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c]; }); }
  function opt(o, k, d) { return o && o[k] != null ? o[k] : d; }

  function sectionHead(o) {
    return '<div class="section-head">'
      + '<span class="prompt">&gt;</span>'
      + '<h1>' + esc(o.title) + '</h1>'
      + '<span class="crumb" id="' + esc(o.crumbId || '') + '">' + esc(o.crumb || '') + '</span>'
      + '</div>';
  }

  function grid(o) {
    var cls = 'grid' + (o.cols ? ' cols-' + o.cols : '') + (o.cls ? ' ' + o.cls : '');
    return '<div class="' + cls + '">' + (o.children || '') + '</div>';
  }

  function panel(o) {
    var head = '';
    if (o.title || o.head) {
      head = '<div class="panel-head">'
        + (o.title ? '<span class="ptitle">' + esc(o.title) + '</span>' : '')
        + (o.head || '')
        + '</div>';
    }
    return '<div class="panel' + (o.emph ? ' emph' : '') + (o.cls ? ' ' + o.cls : '') + '"' + (o.id ? ' id="' + esc(o.id) + '"' : '') + '>'
      + head
      + (o.body !== undefined ? '<div class="panel-body"' + (o.bodyFlush ? ' style="padding:0"' : '') + '>' + o.body + '</div>' : '')
      + '</div>';
  }

  function panelHead(o) {
    return '<div class="panel-head">'
      + (o.title ? '<span class="ptitle">' + esc(o.title) + '</span>' : '')
      + '<span class="pspacer"></span>'
      + (o.extra || '')
      + '</div>';
  }

  function tile(o) {
    return '<div class="panel"><div class="tile">'
      + '<span class="k">' + esc(o.label) + '</span>'
      + '<span class="v ' + (o.state || '') + (o.cls ? ' ' + o.cls : '') + '"' + (o.id ? ' id="' + esc(o.id) + '"' : '') + (o.style ? ' style="' + esc(o.style) + '"' : '') + '>' + (o.value != null ? esc(o.value) : '') + '</span>'
      + '</div></div>';
  }

  function badge(o) {
    return '<span class="badge ' + (o.state || 'neutral') + '"' + (o.id ? ' id="' + esc(o.id) + '"' : '') + '>' + esc(o.text) + '</span>';
  }

  function kv(o) {
    return '<div class="kv"' + (o.id ? ' id="' + esc(o.id) + '"' : '') + '>' + (o.pairs || []).map(function (p) {
      return '<span class="k">' + esc(p.k) + '</span><span class="v ' + (p.state || '') + '"' + (p.id ? ' id="' + esc(p.id) + '"' : '') + '>' + esc(p.v) + '</span>';
    }).join('') + '</div>';
  }

  function tag(o) {
    return '<span class="tag ' + esc(o.proto || 'tcp') + '">' + esc((o.proto || 'tcp').toUpperCase()) + '</span>';
  }
  function protoTag(p) { return tag({ proto: p }); }

  function statusline(o) {
    return '<div class="statusline"' + (o.id ? ' id="' + esc(o.id) + '"' : '') + '><span class="gt">&gt;</span> <span>' + esc(o.text || '') + '</span></div>';
  }

  function field(o) {
    return '<div class="field' + (o.cls ? ' ' + o.cls : '') + '">'
      + (o.label ? '<label' + (o.labelFor ? ' for="' + esc(o.labelFor) + '"' : '') + '>' + esc(o.label) + '</label>' : '')
      + (o.content || '')
      + (o.hint ? '<div class="hint">' + esc(o.hint) + '</div>' : '')
      + '</div>';
  }

  function input(o) {
    return '<input class="input' + (o.cls ? ' ' + o.cls : '') + '"'
      + (o.id ? ' id="' + esc(o.id) + '"' : '')
      + (o.dataF ? ' data-f="' + esc(o.dataF) + '"' : '')
      + ' type="' + esc(o.type || 'text') + '"'
      + (o.value != null ? ' value="' + esc(o.value) + '"' : '')
      + (o.placeholder ? ' placeholder="' + esc(o.placeholder) + '"' : '')
      + (o.readonly ? ' readonly' : '')
      + (o.spellcheck === false ? ' spellcheck="false"' : '')
      + ' autocomplete="off">';
  }

  function select(o) {
    var opts = (o.options || []).map(function (op) {
      return '<option value="' + esc(op.value) + '"' + (op.selected ? ' selected' : '') + '>' + esc(op.label || op.value) + '</option>';
    }).join('');
    return '<select class="select"' + (o.id ? ' id="' + esc(o.id) + '"' : '') + (o.dataF ? ' data-f="' + esc(o.dataF) + '"' : '') + '>' + opts + '</select>';
  }

  function textarea(o) {
    return '<textarea class="input' + (o.cls ? ' ' + o.cls : '') + '"' + (o.id ? ' id="' + esc(o.id) + '"' : '')
      + (o.rows ? ' rows="' + o.rows + '"' : '')
      + (o.readonly ? ' readonly' : '') + '>' + esc(o.value || '') + '</textarea>';
  }

  function toggle(o) {
    return '<label class="toggle">'
      + '<input type="checkbox"' + (o.id ? ' id="' + esc(o.id) + '"' : '') + (o.dataF ? ' data-f="' + esc(o.dataF) + '"' : '') + (o.checked ? ' checked' : '') + '>'
      + '<span class="track"></span>'
      + (o.label ? '<span class="tlabel"' + (o.labelId ? ' id="' + esc(o.labelId) + '"' : '') + '>' + esc(o.label) + '</span>' : '')
      + (o.sub ? '<span class="tsub">' + esc(o.sub) + '</span>' : '')
      + '</label>';
  }

  function button(o) {
    return '<button class="btn ' + (o.variant || '') + (o.cls ? ' ' + o.cls : '') + '"'
      + (o.id ? ' id="' + esc(o.id) + '"' : '')
      + ' type="' + esc(o.type || 'button') + '"'
      + (o.disabled ? ' disabled' : '') + '>'
      + esc(o.text)
      + '</button>';
  }

  function chart(o) {
    return '<div class="chart-meta">'
      + '<div><span class="big tnum"' + (o.bigId ? ' id="' + esc(o.bigId) + '"' : '') + '>' + esc(o.bigValue || '0') + '</span><span class="unit">' + esc(o.unit || '') + '</span></div>'
      + '<div class="muted" style="font-size:11px;">' + esc(o.sublabel || '') + '</div>'
      + '</div>'
      + '<div class="chart-box">'
      + '<div class="chart-axis"' + (o.axisId ? ' id="' + esc(o.axisId) + '"' : '') + '></div>'
      + '<svg id="' + esc(o.svgId) + '" viewBox="0 0 400 120" preserveAspectRatio="none"></svg>'
      + '</div>'
      + '<div class="scalebar">'
      + '<span class="muted" style="font-size:11px;">SCALE</span>'
      + ['1H', '6H', '12H', '24H'].map(function (r) {
        return '<button class="chip' + (r === (o.defaultRange || '6H') ? ' active' : '') + '" data-target="' + esc(o.target) + '" data-range="' + r + '">' + r + '</button>';
      }).join('')
      + '<span class="readout"' + (o.readoutId ? ' id="' + esc(o.readoutId) + '"' : '') + '>-- ' + esc(o.unit || '') + '</span>'
      + '</div>';
  }

  function consoleEl(o) {
    return '<div class="console' + (o.cls ? ' ' + o.cls : '') + '"' + (o.id ? ' id="' + esc(o.id) + '"' : '') + '></div>';
  }

  function logViewer(o) {
    return panel({
      title: 'Logs',
      head: '<span class="pspacer"></span><div class="filter-row">'
        + ['ALL', 'WARN', 'ERR'].map(function (lv, i) {
          return '<button class="chip' + (i === 0 ? ' active' : '') + '" data-level="' + lv + '">' + (lv === 'ALL' ? 'All' : lv === 'WARN' ? 'Warn' : 'Err') + '</button>';
        }).join('')
        + '<label class="toggle" style="margin-left:4px;"><input type="checkbox" id="' + esc(o.autoScrollId || 'logAutoScroll') + '" checked><span class="track"></span><span class="tsub">autoscroll</span></label>'
        + '<span class="logstats"' + (o.statsId ? ' id="' + esc(o.statsId) + '"' : '') + '>all:<b>0</b> warn:<span class="w">0</span> err:<span class="e">0</span></span>'
        + '</div>',
      body: consoleEl({ id: o.consoleId })
    });
  }

  function table(o) {
    var ths = (o.headers || []).map(function (h) {
      return '<th' + (h.sortable ? ' class="sortable" data-sort="' + esc(h.sort || h.label) + '"' : '') + (h.id ? ' id="' + esc(h.id) + '"' : '') + '>' + esc(h.label) + '</th>';
    }).join('');
    return '<div class="table-wrap"><table class="data"' + (o.id ? ' id="' + esc(o.id) + '"' : '') + '><thead><tr>' + ths + '</tr></thead><tbody></tbody></table></div>';
  }

  function routeCard(o) {
    return '<div class="route" id="route_' + o.idx + '">'
      + '<div class="route-head" data-rt="' + o.idx + '">'
      + '<span class="caret">&#9654;</span>'
      + '<span class="rname">' + esc(o.name) + '</span> ' + tag({ proto: o.proto })
      + '<span class="mono muted">' + esc(o.pub) + '</span>'
      + '<span class="rmeta">'
      + '<span>owner <span class="acc">' + esc(o.owner) + '</span></span>'
      + '<span>active <span class="mono">' + esc(o.active) + '</span></span>'
      + '<span class="rtoggle" data-rt="' + o.idx + '"><span class="badge ' + (o.on ? 'good' : 'neutral') + '" id="routeOn_' + o.idx + '">' + (o.on ? 'ON' : 'OFF') + '</span></span>'
      + '</span></div>'
      + '<div class="route-body"><div class="grid cols-2">'
      + '<div class="panel">' + panelHead({ title: 'Route Events' }) + '<div class="panel-body">' + consoleEl({ id: 'routeEvt_' + o.idx, cls: 'sm' }) + '</div></div>'
      + '<div class="panel">' + panelHead({ title: 'Packet Loss' }) + '<div class="panel-body">' + consoleEl({ id: 'routeLoss_' + o.idx, cls: 'sm' }) + '</div></div>'
      + '</div></div></div>';
  }

  function checkItem(o) {
    var statusLabel = o.status === 'ok' ? 'Pass' : o.status === 'warn' ? 'Needs attention' : 'Failed';
    var details = '';
    if (o.details && o.details.length) {
      details = '<div class="check-details"><div class="lbl">Found</div><ul>' + o.details.map(function (d) { return '<li><code>' + esc(d) + '</code></li>'; }).join('') + '</ul></div>';
    }
    var fix = o.fix ? '<div class="check-fix"><div class="lbl">Fix</div><code>' + esc(o.fix) + '</code></div>' : '';
    return '<div class="check-item">'
      + '<div class="check-top"><div><div class="check-name">' + esc(o.name) + '</div><div class="check-summ">' + esc(o.summary || '') + '</div></div>'
      + '<span class="check-status ' + o.status + '">' + statusLabel + '</span></div>'
      + details + fix + '</div>';
  }

  function tabBar(o) {
    return '<div class="topbar">'
      + '<div class="logo">HostIt <span class="sub">' + esc(o.role || '') + '</span></div>'
      + '<nav class="nav">' + (o.tabs || []).map(function (t) {
        return '<button class="tab' + (t.id === o.active ? ' active' : '') + '" data-tab="' + esc(t.id) + '" role="tab">' + esc(t.label) + '</button>';
      }).join('') + '</nav>'
      + '<div class="topbar-right">'
      + '<span class="online-dot"></span><span class="online-label">' + esc(o.online || 'ONLINE') + '</span>'
      + '<button class="theme-btn" id="themeBtn" aria-label="Toggle theme">' + esc(o.themeLabel || 'dark') + '</button>'
      + '<span class="ver">' + esc(o.version || 'v3.1.1') + '</span>'
      + (o.logout ? '<button class="theme-btn" id="logoutBtn">logout</button>' : '')
      + '</div></div>';
  }

  function tmuxBar(o) {
    return '<div class="statusbar">'
      + '<div class="sb-seg sb-l1">hostit</div>'
      + '<div class="sb-seg sb-l2"><span class="win-act" id="sbWin">' + esc(o.win || 'home') + '</span></div>'
      + '<div class="sb-right">'
      + '<div class="sb-seg sb-r1" id="sbAgent">' + esc(o.agent || '') + '</div>'
      + '<div class="sb-seg sb-r2">routes <span id="sbRoutes">' + esc(o.routes || '0') + '</span></div>'
      + '<div class="sb-seg sb-r3" id="sbClock">' + esc(o.clock || '') + '</div>'
      + '</div></div>';
  }

  function tip() { return '<div class="tip" id="tip"></div>'; }

  function updatePopup(o) {
    function v(s) { s = String(s || ''); return (s.charAt(0) === 'v' || s.charAt(0) === 'V') ? s.slice(1) : s; }
    return '<div class="up-head"><span class="ptitle">Update Available</span><button class="btn sm" id="updateClose">&times;</button></div>'
      + '<div class="up-body">'
      + '<div class="verline">v' + esc(v(o.current)) + ' &rarr; <b>v' + esc(v(o.available)) + '</b></div>'
      + '<div class="progress" id="updateProgress"></div>'
      + '<div class="ub-actions">'
      + '<button class="btn sm" id="updateLater">Remind later</button>'
      + '<button class="btn sm" id="updateSkip">Skip</button>'
      + '<button class="btn sm primary" id="updateDo">Update</button>'
      + '</div></div>';
  }

  function resultGrid(o) {
    return '<div class="result-grid">' + (o.items || []).map(function (r) {
      return '<div class="result"><div class="k">' + esc(r.label) + '</div><div class="v"' + (r.id ? ' id="' + esc(r.id) + '"' : '') + '>' + esc(r.value || '—') + '</div></div>';
    }).join('') + '</div>';
  }

  return {
    esc: esc,
    sectionHead: sectionHead,
    grid: grid,
    panel: panel,
    panelHead: panelHead,
    tile: tile,
    badge: badge,
    kv: kv,
    tag: tag,
    protoTag: protoTag,
    statusline: statusline,
    field: field,
    input: input,
    select: select,
    textarea: textarea,
    toggle: toggle,
    button: button,
    chart: chart,
    console: consoleEl,
    logViewer: logViewer,
    table: table,
    routeCard: routeCard,
    checkItem: checkItem,
    tabBar: tabBar,
    tmuxBar: tmuxBar,
    tip: tip,
    updatePopup: updatePopup,
    resultGrid: resultGrid
  };
})();
