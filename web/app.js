'use strict';
/* Binder Explorer front end. Talks to server.py; every number shown comes from the phone or the source tree. */

const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const fmtUs = (v) => (v == null ? '—' : v >= 1000 ? (v / 1000).toFixed(v >= 10000 ? 1 : 2) + ' ms' : v.toFixed(v < 10 ? 1 : 0) + ' µs');
const hex = (v, w = 8) => '0x' + (v >>> 0).toString(16).padStart(w, '0');

async function api(path, body) {
  const r = await fetch(path, body ? { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) } : {});
  const j = await r.json();
  if (!r.ok || j.error) throw new Error(j.error || r.statusText);
  return j;
}

const LAYER_COLOR = {
  app: 'var(--l-app)', manager: 'var(--l-app)', 'aidl-proxy': 'var(--l-gen)', 'aidl-stub': 'var(--l-gen)', 'hidl-proxy': 'var(--l-gen)',
  'hidl-stub': 'var(--l-gen)', java: 'var(--l-java)', jni: 'var(--l-jni)', libbinder: 'var(--l-native)', libhwbinder: 'var(--l-native)',
  'native-cli': 'var(--l-native)', svcmgr: 'var(--l-native)', syscall: 'var(--l-sys)', kernel: 'var(--l-kernel)', sched: 'var(--l-sched)',
  service: 'var(--l-svc)', hal: 'var(--l-svc)', vfs: 'var(--l-hw)', led: 'var(--l-hw)', hop: 'var(--muted)',
};
const LAYER_ROW = (l) => (['app', 'manager', 'aidl-proxy', 'aidl-stub', 'hidl-proxy', 'java', 'service'].includes(l) ? 0
  : ['jni', 'libbinder', 'libhwbinder', 'native-cli', 'svcmgr', 'hidl-stub', 'hal'].includes(l) ? 1 : 2);
const ROW_NAMES = ['Java (ART)', 'Native C++', 'Kernel, in this thread'];
const PROC_COLORS = ['var(--p0)', 'var(--p1)', 'var(--p2)', 'var(--p3)', 'var(--p4)'];
const STATE_COLOR = { running: 'var(--st-run)', runnable: 'var(--st-runnable)', sleeping: 'var(--st-sleep)', traced: 'var(--st-traced)', uninterruptible: 'var(--bad)' };

const S = { info: null, services: [], methods: null, kind: 'probe-app', views: {} };

// ---------------------------------------------------------------------------------------------
// tooltip + source viewer

const tip = $('#tip');
function showTip(e, text) { tip.textContent = text; tip.hidden = false; moveTip(e); }
function moveTip(e) {
  const w = tip.offsetWidth, hgt = tip.offsetHeight;
  tip.style.left = Math.min(window.innerWidth - w - 8, e.clientX + 14) + 'px';
  tip.style.top = Math.min(window.innerHeight - hgt - 8, e.clientY + 14) + 'px';
}
function hideTip() { tip.hidden = true; }

const KW = /\b(static|const|struct|return|if|else|for|while|switch|case|break|continue|goto|void|int|bool|boolean|char|long|unsigned|size_t|uint32_t|int32_t|uint64_t|status_t|public|private|protected|final|native|class|new|try|catch|finally|throw|throws|synchronized|virtual|override|true|false|null|NULL|sizeof|enum|typedef|default|do|import|package|extends|implements|this|super|auto|inline|template|typename|nullptr|instanceof)\b/g;
function hlLine(raw, state) {
  // tiny C/Java highlighter: comments, strings, numbers, keywords
  let out = '', s = raw;
  if (state.inComment) {
    const end = s.indexOf('*/');
    if (end < 0) return { html: '<span class="com">' + esc(s) + '</span>', state };
    out += '<span class="com">' + esc(s.slice(0, end + 2)) + '</span>';
    s = s.slice(end + 2);
    state.inComment = false;
  }
  const re = /(\/\/.*$)|(\/\*)|("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')/;
  while (s.length) {
    const m = re.exec(s);
    if (!m) { out += code(s); break; }
    out += code(s.slice(0, m.index));
    if (m[1]) { out += '<span class="com">' + esc(m[1]) + '</span>'; break; }
    if (m[2]) {
      const rest = s.slice(m.index);
      const end = rest.indexOf('*/', 2);
      if (end < 0) { out += '<span class="com">' + esc(rest) + '</span>'; state.inComment = true; break; }
      out += '<span class="com">' + esc(rest.slice(0, end + 2)) + '</span>';
      s = rest.slice(end + 2);
      continue;
    }
    out += '<span class="str">' + esc(m[3]) + '</span>';
    s = s.slice(m.index + m[3].length);
  }
  return { html: out, state };
  function code(t) {
    return esc(t).replace(KW, '<span class="kw">$1</span>').replace(/\b(0x[0-9a-fA-F]+|\d+)\b/g, '<span class="num">$1</span>');
  }
}
function codeBlock(lines, start, hl = [], focus) {
  const st = { inComment: false };
  return lines.map((l, i) => {
    const n = start + i;
    const r = hlLine(l, st);
    return `<span class="ln${hl.includes(n) || n === focus ? ' h' : ''}" data-n="${n}"><i>${n}</i>${r.html || ' '}</span>`;
  }).join('');
}
async function openSource(file, line) {
  const box = $('#srcview');
  $('#srcview-title').textContent = `${file}:${line}`;
  $('#srcview-body').innerHTML = '<span class="ln"><i></i>loading…</span>';
  box.hidden = false;
  try {
    const r = await api(`/api/source?file=${encodeURIComponent(file)}&line=${line}&ctx=120`);
    $('#srcview-body').innerHTML = codeBlock(r.lines, r.start, [], line);
    const t = $(`#srcview-body .ln[data-n="${line}"]`);
    if (t) t.scrollIntoView({ block: 'center' });
  } catch (e) { $('#srcview-body').textContent = e.message; }
}
$('#srcview-close').onclick = () => { $('#srcview').hidden = true; };
$('#srcview').onclick = (e) => { if (e.target.id === 'srcview') $('#srcview').hidden = true; };
document.addEventListener('click', (e) => {
  const a = e.target.closest('[data-src]');
  if (a) { const [f, l] = a.dataset.src.split('#'); openSource(f, +l); }
});

// ---------------------------------------------------------------------------------------------
// tabs

$$('.tabs button').forEach((b) => b.onclick = () => {
  $$('.tabs button').forEach((x) => x.classList.toggle('on', x === b));
  $$('.tab').forEach((t) => t.classList.toggle('on', t.id === 'tab-' + b.dataset.tab));
  if (b.dataset.tab === 'state' && !$('#state-result').innerHTML) loadStateQuick();
});

// ---------------------------------------------------------------------------------------------
// controls

const KIND_HINT = {
  'probe-app': 'Exactly what an app does: RgbLedManager → the generated AIDL proxy → BinderProxy → JNI → libbinder → kernel. Runs a tiny Java program on the phone through app_process.',
  'probe-aidl': 'Call any AIDL service through its generated Stub.Proxy from Java. Only methods with int/long/boolean/String parameters can be called.',
  native: 'Use /system/bin/service: a native C++ client with no Java and no JNI. It looks the service up itself, so you also see the servicemanager calls.',
  'probe-raw': 'Send any transaction code with a hand-built Parcel, including the special _PNG / _NTF / _TWT codes.',
};
const DEFAULTS = { channel: 0, brightness: 255, rgb: '0x00ff00', onMs: 300, offMs: 700, trigger: 'heartbeat' };

function svcOptions() {
  const sel = $('#svc');
  const cur = sel.value || 'rgbled';
  let list = S.services;
  if (S.kind === 'probe-app') list = list.filter((s) => s.name === 'rgbled');
  if (S.kind === 'probe-aidl') list = list.filter((s) => s.generated);
  sel.innerHTML = list.map((s) => `<option value="${esc(s.name)}">${esc(s.name)}${s.descriptor ? ' — ' + esc(s.descriptor.split('.').pop()) : ''}</option>`).join('');
  sel.value = list.some((s) => s.name === cur) ? cur : (list.find((s) => s.name === 'rgbled') || list[0] || {}).name;
}

async function loadMethods() {
  const svc = $('#svc').value;
  if (!svc) return;
  S.methods = await api('/api/methods?service=' + encodeURIComponent(svc));
  const ms = S.methods.methods.filter((m) => S.kind === 'native' || m.simple);
  $('#meth').innerHTML = ms.map((m) => `<option value="${esc(m.name)}" data-code="${m.code}">${m.code}: ${esc(m.name)}(${m.params.map((p) => p[0].replace('java.lang.', '') + ' ' + p[1]).join(', ')})</option>`).join('')
    || '<option value="">(no callable methods found in the generated code)</option>';
  if (ms.some((m) => m.name === 'getBrightness')) $('#meth').value = 'getBrightness';
  renderArgs();
}

function renderArgs() {
  const box = $('#args');
  if (S.kind === 'probe-raw') {
    box.innerHTML = `<label class="lbl" for="rawargs">Arguments</label><input id="rawargs" placeholder="e.g. i32:0 s16:hello" spellcheck="false">
      <p class="hint">Written after the interface token (only for normal codes 1…0xffffff). Types: i32:, i64:, s16:</p>`;
    return;
  }
  const m = (S.methods?.methods || []).find((x) => x.name === $('#meth').value);
  if (!m) { box.innerHTML = ''; return; }
  box.innerHTML = m.params.map((p, i) => {
    const t = p[0].replace('java.lang.', '');
    const def = DEFAULTS[p[1]] ?? (t === 'String' ? '' : 0);
    return `<div class="argrow"><span title="${esc(t)}">${esc(t)} ${esc(p[1])}</span><input data-type="${esc(t)}" data-i="${i}" value="${esc(def)}" spellcheck="false"></div>`;
  }).join('');
}

function argList() {
  if (S.kind === 'probe-raw') return ($('#rawargs')?.value || '').trim().split(/\s+/).filter(Boolean);
  return $$('#args input').map((inp) => {
    const t = inp.dataset.type;
    const v = inp.value.trim();
    if (t === 'String') return 's16:' + v;
    if (t === 'long') return 'i64:' + v;
    if (t === 'boolean') return 'i32:' + (/^(1|true)$/i.test(v) ? 1 : 0);
    return 'i32:' + v;
  });
}

function setKind(k) {
  S.kind = k;
  $$('#kind button').forEach((b) => b.classList.toggle('on', b.dataset.k === k));
  $('#kind-hint').textContent = KIND_HINT[k];
  $('#method-row').hidden = k === 'probe-raw';
  $('#code-row').hidden = k !== 'probe-raw';
  svcOptions();
  return loadMethods().catch(showErr);
}
$$('#kind button').forEach((b) => b.onclick = () => setKind(b.dataset.k));
$('#svc').onchange = () => loadMethods().catch(showErr);
$('#meth').onchange = renderArgs;

function showErr(e) { const st = $('#run-status'); st.className = 'status err'; st.textContent = e.message || e; }

$('#run').onclick = async () => {
  const btn = $('#run'), st = $('#run-status');
  const req = {
    kind: S.kind, service: $('#svc').value, method: $('#meth').value, args: argList(),
    lookup: $('#opt-lookup').checked, strace: $('#opt-strace').checked, syscalls: $('#opt-sys').checked,
  };
  if (S.kind === 'native') req.code = +$('#meth').selectedOptions[0]?.dataset.code;
  if (S.kind === 'probe-raw') req.code = $('#code').value.trim();
  btn.disabled = true;
  st.className = 'status';
  st.innerHTML = '<span class="spinner"></span>Tracing on the phone… (enabling tracepoints, running the call, collecting the trace)';
  const t0 = performance.now();
  try {
    const res = await api('/api/run', req);
    st.textContent = `Captured ${res.capture.events} kernel events in ${((performance.now() - t0) / 1000).toFixed(1)} s.`;
    renderSummary(res);
    renderResult(res, $('#trace-result'), 'trace');
  } catch (e) { showErr(e); } finally { btn.disabled = false; }
};

function renderSummary(res) {
  const flows = res.flows.filter((f) => !f.reply);
  const procs = [...new Set(res.lanes.map((l) => l.proc))];
  const result = res.probe?.result ?? (res.native_out || '').trim();
  const bytes = res.txns.reduce((a, t) => a + (t.data_size || 0), 0);
  $('#summary').innerHTML = `<div class="sum">
    <div class="wide"><span>result</span><b>${esc(result || '—')}</b></div>
    <div><span>end to end</span><b>${fmtUs(res.span[1])}</b></div>
    <div><span>transactions</span><b>${res.txns.length}</b></div>
    <div><span>processes</span><b>${procs.length}</b></div>
    <div><span>bytes copied</span><b>${bytes}</b></div>
    <div class="wide"><span>path</span><div style="font-size:12px">${procs.map(esc).join(' → ')}</div></div></div>`;
}

// ---------------------------------------------------------------------------------------------
// result view (shared by "trace a call" and "record the app")

function renderResult(res, host, key) {
  const pids = [...new Set(res.lanes.map((l) => l.pid))];
  const color = (pid) => PROC_COLORS[Math.max(0, pids.indexOf(pid)) % PROC_COLORS.length];
  const V = S.views[key] = { res, sel: 0, color, pids, x0: res.span[0], x1: res.span[1], playing: null };
  host.innerHTML = `
    <div class="card map"><div class="sect-h"><h3>Where the call is right now</h3><span class="muted">columns are processes; rows are the layers inside each one. The kernel row runs <b>in the calling thread's context</b>.</span></div><div class="mapbox"></div></div>
    <div class="card"><div class="sect-h"><h3>Timeline</h3><span class="muted">from sched_switch / sched_wakeup / raw_syscalls / binder tracepoints. Scroll to zoom, drag to pan.</span><span class="spacer"></span>
      <button data-z="fit">Fit</button><button data-z="step">Zoom to step</button></div>
      <div class="tl"></div>
      <div class="legend"><span><i style="background:var(--st-run)"></i>running</span><span><i style="background:var(--st-runnable)"></i>runnable (woken / preempted, waiting for a CPU)</span>
      <span><i style="background:var(--st-sleep)"></i>sleeping</span><span><i style="background:var(--st-traced)"></i>stopped by strace</span>
      <span><i style="background:var(--l-java)"></i>trace_marker slice (Java layer)</span><span><i style="background:var(--l-sys)"></i>system call</span>
      <span><i style="background:var(--accent)"></i>request</span><span><i style="background:var(--ok)"></i>reply</span></div></div>
    <div class="journey">
      <div class="card steps"></div>
      <div class="card detail"></div>
    </div>
    <details class="card"><summary><b>Raw evidence</b> <span class="muted">— every trace line for the involved threads, strace, and the probe's output</span></summary>
      <div class="blk"><div class="bh">ftrace (${res.raw.length} lines)</div><div class="ev" style="max-height:420px">${res.raw.map((r) => esc(r.line)).join('\n')}</div></div>
      ${res.strace ? `<div class="blk"><div class="bh">strace of the HAL</div><div class="ev">${esc(res.strace)}</div></div>` : ''}
      ${res.probe && res.probe.pid ? `<div class="blk"><div class="bh">probe output</div><div class="ev">${esc(JSON.stringify(res.probe, null, 1))}</div></div>` : ''}
      ${res.native_out ? `<div class="blk"><div class="bh">service call output</div><div class="ev">${esc(res.native_out)}</div></div>` : ''}
    </details>`;
  V.host = host;
  renderSteps(V);
  renderMap(V);
  renderTimeline(V);
  $$('[data-z]', host).forEach((b) => b.onclick = () => {
    if (b.dataset.z === 'fit') { V.x0 = res.span[0]; V.x1 = res.span[1]; } else zoomToStep(V);
    renderTimeline(V);
  });
  const want = HP.get('s');
  const wi = want ? res.steps.findIndex((x) => x.n === +want || (want === 'hal' && x.layer === 'hal') || (want === 'led' && x.layer === 'led') || (want === 'sched' && x.layer === 'sched')) : -1;
  select(V, wi >= 0 ? wi : firstReal(res.steps));
  S.active = V;
}

function firstReal(steps) { return Math.max(0, steps.findIndex((s) => !s.divider)); }

function renderSteps(V) {
  const box = $('.steps', V.host);
  box.innerHTML = V.res.steps.map((s, i) => s.divider
    ? `<div class="divider" data-i="${i}">${esc(s.title)}</div>`
    : `<div class="step${s.lookup ? ' lookup' : ''}" data-i="${i}"><div class="n">${s.n}</div><div><div class="t">${esc(s.title)}</div>
        <div class="meta"><span class="pdot" style="background:${V.color(s.pid)}"></span>${esc(shortProc(s.proc || ''))}
        <span class="badge" style="background:${LAYER_COLOR[s.layer] || 'var(--muted)'}">${esc(s.layer_label)}</span>
        <span>${s.ts != null ? fmtUs(s.ts) : ''}</span></div></div></div>`).join('');
  box.onclick = (e) => { const d = e.target.closest('[data-i]'); if (d) select(V, +d.dataset.i, true); };
}

function select(V, i, user) {
  const steps = V.res.steps;
  i = Math.max(0, Math.min(steps.length - 1, i));
  if (steps[i].divider) i = Math.min(steps.length - 1, i + 1);
  V.sel = i;
  S.active = V;
  $$('.step, .divider', V.host).forEach((d) => d.classList.toggle('on', +d.dataset.i === i));
  const el = $(`.step[data-i="${i}"]`, V.host);
  const box = $('.steps', V.host);
  if (el && (el.offsetTop < box.scrollTop || el.offsetTop + el.offsetHeight > box.scrollTop + box.clientHeight)) {
    box.scrollTop = el.offsetTop - box.clientHeight / 3;   // scroll the list only, never the page
  }
  renderDetail(V);
  updateMap(V);
  const s = steps[i];
  if (s.ts != null && (s.ts < V.x0 || s.ts > V.x1)) zoomToStep(V);
  renderTimeline(V);
  if (user && V.playing) stopPlay(V);
}

function renderDetail(V) {
  const s = V.res.steps[V.sel];
  const box = $('.detail', V.host);
  const vals = s.values.length ? `<table class="kv">${s.values.map(([k, v]) => `<tr><td>${esc(k)}</td><td>${esc(v)}</td></tr>`).join('')}</table>` : '';
  const struct = s.struct ? `<div class="blk"><div class="bh">${esc(s.struct.name)}</div><table class="struct">
      ${s.struct.fields.map((f) => `<tr><td>+${f.off}</td><td>${f.len}B</td><td>${esc(f.name)}</td><td>${esc(f.value)}</td></tr>`).join('')}</table></div>` : '';
  const parcel = s.parcel ? parcelView(s.parcel) : '';
  const srcs = s.src.map((sn) => sn.missing
    ? `<div class="blk"><div class="srch"><span class="ttl">${esc(sn.title || '')}</span><span class="muted">${esc(sn.file)} — not found in the tree${sn.anchor ? ' (' + esc(sn.anchor) + ')' : ''}</span></div></div>`
    : `<div class="blk"><div class="srch">${sn.title ? `<span class="ttl">${esc(sn.title)}</span>` : ''}<span class="f" data-src="${esc(sn.file)}#${sn.anchor_line}">${esc(sn.file)}:${sn.anchor_line}</span>
        ${sn.truncated ? '<span class="muted">(excerpt, open the file for the rest)</span>' : ''}</div>
        <pre class="code">${codeBlock(sn.lines, sn.start, sn.hl)}</pre></div>`).join('');
  const ev = s.ev.length ? `<div class="blk"><div class="bh">Evidence from this capture</div><div class="ev">${s.ev.map(esc).join('\n')}</div></div>` : '';
  box.innerHTML = `<div class="head"><span class="badge" style="background:${LAYER_COLOR[s.layer] || 'var(--muted)'}">${esc(s.layer_label)}</span>
      <span class="pdot" style="background:${V.color(s.pid)}"></span><span class="muted">${esc(s.thread || '')} · ${esc(s.proc || '')} ${s.pid ? '(pid ' + s.pid + ')' : ''}</span>
      <span class="when">${s.ts != null ? 't = ' + fmtUs(s.ts) : 'no trace event of its own'}${s.lock_wait_us != null ? ' · lock wait ' + fmtUs(s.lock_wait_us) : ''}</span></div>
    <h3>${s.n}. ${esc(s.title)}</h3>
    <div class="what">${s.what}</div>
    ${vals}${struct}${parcel}${srcs}${ev}
    <div class="nav"><button data-nav="-1">← Previous</button><button data-nav="1">Next →</button><button data-nav="play">${V.playing ? 'Pause' : 'Play ▶'}</button>
      <span class="muted" style="align-self:center">step ${s.n} of ${V.res.steps.filter((x) => !x.divider).length}</span></div>`;
  $$('[data-nav]', box).forEach((b) => b.onclick = () => {
    if (b.dataset.nav === 'play') return V.playing ? stopPlay(V) : startPlay(V);
    step(V, +b.dataset.nav);
  });
  wireParcel(box);
}

function step(V, d) {
  let i = V.sel + d;
  while (V.res.steps[i] && V.res.steps[i].divider) i += d;
  if (V.res.steps[i]) select(V, i);
}
function startPlay(V) { V.playing = setInterval(() => { if (V.sel >= V.res.steps.length - 1) return stopPlay(V); step(V, 1); }, 1800); renderDetail(V); }
function stopPlay(V) { clearInterval(V.playing); V.playing = null; renderDetail(V); }

document.addEventListener('keydown', (e) => {
  const V = S.active;
  if (!V || /input|select|textarea/i.test(e.target.tagName) || !$('#srcview').hidden) return;
  if (e.key === 'j' || e.key === 'ArrowDown' || e.key === 'ArrowRight') { e.preventDefault(); step(V, 1); }
  if (e.key === 'k' || e.key === 'ArrowUp' || e.key === 'ArrowLeft') { e.preventDefault(); step(V, -1); }
  if (e.key === ' ') { e.preventDefault(); V.playing ? stopPlay(V) : startPlay(V); }
});

// ---- parcel bytes view

function parcelView(p) {
  const b = p.hex.match(/../g) || [];
  const owner = new Array(b.length).fill(-1);
  p.fields.forEach((f, fi) => { for (let k = f.off; k < f.off + f.len && k < b.length; k++) owner[k] = fi; });
  const rows = [];
  for (let r = 0; r < b.length; r += 16) {
    let cells = '';
    for (let k = r; k < Math.min(b.length, r + 16); k++) {
      const f = p.fields[owner[k]];
      cells += `<b class="k-${f ? f.kind : 'rest'}" data-f="${owner[k]}">${b[k]}</b>${(k + 1) % 4 === 0 ? ' ' : ''}`;
    }
    rows.push(`<div class="r"><span class="o">${r.toString(16).padStart(4, '0')}</span>${cells}</div>`);
  }
  const flds = p.fields.map((f, fi) => `<tr data-f="${fi}"><td>+${f.off}${f.len ? '…' + (f.off + f.len - 1) : ''}</td><td><span class="k-${f.kind}" style="padding:0 4px;border-radius:3px">${esc(f.label)}</span>${f.note ? `<div class="muted" style="font-size:11px">${esc(f.note)}</div>` : ''}</td><td class="v">${esc(f.value)}</td></tr>`).join('');
  return `<div class="blk parcel"><div class="bh">${esc(p.title)} · ${b.length} bytes</div>
    <div class="bytes"><div class="hex">${rows.join('')}</div><table class="flds">${flds}</table></div></div>`;
}
function wireParcel(box) {
  $$('.parcel', box).forEach((pc) => {
    const on = (fi) => {
      $$('[data-f]', pc).forEach((x) => x.classList.toggle('on', x.dataset.f === fi));
    };
    pc.onmouseover = (e) => { const t = e.target.closest('[data-f]'); if (t) on(t.dataset.f); };
    pc.onmouseleave = () => on(null);
  });
}

// ---- process / layer map

function renderMap(V) {
  const box = $('.mapbox', V.host);
  const lanesByPid = new Map();
  V.res.lanes.forEach((l) => { if (!lanesByPid.has(l.pid)) lanesByPid.set(l.pid, l); });
  const cols = [...lanesByPid.values()];
  const hasLed = V.res.steps.some((s) => s.layer === 'led');
  const W = 1000, colW = (W - 140) / Math.max(1, cols.length), rowH = 54, top = 46, H = top + rowH * 3 + (hasLed ? 64 : 18);
  let g = '';
  g += `<rect x="130" y="${top + rowH * 2 - 3}" width="${W - 136}" height="${rowH}" rx="8" fill="var(--l-kernel)" fill-opacity=".07" stroke="var(--l-kernel)" stroke-opacity=".35"/>`;
  g += `<text class="tiny" x="136" y="${top + rowH * 3 + 8}">one binder driver: /dev/binder, /dev/hwbinder and /dev/vndbinder are contexts of the same driver</text>`;
  ROW_NAMES.forEach((n, r) => { g += `<text class="small" x="8" y="${top + r * rowH + rowH / 2 + 2}">${n}</text>`; });
  cols.forEach((l, c) => {
    const x = 136 + c * colW;
    g += `<text x="${x + colW / 2 - 6}" y="18" text-anchor="middle" font-weight="700" font-size="13" fill="${V.color(l.pid)}">${esc(shortProc(l.proc))}</text>`;
    g += `<text class="tiny" x="${x + colW / 2 - 6}" y="34" text-anchor="middle">pid ${l.pid}</text>`;
    for (let r = 0; r < 3; r++) {
      g += `<rect class="cell" data-c="${c}" data-r="${r}" x="${x}" y="${top + r * rowH}" width="${colW - 12}" height="${rowH - 8}" rx="7"/>`;
    }
  });
  if (hasLed) {
    g += `<rect class="cell" data-c="hw" data-r="3" x="${W - 260}" y="${top + rowH * 3 + 4}" width="250" height="40" rx="7"/>`;
    g += `<text class="small" x="${W - 135}" y="${top + rowH * 3 + 28}" text-anchor="middle">PMI8994 PMIC · RGB LED (SPMI)</text>`;
  }
  g += '<g class="hops"></g>';
  g += `<circle class="dot" r="7" cx="0" cy="0" fill="var(--accent)" stroke="var(--panel)" stroke-width="2"/>`;
  g += '<text class="cell-label small" text-anchor="middle"></text>';
  box.innerHTML = `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Processes and layers involved in the call">${g}</svg>`;
  V.map = { hasLed, cols, colW, rowH, top, W, colIndex: new Map(cols.map((l, i) => [l.pid, i])) };
}

function updateMap(V) {
  const M = V.map; if (!M) return;
  const svg = $('.mapbox svg', V.host);
  const steps = V.res.steps;
  const s = steps[V.sel];
  const visited = new Set();
  steps.slice(0, V.sel + 1).forEach((x) => { if (!x.divider && x.pid != null) visited.add(cellKey(M, x)); });
  $$('.cell', svg).forEach((c) => {
    const key = c.dataset.c + ':' + c.dataset.r;
    const on = key === cellKey(M, s);
    c.classList.toggle('on', on);
    c.style.fill = on ? (LAYER_COLOR[s.layer] || 'var(--accent)') : visited.has(key) ? 'var(--panel2)' : '';
    c.style.fillOpacity = on ? 0.28 : '';
    c.style.stroke = on ? (LAYER_COLOR[s.layer] || 'var(--accent)') : visited.has(key) ? 'var(--muted)' : '';
  });
  const [c, r] = cellKey(M, s).split(':');
  const cell = $(`.cell[data-c="${c}"][data-r="${r}"]`, svg);
  if (cell) {
    const cx = +cell.getAttribute('x') + +cell.getAttribute('width') / 2, cy = +cell.getAttribute('y') + +cell.getAttribute('height') / 2;
    $('.dot', svg).style.transform = `translate(${cx}px, ${cy - 6}px)`;
    const lbl = $('.cell-label', svg);
    lbl.setAttribute('x', cx); lbl.setAttribute('y', c === 'hw' ? cy + 34 : cy + 14);
    lbl.textContent = s.layer_label;
  }
  // hops done so far
  const now = Math.max(-1, ...steps.slice(0, V.sel + 1).filter((x) => x.ts != null).map((x) => x.ts));
  const done = V.res.flows.filter((f) => f.t1 <= now + 0.01);
  $('.hops', svg).innerHTML = done.map((f) => {
    const a = M.colIndex.get(pidOfTid(V, f.from)), b = M.colIndex.get(pidOfTid(V, f.to));
    if (a == null || b == null || a === b) return '';
    const y = M.top + M.rowH * 2 + 16 + (f.reply ? 6 : 0);
    const x1 = 136 + a * M.colW + (M.colW - 12) / 2, x2 = 136 + b * M.colW + (M.colW - 12) / 2;
    return `<path class="hop" d="M${x1},${y} C${(x1 + x2) / 2},${y + (f.reply ? 18 : -18)} ${(x1 + x2) / 2},${y + (f.reply ? 18 : -18)} ${x2},${y}" stroke="${f.reply ? 'var(--ok)' : 'var(--accent)'}"/>
      ${f.reply ? '' : `<text class="tiny" x="${(x1 + x2) / 2}" y="${y + 26}" text-anchor="middle">code ${f.code} · ${f.size}B · /dev/${esc(f.dev)}</text>`}`;
  }).join('');
}
function cellKey(M, s) {
  if (s.layer === 'led' && M.hasLed) return 'hw:3';
  const c = M.colIndex.get(s.pid);
  return (c == null ? 0 : c) + ':' + LAYER_ROW(s.layer);
}
function pidOfTid(V, tid) { const l = V.res.lanes.find((x) => x.tid === tid); return l ? l.pid : tid; }
function shortProc(n) { n = String(n || ""); return n.replace("vendor.lineage.", "").replace("-service.bullhead", "").replace(" (app_process)", ""); }

// ---- timeline

function zoomToStep(V) {
  const s = V.res.steps[V.sel];
  if (s.ts == null) return;
  const span = Math.max(60, (V.x1 - V.x0) > 0 && (V.x1 - V.x0) < 800 ? V.x1 - V.x0 : 400);
  V.x0 = Math.max(V.res.span[0], s.ts - span / 2);
  V.x1 = V.x0 + span;
}

function renderTimeline(V) {
  const box = $('.tl', V.host);
  const W = Math.max(600, box.clientWidth || 900), LBL = 190, laneH = 74, top = 22;
  const lanes = V.res.lanes;
  const H = top + lanes.length * laneH + 6;
  const x = (t) => LBL + ((t - V.x0) / (V.x1 - V.x0)) * (W - LBL - 10);
  const vis = (a, b) => b >= V.x0 && a <= V.x1;
  let g = '<defs><marker id="ar" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" orient="auto"><path d="M0,0 L8,4 L0,8z" fill="var(--accent)"/></marker>' +
    '<marker id="arr" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" orient="auto"><path d="M0,0 L8,4 L0,8z" fill="var(--ok)"/></marker>' +
    `<clipPath id="clip-${V.host.id}"><rect x="${LBL}" y="0" width="${W - LBL}" height="${H}"/></clipPath></defs>`;
  // axis
  const span = V.x1 - V.x0, stepT = niceStep(span / 8);
  g += '<g class="axis">';
  for (let t = Math.ceil(V.x0 / stepT) * stepT; t <= V.x1; t += stepT) {
    g += `<line x1="${x(t)}" x2="${x(t)}" y1="${top - 4}" y2="${H}"/><text x="${x(t) + 3}" y="12">${fmtUs(t)}</text>`;
  }
  g += '</g>';
  const laneY = new Map();
  lanes.forEach((l, i) => {
    const y = top + i * laneH;
    laneY.set(l.tid, y);
    g += `<rect class="lane-bg${i % 2 ? ' alt' : ''}" x="0" y="${y}" width="${W}" height="${laneH}"/>`;
    g += `<rect x="0" y="${y}" width="4" height="${laneH}" fill="${V.color(l.pid)}"/>`;
    g += `<text class="lane-name" x="10" y="${y + 18}">${esc(l.thread)}</text>`;
    g += `<text class="lane-sub" x="10" y="${y + 33}">tid ${l.tid}</text>`;
    g += `<text class="lane-sub" x="10" y="${y + 47}">${esc(shortProc(l.proc)).slice(0, 26)}</text>`;
  });
  g += `<g clip-path="url(#clip-${V.host.id})">`;
  lanes.forEach((l) => {
    const y = laneY.get(l.tid);
    l.states.forEach((s) => {
      if (!vis(s.t0, s.t1)) return;
      g += `<rect x="${x(s.t0)}" y="${y + 6}" width="${Math.max(1, x(s.t1) - x(s.t0))}" height="12" fill="${STATE_COLOR[s.s] || 'var(--muted)'}"
        data-tip="${esc(`${s.s}  ${fmtUs(s.t0)} → ${fmtUs(s.t1)}  (${fmtUs(s.t1 - s.t0)})`)}"/>`;
    });
    l.locks.forEach((k) => {
      if (vis(k.t0, k.t1)) g += `<rect x="${x(k.t0)}" y="${y + 3}" width="${Math.max(2, x(k.t1) - x(k.t0))}" height="3" fill="var(--bad)" data-tip="${esc(`waiting for the global binder lock (${k.tag}) ${fmtUs(k.t1 - k.t0)}`)}"/>`;
    });
    l.markers.forEach((m) => {
      if (!vis(m.t0, m.t1)) return;
      const yy = y + 22 + Math.min(m.depth, 2) * 15;
      const w = Math.max(2, x(m.t1) - x(m.t0));
      g += `<g class="mk"><rect x="${x(m.t0)}" y="${yy}" width="${w}" height="13" rx="2" fill="var(--l-java)" data-tip="${esc(`${m.name}\n${fmtUs(m.t0)} → ${fmtUs(m.t1)} (${fmtUs(m.t1 - m.t0)})\ntrace_marker written by Java code`)}"/>`;
      if (w > 40) g += `<text x="${x(m.t0) + 3}" y="${yy + 10}">${esc(m.name.split('.').pop().slice(0, Math.floor(w / 6.5)))}</text>`;
      g += '</g>';
    });
    l.syscalls.forEach((s) => {
      if (!vis(s.t0, s.t1)) return;
      const w = Math.max(2, x(s.t1) - x(s.t0));
      g += `<rect x="${x(s.t0)}" y="${y + 62}" width="${w}" height="7" fill="${s.name === 'ioctl' ? 'var(--l-kernel)' : 'var(--l-sys)'}" fill-opacity=".8"
        data-tip="${esc(`${s.name}(${s.detail || s.args.join(', ')}) = ${s.ret}\n${fmtUs(s.t0)} → ${fmtUs(s.t1)} (${fmtUs(s.t1 - s.t0)})`)}"/>`;
    });
    l.binder.forEach((b) => {
      if (!vis(b.ts, b.ts)) return;
      const imp = /binder_(transaction|transaction_received|return|command)$/.test(b.ev);
      g += `<rect x="${x(b.ts) - (imp ? 1.5 : 0.5)}" y="${y + 56}" width="${imp ? 3 : 1}" height="5" fill="var(--l-kernel)" data-tip="${esc(`${b.ev}: ${b.body}\n${fmtUs(b.ts)}`)}"/>`;
    });
  });
  V.res.flows.forEach((f) => {
    if (!laneY.has(f.from) || !laneY.has(f.to) || !vis(f.t0, f.t1)) return;
    const y1 = laneY.get(f.from) + 12, y2 = laneY.get(f.to) + 12;
    const x1 = x(f.t0), x2 = Math.max(x(f.t1), x1 + 2);
    g += `<path class="flow" d="M${x1},${y1} C${x1 + 30},${y1} ${x2 - 30},${y2} ${x2},${y2}" stroke="${f.reply ? 'var(--ok)' : 'var(--accent)'}" marker-end="url(#${f.reply ? 'arr' : 'ar'})"
      data-flow="${f.id}" data-tip="${esc(`${f.reply ? 'reply' : 'transaction'} ${f.id} over /dev/${f.dev}\ncode ${f.code} · ${f.size} bytes\nsent ${fmtUs(f.t0)}, picked up ${fmtUs(f.t1)} (${fmtUs(f.t1 - f.t0)})`)}"/>`;
  });
  const s = V.res.steps[V.sel];
  if (s && s.ts != null && vis(s.ts, s.ts)) {
    g += `<line class="cursor" x1="${x(s.ts)}" x2="${x(s.ts)}" y1="${top - 6}" y2="${H}"/>`;
    const ly = laneY.get(s.tid);
    if (ly != null) g += `<circle cx="${x(s.ts)}" cy="${ly + 12}" r="5" fill="var(--accent)" stroke="var(--panel)" stroke-width="2"/>`;
  }
  g += '</g>';
  box.innerHTML = `<svg viewBox="0 0 ${W} ${H}" height="${H}">${g}</svg>`;
  const svg = $('svg', box);
  svg.onmousemove = (e) => { const t = e.target.closest('[data-tip]'); if (t) showTip(e, t.dataset.tip); else hideTip(); };
  svg.onmouseleave = hideTip;
  svg.onclick = (e) => {
    const f = e.target.closest('[data-flow]');
    if (!f) return;
    const id = +f.dataset.flow;
    const fl = V.res.flows.find((q) => q.id === id);
    const idx = V.res.steps.findIndex((st) => !st.divider && st.ts != null && st.ts >= fl.t1 - 0.01 && st.tid === fl.to);
    if (idx >= 0) select(V, idx, true);
  };
  svg.onwheel = (e) => {
    e.preventDefault();
    const r = svg.getBoundingClientRect();
    const px = (e.clientX - r.left) * (W / r.width);
    if (px < LBL) return;
    const t = V.x0 + ((px - LBL) / (W - LBL - 10)) * (V.x1 - V.x0);
    const k = e.deltaY > 0 ? 1.25 : 0.8;
    const n0 = t - (t - V.x0) * k, n1 = t + (V.x1 - t) * k;
    if (n1 - n0 < 4) return;
    V.x0 = Math.max(V.res.span[0] - 50, n0); V.x1 = Math.min(V.res.span[1] + 50, n1);
    renderTimeline(V);
  };
  svg.onmousedown = (e) => {
    const r = svg.getBoundingClientRect();
    const sx = e.clientX, a = V.x0, b = V.x1;
    svg.classList.add('drag');
    const mv = (ev) => {
      const d = ((ev.clientX - sx) * (W / r.width)) / (W - LBL - 10) * (b - a);
      V.x0 = a - d; V.x1 = b - d; renderTimeline(V);
    };
    const up = () => { window.removeEventListener('mousemove', mv); window.removeEventListener('mouseup', up); svg.classList.remove('drag'); };
    window.addEventListener('mousemove', mv); window.addEventListener('mouseup', up);
  };
}
function niceStep(v) {
  const p = Math.pow(10, Math.floor(Math.log10(Math.max(v, 1e-6))));
  const n = v / p;
  return (n < 1.5 ? 1 : n < 3.5 ? 2 : n < 7.5 ? 5 : 10) * p;
}
window.addEventListener('resize', () => { Object.values(S.views).forEach((V) => V.host && renderTimeline(V)); });

// ---------------------------------------------------------------------------------------------
// record the app

$('#rec-run').onclick = async () => {
  const btn = $('#rec-run'), st = $('#rec-status');
  const secs = Math.max(1, Math.min(20, +$('#rec-secs').value || 6));
  btn.disabled = true; st.className = 'status';
  let left = secs;
  st.innerHTML = `<span class="spinner"></span><b>Recording — use the app on the phone now.</b> ${left}s`;
  const timer = setInterval(() => { left--; if (left > 0) st.innerHTML = `<span class="spinner"></span><b>Recording — use the app on the phone now.</b> ${left}s`; else st.innerHTML = '<span class="spinner"></span>Collecting and analysing the trace…'; }, 1000);
  try {
    const r = await api('/api/record', { package: $('#rec-pkg').value.trim(), seconds: secs });
    clearInterval(timer);
    st.textContent = `${r.rows.length} transactions sent by ${r.package} (pid ${r.pid}) in ${r.seconds}s · ${r.events} kernel events.`;
    renderRecord(r);
  } catch (e) { clearInterval(timer); st.className = 'status err'; st.textContent = e.message; } finally { btn.disabled = false; }
};

function renderRecord(r) {
  const host = $('#rec-result');
  const dests = {};
  r.rows.forEach((x) => { dests[x.dest] = (dests[x.dest] || 0) + 1; });
  host.innerHTML = `<div class="card" style="margin-top:16px"><div class="sect-h"><h3>Transactions the app sent</h3><span class="muted">click one to see its full journey</span><span class="spacer"></span>
      <input id="rec-filter" placeholder="filter: dest, thread, code" style="width:240px"></div>
      <div class="chips">${Object.entries(dests).sort((a, b) => b[1] - a[1]).map(([d, n]) => `<button data-d="${esc(d)}">${esc(shortProc(d))} × ${n}</button>`).join('')}</div>
      <div class="scroll" style="margin-top:8px"><table class="tbl"><thead><tr><th>t (ms)</th><th>thread</th><th>to</th><th>code</th><th>bytes</th><th>round trip</th><th>hops</th><th>dev</th></tr></thead><tbody>
      ${r.rows.map((x) => `<tr class="click" data-id="${x.id}" data-s="${esc((x.dest + ' ' + x.thread + ' ' + x.code).toLowerCase())}"><td class="m">${x.t.toFixed(3)}</td><td>${esc(x.thread)}</td><td>${esc(shortProc(x.dest))}</td>
        <td class="m">${x.code > 0xffffff ? hex(x.code) : x.code}${x.oneway ? ' <span class="muted">oneway</span>' : ''}</td><td class="m">${x.size}</td><td class="m">${x.rtt_us != null ? fmtUs(x.rtt_us) : x.oneway ? '—' : '?'}</td><td class="m">${x.hops}</td><td class="m">${x.dev}</td></tr>`).join('')}
      </tbody></table></div>
      ${r.stacks.length ? `<details style="margin-top:10px"><summary><b>Java call sites</b> <span class="muted">(from am trace-ipc)</span></summary>
        <table class="tbl">${r.stacks.map((s) => `<tr><td class="m">${s.count}×</td><td class="m">${esc(s.call)}<div class="muted">${s.frames.slice(1, 6).map(esc).join('<br>')}</div></td></tr>`).join('')}</table></details>` : ''}
    </div>`;
  const filt = () => {
    const q = $('#rec-filter').value.toLowerCase();
    $$('tbody tr', host).forEach((tr) => { tr.hidden = q && !tr.dataset.s.includes(q); });
  };
  $('#rec-filter').oninput = filt;
  $$('.chips button', host).forEach((b) => b.onclick = () => { $('#rec-filter').value = b.dataset.d.toLowerCase(); filt(); });
  if (HP.get('recpick')) setTimeout(() => {
    const tr = $$('tbody tr', host).find((x) => x.dataset.s.includes(HP.get('recpick')));
    if (tr) tr.click();
  }, 200);
  $('tbody', host).onclick = async (e) => {
    const tr = e.target.closest('tr[data-id]');
    if (!tr) return;
    $$('tbody tr', host).forEach((x) => x.classList.toggle('sel', x === tr));
    const jh = $('#rec-journey');
    jh.innerHTML = '<div class="card"><span class="spinner"></span>Building the journey…</div>';
    try {
      const res = await api('/api/record/txn?id=' + tr.dataset.id);
      renderResult(res, jh, 'record');
      jh.scrollIntoView({ behavior: 'smooth' });
    } catch (err) { jh.innerHTML = `<div class="card status err">${esc(err.message)}</div>`; }
  };
}

// ---------------------------------------------------------------------------------------------
// protocol

function renderProtocol(info) {
  const P = info.protocol;
  const link = (file, line, text) => `<span class="f mono" style="color:var(--accent);cursor:pointer;text-decoration:underline dotted" data-src="${esc(file)}#${line}">${esc(text || file + ':' + line)}</span>`;
  const cmdRows = (list) => list.map((c) => `<tr><td class="m">${esc(c.name)}</td><td class="m">${hex(c.value)}</td><td class="m">${esc(c.payload || '—')}</td><td class="m">${c.size || 0}</td>
     <td>${esc(c.doc.join(' '))}</td><td>${link(P.file, c.line, ':' + c.line)}</td></tr>`).join('');
  const hal = info.hal, aidl = info.aidl;
  const spec = info.special;
  $('#proto').innerHTML = `<div class="stack">
  <div class="card"><h2>Where is the binder "protocol" defined?</h2>
    <p>It is three protocols stacked on top of each other. Only the bottom one is known to the kernel.</p>
    <div class="grid3" style="margin-top:12px">
      <div class="card layer-card" style="border-top-color:var(--l-kernel)"><h3>1 · Kernel ABI</h3>
        <p>One ioctl, <code>BINDER_WRITE_READ</code>, carries a stream of <b>BC_*</b> commands into the driver and gets a stream of <b>BR_*</b> returns back. A transaction is <code>BC_TRANSACTION</code> + a <code>binder_transaction_data</code> that points at a buffer (the Parcel) and at an offsets array that marks binder objects inside it.</p>
        <p>The kernel treats the <b>code</b> and the bytes as opaque. It only parses the objects listed in the offsets (to translate handles and fds).</p>
        <p>${link(P.file, 1, P.file)}<br>${link(info.paths['binder.c'], 1, info.paths['binder.c'])}<br><span class="muted">userspace copy: bionic/libc/kernel/uapi/linux/android/binder.h</span></p></div>
      <div class="card layer-card" style="border-top-color:var(--l-native)"><h3>2 · libbinder conventions</h3>
        <p>Userspace agrees on how to use the codes and bytes: codes <code>1…0x00ffffff</code> are interface methods, letter-codes like <code>_PNG</code> are understood by every object, and a Parcel starts with an interface token. Parcel layout: 4-byte aligned little-endian values, String16 = length + UTF-16 + NUL + padding.</p>
        <p>${link(info.paths['IBinder.h'], 57, 'IBinder.h')} · ${link(info.paths['Parcel.cpp'], 600, 'Parcel.cpp')} · ${link(info.paths['IPCThreadState'], 559, 'IPCThreadState.cpp')}<br>
        hwbinder: ${link(info.paths['hidl_Interface.cpp'], 56, 'hidl Interface.cpp')} · ${link(info.paths['hw_IPCThreadState'], 562, 'libhwbinder IPCThreadState.cpp')}</p></div>
      <div class="card layer-card" style="border-top-color:var(--l-gen)"><h3>3 · Interface contract</h3>
        <p>Each interface defines what its codes mean. The <b>AIDL</b> compiler numbers methods 1, 2, 3… in file order and generates a Proxy (writes args) and a Stub (reads them in the same order). <b>HIDL</b> does the same for HALs.</p>
        <p>${link(info.paths['IRgbLedService.aidl'], 1, 'IRgbLedService.aidl')} → ${link(info.paths['IRgbLedService.gen'], 1, 'generated IRgbLedService.java')}<br>
        ${link(info.paths['IRgbLed.hal'], 1, 'IRgbLed.hal')} → ${link(info.paths['IRgbLed.gen'], 1, 'generated IRgbLed.java')} / ${link(info.paths['RgbLedAll.cpp'], 1, 'RgbLedAll.cpp')}</p></div>
    </div></div>

  <div class="card"><h2>Decode any binder number</h2>
    <p>Paste a value from a trace (a BC/BR command, an ioctl, a transaction code). Decimal or hex.</p>
    <input id="dec-in" value="0x40406300" spellcheck="false" style="max-width:320px">
    <div id="dec-out"></div></div>

  <div class="card"><h2>Transaction code space</h2>
    <div class="bits" style="margin-top:4px">
      <div style="flex:2;background:var(--l-gen)">0x00000001 … 0x00ffffff<br>interface methods (AIDL/HIDL numbering)</div>
      <div style="flex:1.4;background:var(--l-svc)">0x0f000000 … 0x0fffffff<br>reserved for HIDL</div>
      <div style="flex:1.4;background:var(--l-native)">0x5f______ ('_' + 3 letters)<br>special codes</div></div>
    <table class="tbl" style="margin-top:12px"><thead><tr><th>name</th><th>letters</th><th>hex</th><th>decimal (for service call)</th><th>kind</th><th>defined at</th><th></th></tr></thead><tbody>
    ${spec.map((c) => `<tr><td class="m">${esc(c.name)}</td><td class="m">${esc(c.chars)}</td><td class="m">${hex(c.value)}</td><td class="m">${c.value}</td><td>${esc(c.kind)}</td><td>${link(c.file, c.line, c.file.split('/').pop() + ':' + c.line)}</td>
      <td>${c.kind.startsWith('binder') ? `<button class="tryc" data-code="${c.value}">try on rgbled</button>` : ''}</td></tr>`).join('')}</tbody></table></div>

  <div class="card"><h2>Interface numbering on this device</h2><div class="grid3">
    <div><h3>android.hardware.rgbled.IRgbLedService <span class="muted">(binder, AIDL)</span></h3>
      <table class="tbl"><thead><tr><th>code</th><th>method</th><th>try it</th></tr></thead><tbody>${aidl.map((m) => `<tr><td class="m">${m.code}</td><td class="m">${esc(m.ret)} ${esc(m.name)}(${m.params.map((p) => p.join(' ')).join(', ')})</td>
      <td class="m">service call rgbled ${m.code}${m.params.map((p) => p[0] === 'String' ? ' s16 …' : ' i32 …').join('')}</td></tr>`).join('')}</tbody></table></div>
    <div><h3>vendor.lineage.rgbled@1.0::IRgbLed <span class="muted">(hwbinder, HIDL)</span></h3>
      <table class="tbl"><thead><tr><th>code</th><th>method</th><th>generates</th></tr></thead><tbody>${hal.map((m) => `<tr><td class="m">${m.code}</td><td class="m">${esc(m.name)}(${esc(m.args)})</td><td class="m">${esc(m.gen)}</td></tr>`).join('')}</tbody></table></div>
  </div></div>

  <div class="card"><h2>ioctls on /dev/binder</h2><table class="tbl"><thead><tr><th>name</th><th>value</th><th>argument</th><th>line</th></tr></thead><tbody>
    ${P.ioctls.map((c) => `<tr><td class="m">${esc(c.name)}</td><td class="m">${hex(c.value)}</td><td class="m">${esc(c.payload)}</td><td>${link(P.file, c.line, ':' + c.line)}</td></tr>`).join('')}</tbody></table></div>

  <div class="card"><h2>BC_* commands (userspace → driver)</h2><div class="scroll"><table class="tbl"><thead><tr><th>command</th><th>value</th><th>payload</th><th>bytes</th><th>meaning (header comment)</th><th></th></tr></thead><tbody>${cmdRows(P.commands)}</tbody></table></div></div>
  <div class="card"><h2>BR_* returns (driver → userspace)</h2><div class="scroll"><table class="tbl"><thead><tr><th>return</th><th>value</th><th>payload</th><th>bytes</th><th>meaning (header comment)</th><th></th></tr></thead><tbody>${cmdRows(P.returns)}</tbody></table></div></div>

  <div class="card"><h2>Structures that cross the boundary</h2><div class="grid3">
    ${P.structs.map((s) => `<div><div class="srch"><span class="ttl">struct ${esc(s.name)}</span>${link(P.file, s.line, ':' + s.line)}</div><pre class="code">${codeBlock(s.lines, s.line)}</pre></div>`).join('')}
  </div></div>
  </div>`;
  const dec = () => $('#dec-out').innerHTML = decode($('#dec-in').value, info);
  $('#dec-in').oninput = dec; dec();
  $$('.tryc').forEach((b) => b.onclick = () => {
    $$('.tabs button')[0].click(); setKind('probe-raw');
    setTimeout(() => { $('#code').value = b.dataset.code; $('#svc').value = 'rgbled'; }, 300);
  });
}

function decode(txt, info) {
  const v = Number(txt.trim().toLowerCase().startsWith('0x') ? parseInt(txt.trim(), 16) : parseInt(txt.trim(), 10));
  if (!Number.isFinite(v)) return '<p class="muted">Not a number.</p>';
  const u = v >>> 0;
  const dir = u >>> 30, size = (u >>> 16) & 0x3fff, type = (u >>> 8) & 0xff, nr = u & 0xff;
  const P = info.protocol;
  const all = [...P.commands.map((c) => ['BC command', c]), ...P.returns.map((c) => ['BR return', c]), ...P.ioctls.map((c) => ['ioctl', c])];
  const hits = all.filter(([, c]) => c.value >>> 0 === u).map(([k, c]) => `<b>${esc(c.name)}</b> <span class="muted">(${k}${c.payload ? ', payload ' + esc(c.payload) : ''})</span>`);
  info.special.filter((c) => c.value === u).forEach((c) => hits.push(`<b>${esc(c.name)}</b> <span class="muted">(${esc(c.kind)} special transaction code "${esc(c.chars)}")</span>`));
  if (u >= 1 && u <= 0xffffff) {
    const a = info.aidl.find((m) => m.code === u), h = info.hal.find((m) => m.code === u);
    hits.push(`a <b>method code</b>: FIRST_CALL_TRANSACTION + ${u - 1}${a ? ` → IRgbLedService.<b>${esc(a.name)}</b>` : ''}${h ? `, or IRgbLed (HAL).<b>${esc(h.name)}</b>` : ''}`);
  }
  const ch = (c) => (c >= 32 && c < 127 ? String.fromCharCode(c) : '·');
  const letters = [u >>> 24, (u >>> 16) & 255, (u >>> 8) & 255, u & 255].map(ch).join('');
  return `<p style="margin-top:10px">${hits.length ? hits.join('<br>') : '<span class="muted">No exact match in this device\'s binder.h.</span>'}</p>
   <p class="muted">As an _IOC encoding (how every BC/BR/ioctl value is built: <code>dir&lt;&lt;30 | size&lt;&lt;16 | type&lt;&lt;8 | nr</code>). As 4 ASCII bytes: <code>${esc(letters)}</code>.</p>
   <div class="bits"><div style="flex:2;background:var(--l-kernel)">dir ${['none', 'W', 'R', 'RW'][dir]} (2 bits)</div><div style="flex:6;background:var(--l-native)">size ${size} bytes (14 bits)</div>
     <div style="flex:4;background:var(--l-gen)">type '${ch(type)}' 0x${type.toString(16)} (8 bits)</div><div style="flex:4;background:var(--l-svc)">nr ${nr} (8 bits)</div></div>`;
}

// ---------------------------------------------------------------------------------------------
// live state

const LOOPER = [[0x01, 'REGISTERED'], [0x02, 'ENTERED'], [0x04, 'EXITED'], [0x08, 'INVALID'], [0x10, 'WAITING'], [0x20, 'NEED_RETURN']];
async function loadStateQuick() {
  try {
    const ps = await api('/api/procs');
    S.procs = ps;
    $('#proc-list').innerHTML = ps.map((p) => `<option value="${p.pid}">${esc(p.name)}</option>`).join('');
    const want = ['com.example.rgbleddemo', 'system_server', 'vendor.lineage.rgbled@1.0-service.bullhead', 'servicemanager', 'hwservicemanager', 'surfaceflinger'];
    $('#state-quick').innerHTML = want.map((n) => ps.find((p) => p.name === n)).filter(Boolean)
      .map((p) => `<button data-pid="${p.pid}">${esc(shortProc(p.name))} · ${p.pid}</button>`).join('');
    $$('#state-quick button').forEach((b) => b.onclick = () => showState(+b.dataset.pid));
  } catch (e) { $('#state-result').innerHTML = `<div class="card status err">${esc(e.message)}</div>`; }
}
$('#state-go').onclick = () => {
  const v = $('#state-pid').value.trim();
  const p = /^\d+$/.test(v) ? +v : (S.procs || []).find((x) => x.name.includes(v))?.pid;
  if (p) showState(p);
};
async function showState(pid) {
  const host = $('#state-result');
  host.innerHTML = '<div class="card"><span class="spinner"></span>Reading debugfs…</div>';
  try {
    const r = await api('/api/state?pid=' + pid);
    const ctxs = Object.entries(r.contexts);
    host.innerHTML = `<div class="card" style="margin-top:14px"><h2>${esc(r.name)} <span class="muted">pid ${r.pid}</span></h2>
      <p>Binder mappings: ${r.maps.map((m) => `<code>${esc(m.split(/\s+/)[0])} ${esc(m.split(/\s+/).pop())}</code>`).join(' ') || '<span class="muted">none</span>'}</p></div>
      ${ctxs.map(([name, c]) => `<div class="state-grid">
        <div class="card"><h3>/dev/${esc(name)} · threads (${c.threads.length})</h3><p class="muted">Looper flags from binder.c: ENTERED = a pool thread started by the process, REGISTERED = spawned on request of the driver, WAITING = blocked in binder_thread_read().</p>
          <div class="scroll"><table class="tbl"><thead><tr><th>tid</th><th>name</th><th>looper</th><th>kernel wait</th></tr></thead><tbody>
          ${c.threads.map((t) => { const f = parseInt(t.looper, 16); return `<tr><td class="m">${t.tid}</td><td>${esc(t.comm || '')}</td><td class="m">${t.looper} ${LOOPER.filter(([b]) => f & b).map(([, n]) => n).join('|') || '<span class="muted">not a looper</span>'}</td><td class="m">${esc(t.wchan || '')}</td></tr>`; }).join('')}</tbody></table></div></div>
        <div class="card"><h3>/dev/${esc(name)} · handles this process holds (${c.refs.length})</h3><p class="muted">"desc" is the handle number this process uses; it points at a node owned by another process.</p>
          <div class="scroll"><table class="tbl"><thead><tr><th>handle</th><th>node</th><th>owner</th><th>strong/weak</th></tr></thead><tbody>
          ${c.refs.map((x) => `<tr><td class="m">${x.desc}</td><td class="m">${x.node}${x.dead ? ' <span class="muted">dead</span>' : ''}</td><td>${esc(shortProc(x.owner_name))} <span class="muted">${x.owner ?? ''}</span></td><td class="m">${x.strong}/${x.weak}</td></tr>`).join('')}</tbody></table></div></div>
        <div class="card"><h3>/dev/${esc(name)} · objects this process hosts (${c.nodes.length})</h3><p class="muted">Each node is a local Binder object; ptr/cookie are its addresses in this process. "held by" lists processes with a handle to it.</p>
          <div class="scroll"><table class="tbl"><thead><tr><th>node</th><th>ptr / cookie</th><th>held by</th></tr></thead><tbody>
          ${c.nodes.map((n) => `<tr><td class="m">${n.id}</td><td class="m">${n.ptr}<br>${n.cookie}</td><td>${n.held_by_names.map(esc).join(', ')}</td></tr>`).join('')}</tbody></table></div></div>
        ${c.buffers.length || (c.transactions || []).length ? `<div class="card"><h3>/dev/${esc(name)} · buffers and transactions in flight</h3><div class="ev">${c.buffers.map((b) => `buffer ${b.id}: ${b.data_size}+${b.offsets_size} bytes ${b.state}`).concat(c.transactions || []).map(esc).join('\n')}</div></div>` : ''}
      </div>`).join('')}
      <details class="card" style="margin-top:14px"><summary>raw debugfs</summary><div class="ev">${esc(r.raw)}</div></details>`;
  } catch (e) { host.innerHTML = `<div class="card status err">${esc(e.message)}</div>`; }
}

// ---------------------------------------------------------------------------------------------
// boot

// Deep links, e.g. #kind=native&meth=setChannel&args=1,255&lookup=1&run&s=5 or #tab=state&pid=791
const HP = new URLSearchParams(location.hash.slice(1));
async function applyHash() {
  if (HP.get('theme')) document.documentElement.dataset.theme = HP.get('theme');
  if (HP.get('kind')) await setKind(HP.get('kind'));
  if (HP.get('svc')) { $('#svc').value = HP.get('svc'); await loadMethods(); }
  if (HP.get('meth')) { $('#meth').value = HP.get('meth'); renderArgs(); }
  if (HP.get('args')) {
    const a = HP.get('args').split(',');
    if (S.kind === 'probe-raw') $('#rawargs').value = a.join(' ');
    else $$('#args input').forEach((inp, i) => { if (a[i] != null) inp.value = a[i]; });
  }
  if (HP.get('code')) $('#code').value = HP.get('code');
  if (HP.has('lookup')) $('#opt-lookup').checked = true;
  if (HP.has('strace')) $('#opt-strace').checked = true;
  if (HP.get('tab')) $(`.tabs button[data-tab="${HP.get('tab')}"]`)?.click();
  if (HP.get('pid')) setTimeout(() => showState(+HP.get('pid')), 300);
  if (HP.get('secs')) $('#rec-secs').value = HP.get('secs');
  if (HP.has('rec')) setTimeout(() => $('#rec-run').click(), 300);
  if (HP.has('run')) setTimeout(() => $('#run').click(), 300);
}

(async function init() {
  try {
    const info = await api('/api/info');
    S.info = info;
    const d = info.device;
    $('#device').innerHTML = `${esc(d.model)} · Android ${esc(d.android)} · ${esc(d.kernel)}<br>${d.root ? 'root' : 'NOT root'} · servicemanager ${d.servicemanager} · system_server ${d.system_server} · LED HAL ${d.hal}`;
    renderProtocol(info);
    S.services = await api('/api/services');
    await setKind('probe-app');
    const chips = info.special.filter((c) => c.kind.startsWith('binder'));
    $('#code-chips').innerHTML = chips.map((c) => `<button data-v="${c.value}" title="${esc(c.name)}">${esc(c.chars)}</button>`).join('') + '<button data-v="8">8 getBrightness</button>';
    $$('#code-chips button').forEach((b) => b.onclick = () => { $('#code').value = b.dataset.v; });
    await applyHash();
  } catch (e) {
    $('#device').textContent = 'not connected';
    showErr(e);
  }
})();
