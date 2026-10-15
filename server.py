#!/usr/bin/env python3
"""Binder Explorer: a local web UI that traces real binder calls on a connected phone.

    python3 server.py            # then open http://127.0.0.1:8765

Needs: adb with a rooted (adb root / Rooted debugging) device, the LineageOS tree
at $LINEAGE_ROOT (default ~/Desktop/android/lineage) for source excerpts.
"""
import json
import os
import re
import shlex
import subprocess
import sys
import threading
import time
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from bx import trace, source, journey  # noqa: E402

PORT = int(os.environ.get('BX_PORT', '8765'))
DEV = '/data/local/tmp/bx'
HAL_NAME = 'vendor.lineage.rgbled@1.0-service.bullhead'
LOCK = threading.Lock()
LAST = {}


# ---- adb -------------------------------------------------------------------------------------

def adb(*args, timeout=60, text=True):
    cmd = ['adb'] + list(args)
    r = subprocess.run(cmd, capture_output=True, timeout=timeout)
    out = r.stdout.decode(errors='replace') if text else r.stdout
    return out


def sh(script, timeout=60):
    return adb('shell', script, timeout=timeout)


def push_tools():
    sh('mkdir -p %s' % DEV)
    for local, remote in (('probe/probe.dex', DEV + '/probe.dex'), ('device/capture.sh', DEV + '/capture.sh')):
        adb('push', os.path.join(HERE, local), remote)


def pidof(name):
    out = sh('pidof %s' % name).strip()
    return int(out.split()[0]) if out else None


# ---- debugfs ---------------------------------------------------------------------------------

def parse_debugfs(text):
    """/sys/kernel/debug/binder/proc/<pid> → {context: {threads, nodes, refs, buffers}}."""
    out, cur = {}, None
    for l in text.splitlines():
        s = l.strip()
        if s.startswith('context '):
            cur = out.setdefault(s.split()[1], {'threads': [], 'nodes': {}, 'refs': [], 'buffers': []})
            continue
        if cur is None:
            continue
        m = re.match(r'thread (\d+): l (\w+)(.*)', s)
        if m:
            cur['threads'].append({'tid': int(m.group(1)), 'looper': m.group(2), 'rest': m.group(3).strip()})
            continue
        m = re.match(r'node (\d+): u([0-9a-f]+) c([0-9a-f]+) hs (\d+) hw (\d+) ls (\d+) lw (\d+) is (\d+) iw (\d+)(?: proc (.*))?', s)
        if m:
            cur['nodes'][int(m.group(1))] = {'id': int(m.group(1)), 'ptr': '0x' + m.group(2).lstrip('0').rjust(1, '0'),
                                             'cookie': '0x' + m.group(3).lstrip('0').rjust(1, '0'),
                                             'strong_refs': int(m.group(8)),
                                             'held_by': [int(x) for x in (m.group(10) or '').split()]}
            continue
        m = re.match(r'ref (\d+): desc (\d+) (dead )?node (\d+) s (\d+) w (\d+)', s)
        if m:
            cur['refs'].append({'id': int(m.group(1)), 'desc': int(m.group(2)), 'dead': bool(m.group(3)),
                                'node': int(m.group(4)), 'strong': int(m.group(5)), 'weak': int(m.group(6))})
            continue
        m = re.match(r'buffer (\d+): \S+ size (\d+):(\d+)(?::(\d+))? (.*)', s)
        if m:
            cur['buffers'].append({'id': int(m.group(1)), 'data_size': int(m.group(2)), 'offsets_size': int(m.group(3)),
                                   'state': m.group(5)})
            continue
        if s.startswith(('incoming transaction', 'outgoing transaction', 'pending transaction')):
            cur.setdefault('transactions', []).append(s)
    return out


def node_owners():
    """node debug id → owner pid, per context, from the global state file."""
    text = sh('cat /sys/kernel/debug/binder/state', timeout=30)
    owners, pid, ctx = {}, None, None
    for l in text.splitlines():
        s = l.strip()
        m = re.match(r'proc (\d+)$', s)
        if m:
            pid = int(m.group(1))
            continue
        if s.startswith('context '):
            ctx = s.split()[1]
            continue
        m = re.match(r'node (\d+):', s)
        if m and pid:
            owners[(ctx, int(m.group(1)))] = pid
    return owners


# ---- metadata after a capture ----------------------------------------------------------------

def collect_meta(model, extra_pids=()):
    tids = set()
    for t in model.txns.values():
        tids.add(t['from_tid'])
        if t['to_tid']:
            tids.add(t['to_tid'])
    for e in model.events:
        if e['ev'] == 'sched_wakeup':
            pass
    meta = {'tids': {}, 'procs': {}, 'fds': {}}
    if tids:
        out = sh('for t in %s; do g=$(grep -m1 Tgid /proc/$t/status 2>/dev/null | cut -f2); '
                 '[ -n "$g" ] && echo "T|$t|$g|$(cat /proc/$t/comm)"; done' % ' '.join(map(str, sorted(tids))))
        for l in out.splitlines():
            p = l.split('|', 3)
            if len(p) == 4 and p[0] == 'T':
                meta['tids'][int(p[1])] = {'tgid': int(p[2]), 'comm': p[3].strip()}
    pids = set(v['tgid'] for v in meta['tids'].values()) | set(extra_pids)
    for t in model.txns.values():
        if t['to_proc']:
            pids.add(t['to_proc'])
    fds = set()
    for e in model.events:
        if e['ev'] == 'sys_enter' and e['f'].get('nr') == 29 and e['tid'] in meta['tids']:
            try:
                fds.add((meta['tids'][e['tid']]['tgid'], int(e['f']['args'][0], 16)))
            except (ValueError, IndexError):
                pass
    if pids:
        script = ('for p in %s; do echo "C|$p|$(tr \'\\0\' \' \' < /proc/$p/cmdline 2>/dev/null)"; '
                  'grep -E "/dev/(hw|vnd)?binder$" /proc/$p/maps 2>/dev/null | sed "s/^/M|$p|/"; '
                  'cat /sys/kernel/debug/binder/proc/$p 2>/dev/null | sed "s/^/D|$p|/"; done; '
                  % ' '.join(map(str, sorted(pids))))
        script += ' '.join('echo "F|%d:%d|$(readlink /proc/%d/fd/%d)";' % (p, f, p, f) for p, f in sorted(fds))
        out = sh(script, timeout=60)
        dbg = {}
        for l in out.splitlines():
            p = l.split('|', 2)
            if len(p) < 3:
                continue
            if p[0] == 'C':
                pid = int(p[1])
                name = p[2].strip().split(' ')[0] if p[2].strip() else ''
                meta['procs'].setdefault(pid, {'maps': []})['name'] = name
            elif p[0] == 'M':
                meta['procs'].setdefault(int(p[1]), {'maps': []}).setdefault('maps', []).append(p[2])
            elif p[0] == 'D':
                dbg.setdefault(int(p[1]), []).append(p[2])
            elif p[0] == 'F':
                meta['fds'][p[1]] = p[2].strip()
        for pid, ls in dbg.items():
            meta['procs'].setdefault(pid, {'maps': []})['debugfs'] = parse_debugfs('\n'.join(ls))
    return meta


def hal_strace(text):
    out = []
    for l in text.splitlines():
        m = re.match(r'(\d+)\s+(\S+)\s+((\w+)\(.*)$', l)
        if m:
            out.append({'tid': int(m.group(1)), 'time': m.group(2), 'name': m.group(4), 'call': m.group(3)})
    return out


# ---- running a capture -----------------------------------------------------------------------

def run_capture(req):
    kind = req.get('kind', 'probe-app')
    service = req.get('service', 'rgbled')
    method = req.get('method')
    args = [a for a in req.get('args', []) if a != '']
    strace_on = '1' if req.get('strace') else '0'
    sysc = '0' if req.get('syscalls') is False else '1'
    if kind.startswith('probe'):
        pargs = [kind.split('-')[1], service, method if kind != 'probe-raw' else str(req.get('code'))] + args
        if req.get('lookup'):
            pargs.append('--lookup')
        cap = 'probe'
    else:
        pargs = [service, str(req.get('code'))] + [x for a in args for x in (a.split(':', 1) if ':' in a else ['i32', a])]
        cap = 'native'
    script = 'sh %s/capture.sh %s %s %s 1 -- %s' % (DEV, cap, strace_on, sysc, ' '.join(shlex.quote(a) for a in pargs))
    t0 = time.time()
    status = sh(script, timeout=120)
    if 'CAPTURE_DONE' not in status:
        raise RuntimeError('capture failed: ' + status[-500:])
    raw = adb('exec-out', 'cat %s/trace.txt' % DEV, timeout=60)
    out = adb('exec-out', 'cat %s/out.txt' % DEV)
    hal = adb('exec-out', 'cat %s/hal.st 2>/dev/null' % DEV) if strace_on == '1' else ''
    events = trace.parse(raw)
    model = trace.Model(events)
    probe = None
    native_out = None
    if cap == 'probe':
        m = re.search(r'BXJSON:(\{.*\})', out)
        if not m:
            raise RuntimeError('probe failed: ' + out[-800:])
        probe = json.loads(m.group(1))
        if probe.get('error'):
            raise RuntimeError('probe error: ' + probe['error'])
        probe['debugfs_parsed'] = parse_debugfs(probe.get('debugfs', ''))
    else:
        native_out = out
    meta = collect_meta(model, extra_pids=[INFO.get('servicemanager'), INFO.get('hal')])
    meta['servicemanager_pid'] = INFO.get('servicemanager')
    if probe:
        meta['tids'][probe['tid']] = {'tgid': probe['pid'], 'comm': 'main (probe)'}
        meta['procs'][probe['pid']] = {'name': 'com.bx.Probe (app_process)', 'debugfs': probe['debugfs_parsed'],
                                       'maps': [l for l in probe.get('maps', '').splitlines() if l.rstrip().endswith('binder')]}
    else:
        for tid, cm in model.comm.items():
            if cm == 'service':
                meta['tids'][tid] = {'tgid': tid, 'comm': 'service'}
                meta['procs'][tid] = {'name': '/system/bin/service (exited)', 'maps': []}
    descriptor = (probe or {}).get('descriptor') or SERVICES.get(service, '')
    code = (probe or {}).get('code') if probe else int(str(req.get('code')), 0)
    argv_int = []
    for a in args:
        v = a.split(':', 1)[-1]
        try:
            argv_int.append(int(v, 0))
        except ValueError:
            pass
    jreq = {'kind': kind, 'service': service, 'method': method, 'code': code, 'argv': args, 'argv_int': argv_int,
            'descriptor': descriptor}
    if kind == 'native':
        for mm in source.aidl_methods():
            if mm['code'] == code and service == 'rgbled':
                jreq['method'] = mm['name']
    ctx = journey.Ctx(model, meta, jreq, probe=probe, native_out=native_out, hal_strace=hal_strace(hal))
    res = journey.build(ctx)
    res['request'] = jreq
    res['probe'] = {k: v for k, v in (probe or {}).items() if k not in ('debugfs_parsed',)}
    res['native_out'] = native_out
    res['strace'] = hal
    res['options'] = {'strace': strace_on == '1', 'syscalls': sysc == '1', 'lookup': bool(req.get('lookup'))}
    res['capture'] = {'events': len(events), 'seconds': round(time.time() - t0, 2)}
    res['procs'] = {str(k): {'name': v.get('name'), 'maps': v.get('maps', [])} for k, v in meta['procs'].items()}
    return res


def run_record(req):
    pkg = req.get('package', 'com.example.rgbleddemo')
    secs = max(1, min(int(req.get('seconds', 5)), 20))
    app_pid = pidof(pkg)
    if not app_pid:
        raise RuntimeError('%s is not running. Start the app first.' % pkg)
    status = sh('sh %s/capture.sh record 0 0 1 -- %d' % (DEV, secs), timeout=secs + 90)
    if 'CAPTURE_DONE' not in status:
        raise RuntimeError('capture failed: ' + status[-500:])
    raw = adb('exec-out', 'cat %s/trace.txt' % DEV, timeout=120)
    ipc = adb('exec-out', 'cat %s/ipc.txt 2>/dev/null' % DEV, timeout=60)
    model = trace.Model(trace.parse(raw))
    meta = collect_meta(model, extra_pids=[INFO.get('servicemanager'), app_pid])
    meta['servicemanager_pid'] = INFO.get('servicemanager')
    rgb_node = None
    owners = None
    rows = []
    aidl = source.aidl_methods()
    for t in sorted(model.txns.values(), key=lambda t: t['ts']):
        if t['reply'] or meta['tids'].get(t['from_tid'], {}).get('tgid') != app_pid:
            continue
        rep = model.txns.get(t['reply_id']) if t['reply_id'] else None
        dest = meta['procs'].get(t['to_proc'], {}).get('name', str(t['to_proc']))
        rows.append({'id': t['id'], 'ts': t['ts'], 'thread': meta['tids'].get(t['from_tid'], {}).get('comm'),
                     'tid': t['from_tid'], 'to_proc': t['to_proc'], 'dest': dest, 'node': t['node'], 'code': t['code'],
                     'oneway': t['oneway'], 'size': t['data_size'], 'dev': journey.ctx_of(t),
                     'rtt_us': round((rep['ts_recv'] - t['ts']) * 1e6, 1) if rep and rep['ts_recv'] else None,
                     'hops': len(model.tree_ids(t['id'])) // 2})
    base = rows[0]['ts'] if rows else 0
    for r in rows:
        r['t'] = round((r['ts'] - base) * 1e3, 3)
    # app-side Java stacks from `am trace-ipc`
    stacks = []
    sec = re.search(r'Traces for process: %s\n(.*?)(?=\nTraces for process:|\Z)' % re.escape(pkg), ipc, re.S)
    if sec:
        for blk in re.split(r'\n(?=Count: )', sec.group(1)):
            m = re.match(r'Count: (\d+)\nTrace: java.lang.Throwable\n(.*)', blk.strip(), re.S)
            if m:
                frames = [f.strip()[3:] for f in m.group(2).splitlines() if f.strip().startswith('at ')]
                proxy = next((f for f in frames if '$Stub$Proxy.' in f), frames[1] if len(frames) > 1 else '')
                stacks.append({'count': int(m.group(1)), 'call': proxy.split('(')[0], 'frames': frames[:25]})
    LAST['record'] = (model, meta, pkg, app_pid, stacks)
    return {'package': pkg, 'pid': app_pid, 'seconds': secs, 'rows': rows, 'stacks': stacks, 'events': len(model.events),
            'procs': {str(k): v.get('name') for k, v in meta['procs'].items()}}


def record_detail(txn_id):
    model, meta, pkg, app_pid, stacks = LAST['record']
    t = model.txns[txn_id]
    jreq = {'kind': 'record', 'service': '', 'method': None, 'code': t['code'], 'argv': [], 'argv_int': [],
            'descriptor': ''}
    ctx = journey.Ctx(model, meta, jreq)
    ctx.record_stacks = stacks
    return journey.build_one(ctx, txn_id)


# ---- device info & lists ---------------------------------------------------------------------

INFO = {}
SERVICES = {}


def device_info():
    out = sh('getprop ro.product.model; getprop ro.build.version.release; getprop ro.lineage.version; uname -r; id -u; '
             'pidof servicemanager; pidof hwservicemanager; pidof system_server; pidof %s; '
             'cat /sys/kernel/debug/tracing/trace_clock' % HAL_NAME)
    L = (out.splitlines() + [''] * 12)
    INFO.update({'model': L[0], 'android': L[1], 'lineage': L[2], 'kernel': L[3], 'root': L[4].strip() == '0',
                 'servicemanager': int(L[5]) if L[5].strip().isdigit() else None,
                 'hwservicemanager': int(L[6]) if L[6].strip().isdigit() else None,
                 'system_server': int(L[7]) if L[7].strip().isdigit() else None,
                 'hal': int(L[8]) if L[8].strip().isdigit() else None, 'trace_clock': L[9]})
    return INFO


def services():
    out = sh('service list')
    res = []
    for l in out.splitlines():
        m = re.match(r'\d+\s+(\S+): \[(.*)\]', l)
        if m:
            SERVICES[m.group(1)] = m.group(2)
            res.append({'name': m.group(1), 'descriptor': m.group(2),
                        'generated': bool(source.find_aidl_gen(m.group(2))) if m.group(2) else False})
    return res


SIMPLE = {'int', 'long', 'boolean', 'java.lang.String', 'String'}


def methods_for(service):
    desc = SERVICES.get(service) or ''
    if service == 'rgbled':
        ms = source.aidl_methods()
        return {'descriptor': desc, 'methods': [{'code': m['code'], 'name': m['name'], 'ret': m['ret'],
                                                 'params': m['params'], 'simple': all(p[0] in SIMPLE for p in m['params'])}
                                                for m in ms], 'file': source.path('IRgbLedService.aidl')}
    gen = source.find_aidl_gen(desc)
    if not gen:
        return {'descriptor': desc, 'methods': [], 'file': None}
    src = source.lines(gen)
    codes = {}
    for l in src:
        m = re.search(r'static final int TRANSACTION_(\w+) = \(android\.os\.IBinder\.FIRST_CALL_TRANSACTION \+ (\d+)\)', l)
        if m:
            codes[m.group(1)] = int(m.group(2)) + 1
    out, seen = [], set()
    for l in src:
        m = re.match(r'@Override public ([\w.<>\[\]]+) (\w+)\(([^)]*)\) throws android\.os\.RemoteException', l.strip())
        if m and m.group(2) in codes and m.group(2) not in seen:
            seen.add(m.group(2))
            params = []
            for p in [x.strip() for x in m.group(3).split(',') if x.strip()]:
                parts = p.split()
                params.append((parts[0], parts[-1]))
            out.append({'code': codes[m.group(2)], 'name': m.group(2), 'ret': m.group(1), 'params': params,
                        'simple': all(p[0] in SIMPLE for p in params)})
    out.sort(key=lambda m: m['code'])
    return {'descriptor': desc, 'methods': out, 'file': gen}


def procs():
    out = sh('ps -A -o PID,NAME')
    res = []
    for l in out.splitlines()[1:]:
        p = l.split(None, 1)
        if len(p) == 2 and p[0].isdigit() and not p[1].startswith('['):
            res.append({'pid': int(p[0]), 'name': p[1].strip()})
    return res


def live_state(pid):
    text = sh('cat /sys/kernel/debug/binder/proc/%d' % pid)
    st = parse_debugfs(text)
    owners = node_owners()
    names = {p['pid']: p['name'] for p in procs()}
    threads = sh('for t in /proc/%d/task/*; do echo "$(basename $t)|$(cat $t/comm)|$(cat $t/wchan 2>/dev/null)"; done' % pid)
    tinfo = {}
    for l in threads.splitlines():
        p = l.split('|')
        if len(p) >= 2 and p[0].isdigit():
            tinfo[int(p[0])] = {'comm': p[1], 'wchan': p[2] if len(p) > 2 else ''}
    for ctxname, c in st.items():
        for r in c['refs']:
            o = owners.get((ctxname, r['node']))
            r['owner'] = o
            r['owner_name'] = names.get(o, '?')
        for n in c['nodes'].values():
            n['held_by_names'] = [names.get(x, str(x)) for x in n['held_by']]
        for th in c['threads']:
            th.update(tinfo.get(th['tid'], {}))
        c['nodes'] = sorted(c['nodes'].values(), key=lambda n: n['id'])
    maps = sh('grep -E "/dev/(hw|vnd)?binder$" /proc/%d/maps' % pid)
    return {'pid': pid, 'name': names.get(pid, '?'), 'contexts': st, 'maps': maps.splitlines(), 'raw': text}


def source_view(rel, line, ctx=40):
    full = os.path.realpath(os.path.join(source.ROOT, rel))
    if not full.startswith(os.path.realpath(source.ROOT) + os.sep):
        raise ValueError('outside the tree')
    src = source.lines(os.path.relpath(full, source.ROOT))
    if src is None:
        raise ValueError('no such file')
    a, b = max(0, line - ctx), min(len(src), line + ctx)
    return {'file': rel, 'start': a + 1, 'lines': src[a:b], 'focus': line, 'total': len(src)}


# ---- HTTP ------------------------------------------------------------------------------------

class H(BaseHTTPRequestHandler):
    def log_message(self, fmt, *a):
        sys.stderr.write('[bx] %s\n' % (fmt % a))

    def send(self, code, body, ctype='application/json'):
        b = body if isinstance(body, bytes) else body.encode()
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(b)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(b)

    def j(self, obj, code=200):
        self.send(code, json.dumps(obj, default=str))

    def do_GET(self):
        u = urlparse(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        try:
            if u.path in ('/', '/index.html'):
                return self.static('index.html')
            if u.path.startswith('/web/'):
                return self.static(u.path[5:])
            if u.path == '/api/info':
                return self.j({'device': device_info(), 'root': source.ROOT,
                               'protocol': source.protocol(), 'special': source.special_codes(),
                               'aidl': source.aidl_methods(), 'hal': source.hal_methods(), 'layers': journey.LAYERS,
                               'paths': {k: v for k, v in source.P.items()}})
            if u.path == '/api/services':
                return self.j(services())
            if u.path == '/api/methods':
                if not SERVICES:
                    services()
                return self.j(methods_for(q.get('service', 'rgbled')))
            if u.path == '/api/procs':
                return self.j(procs())
            if u.path == '/api/state':
                return self.j(live_state(int(q['pid'])))
            if u.path == '/api/source':
                return self.j(source_view(q['file'], int(q.get('line', 1)), int(q.get('ctx', 40))))
            if u.path == '/api/record/txn':
                return self.j(record_detail(int(q['id'])))
            self.send(404, 'not found', 'text/plain')
        except Exception as e:  # noqa: BLE001
            import traceback
            traceback.print_exc()
            self.j({'error': str(e)}, 500)

    def do_POST(self):
        u = urlparse(self.path)
        n = int(self.headers.get('Content-Length', 0))
        body = json.loads(self.rfile.read(n) or b'{}')
        try:
            if not LOCK.acquire(timeout=1):
                return self.j({'error': 'Another capture is running on the phone. Wait for it to finish.'}, 409)
            try:
                if u.path == '/api/run':
                    if not SERVICES:
                        services()
                    return self.j(run_capture(body))
                if u.path == '/api/record':
                    return self.j(run_record(body))
            finally:
                LOCK.release()
            self.send(404, 'not found', 'text/plain')
        except Exception as e:  # noqa: BLE001
            import traceback
            traceback.print_exc()
            self.j({'error': str(e)}, 500)

    def static(self, name):
        p = os.path.realpath(os.path.join(HERE, 'web', name))
        if not p.startswith(os.path.join(HERE, 'web')) or not os.path.isfile(p):
            return self.send(404, 'not found', 'text/plain')
        ctype = {'html': 'text/html', 'js': 'text/javascript', 'css': 'text/css', 'svg': 'image/svg+xml'}.get(
            p.rsplit('.', 1)[-1], 'application/octet-stream')
        with open(p, 'rb') as fh:
            self.send(200, fh.read(), ctype + '; charset=utf-8')


def main():
    devs = [l for l in adb('devices').splitlines()[1:] if l.strip().endswith('device')]
    if not devs:
        sys.exit('No device. Connect the phone and enable USB debugging.')
    if sh('id -u').strip() != '0':
        print('adbd is not root, running `adb root`...')
        adb('root')
        time.sleep(2)
        adb('wait-for-device')
    push_tools()
    info = device_info()
    print('Device: %s, Android %s, kernel %s, root=%s' % (info['model'], info['android'], info['kernel'], info['root']))
    print('Source tree: %s' % source.ROOT)
    print('Binder Explorer on http://127.0.0.1:%d' % PORT)
    ThreadingHTTPServer(('127.0.0.1', PORT), H).serve_forever()


if __name__ == '__main__':
    main()
