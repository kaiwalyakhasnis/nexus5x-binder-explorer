"""Parse a raw ftrace capture and rebuild binder transactions from it.

Everything here works from the kernel's own trace output (binder_*, sched_*,
raw_syscalls and trace_marker events). Nothing is simulated.
"""
import re
from collections import defaultdict

LINE = re.compile(
    r'^\s*(?P<comm>.+?)-(?P<tid>\d+)\s+(?:\(\s*[\d-]+\)\s+)?\[(?P<cpu>\d+)\]\s+(?P<flags>\S+)\s+'
    r'(?P<ts>\d+\.\d+):\s+(?P<ev>\w+):\s?(?P<body>.*)$')
KV = re.compile(r'(\w+)=(\S+)')
SWITCH = re.compile(r'prev_comm=(.*) prev_pid=(\d+) prev_prio=(\d+) prev_state=(\S+) ==> '
                    r'next_comm=(.*) next_pid=(\d+) next_prio=(\d+)')
WAKEUP = re.compile(r'comm=(.*) pid=(\d+) prio=(\d+) success=(\d+) target_cpu=(\d+)')
SYS_ENTER = re.compile(r'NR (\d+) \((.*)\)')
SYS_EXIT = re.compile(r'NR (\d+) = (-?\d+)')

# arm64 syscall numbers (include/uapi/asm-generic/unistd.h)
SYSCALLS = {
    17: 'getcwd', 19: 'eventfd2', 20: 'epoll_create1', 21: 'epoll_ctl', 22: 'epoll_pwait', 23: 'dup',
    24: 'dup3', 25: 'fcntl', 29: 'ioctl', 34: 'mkdirat', 35: 'unlinkat', 43: 'statfs', 46: 'ftruncate',
    48: 'faccessat', 56: 'openat', 57: 'close', 59: 'pipe2', 61: 'getdents64', 62: 'lseek', 63: 'read',
    64: 'write', 65: 'readv', 66: 'writev', 67: 'pread64', 68: 'pwrite64', 71: 'sendfile',
    72: 'pselect6', 73: 'ppoll', 78: 'readlinkat', 79: 'newfstatat', 80: 'fstat', 93: 'exit',
    94: 'exit_group', 96: 'set_tid_address', 98: 'futex', 101: 'nanosleep', 113: 'clock_gettime',
    115: 'clock_nanosleep', 124: 'sched_yield', 129: 'kill', 131: 'tgkill', 134: 'rt_sigaction',
    135: 'rt_sigprocmask', 139: 'rt_sigreturn', 160: 'uname', 163: 'getrlimit', 167: 'prctl',
    169: 'gettimeofday', 172: 'getpid', 173: 'getppid', 174: 'getuid', 175: 'geteuid', 178: 'gettid',
    179: 'sysinfo', 198: 'socket', 203: 'connect', 206: 'sendto', 207: 'recvfrom', 211: 'sendmsg',
    212: 'recvmsg', 214: 'brk', 215: 'munmap', 216: 'mremap', 220: 'clone', 221: 'execve', 222: 'mmap',
    226: 'mprotect', 233: 'madvise', 260: 'wait4', 261: 'prlimit64', 278: 'getrandom',
}


def parse(text):
    """Returns a list of event dicts in file (= time) order."""
    events = []
    for line in text.splitlines():
        if not line or line[0] == '#':
            continue
        m = LINE.match(line)
        if not m:
            continue
        ev = m.group('ev')
        body = m.group('body')
        e = {
            'i': len(events), 'comm': m.group('comm').strip(), 'tid': int(m.group('tid')),
            'cpu': int(m.group('cpu')), 'ts': float(m.group('ts')), 'ev': ev, 'body': body, 'raw': line.strip(),
        }
        f = {}
        if ev == 'sched_switch':
            s = SWITCH.match(body)
            if s:
                f = {'prev_comm': s.group(1), 'prev_pid': int(s.group(2)), 'prev_state': s.group(4),
                     'next_comm': s.group(5), 'next_pid': int(s.group(6))}
        elif ev == 'sched_wakeup':
            s = WAKEUP.match(body)
            if s:
                f = {'comm': s.group(1), 'pid': int(s.group(2)), 'target_cpu': int(s.group(5))}
        elif ev == 'sys_enter':
            s = SYS_ENTER.match(body)
            if s:
                nr = int(s.group(1))
                f = {'nr': nr, 'name': SYSCALLS.get(nr, 'sys_%d' % nr),
                     'args': [a.strip() for a in s.group(2).split(',')]}
        elif ev == 'sys_exit':
            s = SYS_EXIT.match(body)
            if s:
                nr = int(s.group(1))
                f = {'nr': nr, 'name': SYSCALLS.get(nr, 'sys_%d' % nr), 'ret': int(s.group(2))}
        elif ev == 'tracing_mark_write':
            f = {'text': body.strip()}
        elif ev in ('binder_command', 'binder_return'):
            parts = body.split()
            f = {'cmd': int(parts[0].split('=')[1], 16), 'name': parts[1] if len(parts) > 1 else '?'}
        else:
            for k, v in KV.findall(body):
                try:
                    f[k] = int(v, 16) if v.startswith('0x') or k in ('flags', 'code', 'cmd', 'arg') else int(v)
                except ValueError:
                    f[k] = v
        e['f'] = f
        events.append(e)
    return events


class Model:
    """Transactions, per-thread event index and thread state, rebuilt from the events."""

    def __init__(self, events):
        self.events = events
        self.txns = {}
        self.by_tid = defaultdict(list)
        self.comm = {}
        stacks = defaultdict(list)          # tid -> ids of transactions it is currently serving
        last_cmd = {}                       # tid -> last binder_command name
        ioctl_cmds = defaultdict(list)      # tid -> commands written in the current ioctl
        for e in events:
            tid = e['tid']
            self.by_tid[tid].append(e['i'])
            self.comm.setdefault(tid, e['comm'])
            ev, f = e['ev'], e['f']
            if ev == 'binder_ioctl':
                ioctl_cmds[tid] = []
            elif ev == 'binder_command':
                last_cmd[tid] = f['name']
                ioctl_cmds[tid].append(e['i'])
            elif ev == 'binder_transaction':
                t = {
                    'id': f['transaction'], 'from_tid': tid, 'from_comm': e['comm'], 'ts': e['ts'],
                    'ev_send': e['i'], 'node': f.get('dest_node', 0), 'to_proc': f.get('dest_proc', 0),
                    'to_thread': f.get('dest_thread', 0), 'reply': bool(f.get('reply')),
                    'flags': f.get('flags', 0), 'code': f.get('code', 0), 'oneway': bool(f.get('flags', 0) & 1),
                    'bc': last_cmd.get(tid, '?'), 'bc_batch': list(ioctl_cmds[tid]),
                    'parent': None, 'reply_to': None, 'reply_id': None, 'children': [],
                    'to_tid': None, 'ts_recv': None, 'ev_recv': None, 'data_size': None, 'offsets_size': None,
                    'freed_ts': None, 'freed_by': None, 'translations': [],
                }
                if t['reply']:
                    if stacks[tid]:
                        req = stacks[tid].pop()
                        t['reply_to'] = req
                        if req in self.txns:
                            self.txns[req]['reply_id'] = t['id']
                elif stacks[tid]:
                    t['parent'] = stacks[tid][-1]
                    if t['parent'] in self.txns:
                        self.txns[t['parent']]['children'].append(t['id'])
                self.txns[t['id']] = t
            elif ev == 'binder_transaction_alloc_buf':
                t = self.txns.get(f.get('transaction'))
                if t:
                    t['data_size'] = f.get('data_size')
                    t['offsets_size'] = f.get('offsets_size')
                    t['ev_alloc'] = e['i']
            elif ev.startswith('binder_transaction_') and ev[19:] in ('node_to_ref', 'ref_to_node', 'ref_to_ref', 'fd'):
                t = self.txns.get(f.get('transaction'))
                if t:
                    t['translations'].append(e['i'])
            elif ev == 'binder_transaction_received':
                t = self.txns.get(f.get('transaction'))
                if t:
                    t['to_tid'] = tid
                    t['ts_recv'] = e['ts']
                    t['ev_recv'] = e['i']
                    if not t['reply'] and not t['oneway']:
                        stacks[tid].append(t['id'])
            elif ev == 'binder_transaction_buffer_release':
                t = self.txns.get(f.get('transaction'))
                if t:
                    t['freed_ts'] = e['ts']
                    t['freed_by'] = tid
                    t['ev_free'] = e['i']

    # ---- per-thread helpers -------------------------------------------------

    def tid_events(self, tid, t0=None, t1=None):
        for i in self.by_tid.get(tid, ()):
            e = self.events[i]
            if (t0 is None or e['ts'] >= t0) and (t1 is None or e['ts'] <= t1):
                yield e

    def find(self, tid, ev, after=None, before=None, pred=None, last=False):
        """First (or last) event of a type on a thread inside a time range."""
        hit = None
        for e in self.tid_events(tid, after, before):
            if e['ev'] == ev and (pred is None or pred(e)):
                if not last:
                    return e
                hit = e
        return hit

    def wakeups_of(self, tid, t0, t1):
        return [e for e in self.events if e['ev'] == 'sched_wakeup' and e['f'].get('pid') == tid
                and t0 <= e['ts'] <= t1]

    def thread_states(self, tid, t0, t1):
        """Running / runnable / sleeping intervals for one thread, from sched_switch + sched_wakeup."""
        out = []
        state, since, cpu = None, t0, None
        for e in self.events:
            if e['ts'] < t0 - 0.05 or e['ev'] not in ('sched_switch', 'sched_wakeup'):
                continue
            if e['ts'] > t1:
                break
            f = e['f']
            ts = max(e['ts'], t0)
            if e['ev'] == 'sched_switch' and f.get('next_pid') == tid:
                if state is not None and ts > since:
                    out.append({'s': state, 't0': since, 't1': ts})
                elif state is None and ts > t0:
                    out.append({'s': 'runnable' if self._woken_before(tid, e['ts']) else 'sleeping', 't0': t0, 't1': ts})
                state, since, cpu = 'running', ts, e['cpu']
            elif e['ev'] == 'sched_switch' and f.get('prev_pid') == tid:
                if state is None:
                    state = 'running'
                if ts > since:
                    out.append({'s': state, 't0': since, 't1': ts, 'cpu': e['cpu']})
                ps = f.get('prev_state', 'S')
                state = 'runnable' if ps.startswith('R') else ('traced' if ps.startswith('t') else
                                                              ('uninterruptible' if ps.startswith('D') else 'sleeping'))
                since = ts
            elif e['ev'] == 'sched_wakeup' and f.get('pid') == tid:
                if state in ('sleeping', 'traced', 'uninterruptible', None):
                    if state is not None and ts > since:
                        out.append({'s': state, 't0': since, 't1': ts})
                    state, since = 'runnable', ts
        if state is None:
            # never switched in the window: if it emitted events it was running all along
            ran = any(True for _ in self.tid_events(tid, t0, t1))
            state = 'running' if ran else 'sleeping'
        if t1 > since:
            out.append({'s': state, 't0': since, 't1': t1})
        return [o for o in out if o['t1'] > o['t0']]

    def _woken_before(self, tid, ts):
        for e in self.events:
            if e['ts'] >= ts:
                return False
            if e['ev'] == 'sched_wakeup' and e['f'].get('pid') == tid and ts - e['ts'] < 0.05:
                return True
        return False

    def syscalls(self, tid, t0, t1):
        out, open_ = [], None
        for e in self.tid_events(tid, t0 - 0.05, t1 + 0.05):
            if e['ev'] == 'sys_enter':
                open_ = {'name': e['f']['name'], 'nr': e['f']['nr'], 'args': e['f']['args'],
                         't0': e['ts'], 'ev': e['i'], 't1': None, 'ret': None}
                out.append(open_)
            elif e['ev'] == 'sys_exit' and open_ and e['f'].get('nr') == open_['nr']:
                open_['t1'] = e['ts']
                open_['ret'] = e['f']['ret']
                open_ = None
        return [s for s in out if (s['t1'] or s['t0']) >= t0 and s['t0'] <= t1]

    def markers(self, tid, t0, t1):
        """Nested B/E trace_marker slices on a thread."""
        out, stack = [], []
        for e in self.tid_events(tid, t0 - 0.5, t1 + 0.5):
            if e['ev'] != 'tracing_mark_write':
                continue
            txt = e['f']['text']
            if txt.startswith('B|'):
                parts = txt.split('|', 2)
                s = {'name': parts[2] if len(parts) > 2 else txt, 't0': e['ts'], 't1': None,
                     'depth': len(stack), 'ev': e['i']}
                stack.append(s)
                out.append(s)
            elif txt.startswith('E') and stack:
                stack.pop()['t1'] = e['ts']
        return [s for s in out if s['t0'] <= t1 and (s['t1'] or t1) >= t0]

    # ---- transaction trees -----------------------------------------------------

    def tree(self, tid_):
        t = self.txns[tid_]
        rep = self.txns.get(t['reply_id']) if t['reply_id'] else None
        return {'id': t['id'], 'children': [self.tree(c) for c in t['children'] if c in self.txns],
                'reply': rep['id'] if rep else None}

    def tree_ids(self, root):
        ids = [root]
        t = self.txns[root]
        if t['reply_id']:
            ids.append(t['reply_id'])
        for c in t['children']:
            ids += self.tree_ids(c)
        return ids

    def tree_threads(self, root):
        tids = []
        for i in self.tree_ids(root):
            t = self.txns[i]
            for x in (t['from_tid'], t['to_tid']):
                if x and x not in tids:
                    tids.append(x)
        return tids

    def tree_span(self, root):
        ts = []
        for i in self.tree_ids(root):
            t = self.txns[i]
            ts += [x for x in (t['ts'], t['ts_recv'], t['freed_ts']) if x]
        return min(ts), max(ts)
