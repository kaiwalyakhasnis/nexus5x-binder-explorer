"""Turns one captured call into an ordered, layer-by-layer story.

Each step carries: which thread/process it runs on, which layer (Java, JNI,
libbinder, kernel...), the real source excerpt from the LineageOS tree, the real
values from this capture, and the exact trace lines that prove it happened.
"""
import re

from . import parcel, source
from .source import snip

LAYERS = {
    'app': 'App / caller code',
    'manager': 'Framework manager (Java)',
    'aidl-proxy': 'AIDL proxy (generated)',
    'java': 'android.os (Java)',
    'jni': 'JNI (C++)',
    'libbinder': 'libbinder (C++)',
    'libhwbinder': 'libhwbinder (C++)',
    'hidl-proxy': 'HIDL proxy (generated)',
    'syscall': 'System call',
    'kernel': 'Binder driver (kernel)',
    'sched': 'Scheduler (kernel)',
    'aidl-stub': 'AIDL stub (generated)',
    'service': 'System service (Java)',
    'hidl-stub': 'HIDL stub (generated C++)',
    'hal': 'HAL implementation (C++)',
    'vfs': 'VFS / sysfs (kernel)',
    'led': 'LED driver (kernel)',
    'native-cli': 'Native client (C++)',
    'svcmgr': 'servicemanager (C)',
}

SM_CODES = {1: 'GET_SERVICE', 2: 'CHECK_SERVICE', 3: 'ADD_SERVICE', 4: 'LIST_SERVICES'}


def code_name(code, hw=False, methods=None, hal_methods=None, to_sm=False):
    if code > 0x00ffffff:
        b = code.to_bytes(4, 'big')
        if b[0] == 0x0f:
            return 'HIDL ' + b[1:].decode(errors='replace')
        return b.decode(errors='replace')
    if to_sm:
        return SM_CODES.get(code, str(code))
    pool = hal_methods if hw else methods
    for m in pool or []:
        if m['code'] == code:
            return m['name']
    return str(code)


class Ctx:
    def __init__(self, model, meta, req, probe=None, native_out=None, hal_strace=None):
        self.m = model
        self.meta = meta
        self.req = req
        self.probe = probe
        self.native_out = native_out
        self.hal_strace = hal_strace or []
        self.steps = []
        self.base = None
        self.aidl = source.aidl_methods()
        self.hal = source.hal_methods()
        self.sm_pid = meta.get('servicemanager_pid')

    # ---- naming --------------------------------------------------------------

    def pid_of(self, tid):
        return self.meta['tids'].get(tid, {}).get('tgid', tid)

    def pname(self, pid):
        p = self.meta['procs'].get(pid, {})
        n = p.get('name') or self.meta['tids'].get(pid, {}).get('comm') or str(pid)
        return n.rsplit('/', 1)[-1] if n.startswith('/') else n

    def tname(self, tid):
        return self.meta['tids'].get(tid, {}).get('comm') or self.m.comm.get(tid, str(tid))

    def tlabel(self, tid):
        pid = self.pid_of(tid)
        return '%s (tid %d) in %s (pid %d)' % (self.tname(tid), tid, self.pname(pid), pid)

    def us(self, ts):
        return None if ts is None else round((ts - self.base) * 1e6, 1)

    def is_java(self, pid):
        if self.probe and pid == self.probe.get('pid'):
            return True
        n = self.pname(pid)
        return n == 'system_server' or ('.' in n and '@' not in n and not n.startswith('/') and not n.startswith('vendor.'))

    def debugfs(self, pid):
        return self.meta['procs'].get(pid, {}).get('debugfs') or {}

    def handle_for(self, pid, node, ctxname):
        d = self.debugfs(pid).get(ctxname, {})
        for r in d.get('refs', []):
            if r['node'] == node:
                return r['desc']
        return None

    def node_info(self, pid, node, ctxname):
        return self.debugfs(pid).get(ctxname, {}).get('nodes', {}).get(node)

    def binder_map(self, pid, dev):
        for l in self.meta['procs'].get(pid, {}).get('maps', []):
            if l.rstrip().endswith('/dev/' + dev):
                a, b = l.split()[0].split('-')
                return {'start': '0x' + a, 'end': '0x' + b, 'size': int(b, 16) - int(a, 16)}
        return None

    def add(self, tid, layer, title, what, values=(), src=(), ev=(), ts=None, extra=None):
        st = {'n': len(self.steps) + 1, 'tid': tid, 'pid': self.pid_of(tid) if tid else None,
              'thread': self.tname(tid) if tid else None, 'proc': self.pname(self.pid_of(tid)) if tid else None,
              'layer': layer, 'layer_label': LAYERS.get(layer, layer), 'title': title, 'what': what,
              'values': [[k, v] for k, v in values if v is not None and v != ''],
              'src': [s for s in src if s], 'ev': [self.m.events[i]['raw'] for i in ev if i is not None],
              'ev_idx': [i for i in ev if i is not None], 'ts': self.us(ts)}
        if extra:
            st.update(extra)
        self.steps.append(st)
        return st


def ctx_of(t):
    return 'hwbinder' if t['bc'] in ('BC_TRANSACTION_SG', 'BC_REPLY_SG') else 'binder'


# ---- kernel pieces shared by every hop -------------------------------------------------------

def kernel_send(c, t, hop):
    m = c.m
    S = t['from_tid']
    sp = c.pid_of(S)
    dev = ctx_of(t)
    # the ioctl that carried this BC_TRANSACTION
    ioctl = m.find(S, 'binder_ioctl', before=t['ts'], last=True, after=t['ts'] - 0.05)
    sysent = m.find(S, 'sys_enter', before=t['ts'], last=True, after=t['ts'] - 0.05,
                    pred=lambda e: e['f'].get('nr') == 29)
    lock = m.find(S, 'binder_lock', after=ioctl['ts'] if ioctl else None, before=t['ts'])
    locked = m.find(S, 'binder_locked', after=ioctl['ts'] if ioctl else None, before=t['ts'])
    fd = None
    if sysent:
        try:
            fd = int(sysent['f']['args'][0], 16)
        except (ValueError, IndexError):
            fd = None
    fdpath = c.meta['fds'].get('%d:%s' % (sp, fd)) if fd is not None else None
    cmds = [m.events[i] for i in t['bc_batch']]
    write_size = sum(4 + ((e['f']['cmd'] >> 16) & 0x3fff) for e in cmds)
    wait_lock = (locked['ts'] - lock['ts']) * 1e6 if lock and locked else None

    vals = [('process', '%s (pid %d)' % (c.pname(sp), sp)), ('thread', '%s (tid %d)' % (c.tname(S), S))]
    if sysent:
        vals.append(('syscall', 'ioctl(fd=%s%s, cmd=0x%s, arg=0x%s)' % (
            fd, ' → ' + fdpath if fdpath else '', sysent['f']['args'][1], sysent['f']['args'][2])))
    c.add(S, 'syscall', 'ioctl(BINDER_WRITE_READ) enters the kernel',
          'The thread hands the driver a <code>struct binder_write_read</code>: a pointer to its outgoing '
          'command buffer (<code>mOut</code>) and to an empty incoming buffer (<code>mIn</code>). '
          'From here on everything runs in kernel mode <b>on the same CPU, in the same thread</b>. '
          'There is no separate "binder kernel thread": the sender\'s own syscall does the delivery work.'
          + (' This ioctl went to <code>%s</code>, a different device node with its own context and its own '
             'handle numbers.' % fdpath if fdpath and 'hwbinder' in fdpath else ''),
          vals + [('write_size', '%d bytes (%s)' % (write_size, ' + '.join(
              '%s %dB' % (e['f']['name'], 4 + ((e['f']['cmd'] >> 16) & 0x3fff)) for e in cmds))),
                  ('cmd value', '0xc0306201 = _IOWR(\'b\', 1, struct binder_write_read): dir=RW, size=48, type=\'b\', nr=1')],
          [snip('IPCThreadState' if dev == 'binder' else 'hw_IPCThreadState',
                ['status_t IPCThreadState::talkWithDriver', r'bwr\.write_size = outAvail'], before=2, after=12,
                hl=[r'bwr\.(write|read)_(size|buffer)'], title='userspace: talkWithDriver() fills binder_write_read'),
           snip('IPCThreadState' if dev == 'binder' else 'hw_IPCThreadState',
                ['status_t IPCThreadState::talkWithDriver', r'ioctl\(mProcess->mDriverFD, BINDER_WRITE_READ'],
                before=1, after=3, hl=[r'ioctl\('], title='the system call'),
           snip('binder.c', r'case BINDER_WRITE_READ: \{', after=26, hl=[r'binder_thread_write\(', r'binder_thread_read\(',
                                                                     r'copy_from_user'], title='kernel: binder_ioctl()')],
          [sysent and sysent['i'], ioctl and ioctl['i'], lock and lock['i'], locked and locked['i']],
          sysent['ts'] if sysent else (ioctl['ts'] if ioctl else t['ts']),
          extra={'lock_wait_us': wait_lock})

    c.add(S, 'kernel', 'binder_thread_write() reads the commands: %s' % ', '.join(e['f']['name'] for e in cmds),
          'The driver walks the write buffer one command at a time: a 32-bit <code>BC_*</code> code, then its payload. '
          + ('<b>BC_FREE_BUFFER</b> comes first: libbinder queued it after the previous reply Parcel was recycled, '
             'and it rides along with the next ioctl, which saves a syscall. ' if any(e['f']['name'] == 'BC_FREE_BUFFER' for e in cmds) else '')
          + 'Then <b>%s</b> carries a <code>binder_transaction_data</code> (64 bytes on arm64) that points at the Parcel. '
          'The command values are ioctl-style encodings: <code>0x%08x</code> = _IOW(\'c\', %d, %d-byte payload).'
          % (t['bc'], cmds[-1]['f']['cmd'] if cmds else 0, (cmds[-1]['f']['cmd'] & 0xff) if cmds else 0,
             ((cmds[-1]['f']['cmd'] >> 16) & 0x3fff) if cmds else 0)
          + (' Taking the <b>global binder mutex</b> took %.1f µs (the 3.10 driver has one lock for everything).' % wait_lock
             if wait_lock is not None else ''),
          [('commands', ', '.join('%s (0x%08x)' % (e['f']['name'], e['f']['cmd']) for e in cmds))],
          [snip('binder.c', r'static int binder_thread_write\(', after=22, hl=[r'get_user', r'trace_binder_command']),
           snip('binder.c', r'case BC_TRANSACTION_SG:', after=26 if dev == 'hwbinder' else 26,
                hl=[r'binder_transaction\(proc, thread', r'copy_from_user']),
           snip('binder.c', r'static inline void binder_lock\(', after=6, hl=[r'mutex_lock'],
                title='the global lock taken around all of this')],
          [e['i'] for e in cmds], cmds[0]['ts'] if cmds else t['ts'])

    if not t['reply']:
        handle = None
        if hop.get('handle') is not None:
            handle = hop['handle']
        else:
            handle = c.handle_for(sp, t['node'], dev)
        is_sm = t['to_proc'] == c.sm_pid and t['node'] in (1, 2) and handle in (0, None)
        ni = c.node_info(t['to_proc'], t['node'], dev)
        c.add(S, 'kernel', 'binder_transaction(): handle %s → node %d → %s' % (
            handle if handle is not None else '?', t['node'], c.pname(t['to_proc'])),
              'The driver turns the number the sender used into a destination. '
              + ('Handle <b>0</b> is special: it always means the context manager (servicemanager), with no lookup needed. '
                 if handle == 0 or is_sm else
                 '<code>binder_get_ref(proc, %s)</code> looks up <b>this process\'s own</b> table of refs '
                 '(a red-black tree keyed by handle). The ref points at a <code>binder_node</code>, debug id %d, '
                 'which belongs to %s (pid %d). ' % (handle, t['node'], c.pname(t['to_proc']), t['to_proc']))
              + 'Then <code>security_binder_transaction()</code> asks SELinux whether %s may call %s. '
                'Because this is a synchronous call and the sender is not already serving a call from the target, '
                'no particular thread is picked: the work goes on the <b>process-wide todo list</b> (dest_thread=0) and '
                'any idle binder thread of %s can take it.' % (c.pname(sp), c.pname(t['to_proc']), c.pname(t['to_proc'])),
              [('target.handle (sender\'s number)', handle), ('binder_node debug id', t['node']),
               ('node owner', '%s (pid %d)' % (c.pname(t['to_proc']), t['to_proc'])),
               ('node->ptr / cookie in owner', '%s / %s' % (ni['ptr'], ni['cookie']) if ni else None),
               ('code', '%d (0x%x) = %s' % (t['code'], t['code'], hop.get('code_name'))),
               ('flags', '0x%02x%s' % (t['flags'], ' (TF_ACCEPT_FDS)' if t['flags'] == 0x10 else
                                         ' (TF_ONE_WAY | TF_ACCEPT_FDS)' if t['flags'] == 0x11 else '')),
               ('transaction debug id', t['id'])],
              [snip('binder.c', [r'static void binder_transaction\(', r'if \(tr->target.handle\) \{'], before=1, after=34,
                    hl=[r'binder_get_ref\(', r'target_node = ref->node', r'binder_context_mgr_node', r'security_binder_transaction',
                        r'target_proc = target_node->proc']),
               snip('binder.c', [r'static void binder_transaction\(', r'if \(target_thread\) \{'], after=8,
                    hl=[r'target_list', r'target_wait'], title='where the work will be queued')],
              [t['ev_send']], t['ts'])
    else:
        req = c.m.txns.get(t['reply_to'])
        c.add(S, 'kernel', 'binder_transaction(reply): routed by the transaction stack, not by a handle',
              'A reply has no target handle (<code>target.handle</code> is ignored). The driver pops '
              '<code>thread->transaction_stack</code>, the request this thread is serving (transaction %s), and sends the '
              'reply straight to <b>the exact thread that is blocked waiting</b>: %s. That is why <code>dest_thread</code> '
              'is filled in for replies.' % (t['reply_to'], c.tlabel(t['to_thread'])),
              [('in reply to transaction', t['reply_to']), ('dest_thread', t['to_thread']),
               ('dest_proc', '%s (pid %d)' % (c.pname(t['to_proc']), t['to_proc'])), ('transaction debug id', t['id'])],
              [snip('binder.c', [r'static void binder_transaction\(', r'if \(reply\) \{'], after=26,
                    hl=[r'in_reply_to = thread->transaction_stack', r'target_thread = in_reply_to->from',
                        r'binder_pop_transaction'])],
              [t['ev_send']], t['ts'])

    tm = c.binder_map(t['to_proc'], dev) if t['to_proc'] else None
    alloc = m.events[t['ev_alloc']] if t.get('ev_alloc') is not None else None
    pages = [e for e in m.tid_events(S, t['ts'], t['ts'] + 0.0005) if e['ev'] == 'binder_update_page_range']
    c.add(S, 'kernel', 'binder_alloc_buf() + copy_from_user(): the one and only copy (%s bytes)' % t['data_size'],
          'Here is the trick that makes binder fast. Every process <code>mmap</code>s its binder device read-only '
          '(1 MB − 8 KB, <code>BINDER_VM_SIZE</code>). The kernel maps the <b>same physical pages</b> into its own address '
          'space too. <code>binder_alloc_buf()</code> carves %s bytes out of <b>%s\'s</b> area, and '
          '<code>copy_from_user()</code> copies the Parcel from the sender\'s heap <b>directly into the receiver\'s '
          'mapping</b>. The receiver will read it in place, so there is no second copy. %s'
          % (t['data_size'], c.pname(t['to_proc']),
             'New physical pages had to be allocated for this buffer (binder_update_page_range).' if pages else
             'No new pages were needed: the buffer fit in pages that were already backed.'),
          [('data_size', '%s bytes' % t['data_size']), ('offsets_size', '%s bytes → %d binder object(s) inside' % (
              t['offsets_size'], (t['offsets_size'] or 0) // 8)),
           ('receiver mapping (%s)' % dev, '%s-%s (%d KB) in %s' % (tm['start'], tm['end'], tm['size'] // 1024, c.pname(t['to_proc'])) if tm else None)],
          [snip('binder.c', [r'static void binder_transaction\(', r'trace_binder_transaction\(reply'], before=1, after=24,
                hl=[r'binder_alloc_buf\(', r'copy_from_user_preempt_disabled\(t->buffer->data', r'trace_binder_transaction_alloc_buf']),
           snip('binder.c', r'static int binder_mmap\(', after=44, hl=[r'user_buffer_offset', r'get_vm_area', r'SZ_4M'],
                title='set up once per process: the shared mapping')],
          [t.get('ev_alloc')] + [e['i'] for e in pages], alloc['ts'] if alloc else t['ts'])

    if t['translations']:
        tr_ev = [m.events[i] for i in t['translations']]
        c.add(S, 'kernel', 'Binder objects inside the Parcel are translated',
              'The offsets array lists where <code>flat_binder_object</code>s sit inside the data. The driver rewrites each one '
              'for the receiver: a local object becomes a <b>handle</b> in the receiving process (creating a ref if needed), '
              'and a handle is mapped to the receiver\'s own number for the same node. This is how a process gets '
              'a handle at all.',
              [('translation', e['body']) for e in tr_ev],
              [snip('binder.c', [r'static void binder_transaction\(', r'for \(; offp < off_end; offp\+\+\)'], after=30,
                    hl=[r'binder_translate_binder', r'binder_translate_handle', r'BINDER_TYPE_'])],
              t['translations'], tr_ev[0]['ts'])

    wake = None
    if t['to_tid']:
        wake = next((e for e in m.events if e['ev'] == 'sched_wakeup' and e['f'].get('pid') == t['to_tid']
                     and t['ts'] <= e['ts'] <= (t['ts_recv'] or t['ts'] + 0.01)), None)
    c.add(S, 'kernel', 'Queue the work and wake %s' % (c.tname(t['to_tid']) if t['to_tid'] else 'a thread'),
          'Two work items are queued: <code>BINDER_WORK_TRANSACTION</code> on the %s todo list, and '
          '<code>BINDER_WORK_TRANSACTION_COMPLETE</code> on the sender\'s own list (that becomes '
          '<code>BR_TRANSACTION_COMPLETE</code>, meaning "your send was accepted"). Then '
          '<code>wake_up_interruptible_sync()</code> wakes a thread sleeping in <code>binder_thread_read()</code>. '
          'The "sync" variant hints to the scheduler that the waker is about to sleep, so the wakee can run on this CPU.'
          % ('target thread\'s' if t['to_thread'] else 'target process\'s'),
          [('woken thread', c.tlabel(wake['f']['pid']) if wake else None),
           ('woken by', '%s (tid %d)' % (wake['comm'], wake['tid']) if wake else None),
           ('target cpu', wake['f'].get('target_cpu') if wake else None)],
          [snip('binder.c', [r'static void binder_transaction\(', r't->work.type = BINDER_WORK_TRANSACTION;'], before=17,
                after=13, hl=[r'list_add_tail', r'wake_up_interruptible', r'BINDER_WORK_TRANSACTION'])],
          [wake and wake['i']], wake['ts'] if wake else t['ts'])
    return wake


def sender_waits(c, t):
    """What the sender did right after sending: this depends on the scheduler, so read it from the trace."""
    m = c.m
    S = t['from_tid']
    rep = m.txns.get(t['reply_id']) if t['reply_id'] else None
    end = rep['ts_recv'] if rep and rep['ts_recv'] else t['ts'] + 0.05
    sw = m.find(S, 'sched_switch', after=t['ts'], before=end, pred=lambda e: e['f'].get('prev_pid') == S)
    wfw = m.find(S, 'binder_wait_for_work', after=t['ts'], before=sw['ts'] if sw else end)
    comps = [e for e in m.tid_events(S, t['ts'], end + 0.0001) if e['ev'] == 'binder_return']
    comp = next((e for e in comps if e['f']['name'] == 'BR_TRANSACTION_COMPLETE'), None)
    back = m.find(S, 'sched_switch', after=sw['ts'] if sw else t['ts'], before=end + 0.001,
                  pred=lambda e: e['f'].get('next_pid') == S) if sw else None
    srcs = [snip('binder.c', [r'static int binder_thread_read\(', r'case BINDER_WORK_TRANSACTION_COMPLETE:'], after=12,
                 hl=[r'BR_TRANSACTION_COMPLETE']),
            snip('binder.c', [r'static int binder_thread_read\(', r'trace_binder_wait_for_work'], before=4, after=24,
                 hl=[r'wait_event_freezable', r'binder_unlock'])]
    evs = [wfw and wfw['i'], sw and sw['i'], back and back['i'], comp and comp['i']]
    if sw and sw['f'].get('prev_state', '').startswith('R'):
        gap = ((back['ts'] if back else end) - sw['ts']) * 1e6
        c.add(S, 'sched', '%s is preempted by the thread it just woke' % c.tname(S),
              'This is not the textbook path. The <b>sync</b> wakeup let the scheduler switch straight to %s on '
              '<b>the same CPU</b> (CPU%d), before %s even reached its wait: it was switched out still runnable '
              '(state <b>%s</b>), not sleeping. It sat in the run queue for %.0f µs. By the time it ran again, the '
              'reply was already on its todo list, so a single read returned <b>BR_TRANSACTION_COMPLETE and BR_REPLY '
              'together</b> and it never slept in <code>wait_event_freezable()</code> at all.'
              % (sw['f'].get('next_comm'), sw['cpu'], c.tname(S), sw['f'].get('prev_state'), gap),
              [('switched out', '%s µs, state %s → %s' % (c.us(sw['ts']), sw['f'].get('prev_state'), sw['f'].get('next_comm'))),
               ('ran again', '%s µs on CPU%d' % (c.us(back['ts']), back['cpu']) if back else None),
               ('returns read together', ', '.join(e['f']['name'] for e in comps))],
              srcs, evs, sw['ts'])
    else:
        c.add(S, 'sched', '%s gets BR_TRANSACTION_COMPLETE, then sleeps' % c.tname(S),
              'The sender reads back <code>BR_TRANSACTION_COMPLETE</code>. libbinder\'s <code>waitForResponse()</code> '
              'loops and calls <code>ioctl()</code> again. With nothing on its todo list, <code>binder_thread_read()</code> '
              'calls <code>wait_event_freezable()</code> on the <b>thread\'s</b> wait queue (it has a transaction '
              'outstanding, so <code>transaction_stack=1</code>), and the scheduler switches it out with state <b>S</b> '
              '(interruptible sleep). It uses no CPU until the reply arrives.',
              [('wait_for_work', wfw['body'] if wfw else None),
               ('switched out', '%s µs, state %s → %s' % (c.us(sw['ts']), sw['f'].get('prev_state'), sw['f'].get('next_comm'))
                if sw else 'never switched out: the reply arrived while it was still on the CPU')],
              srcs, evs, comp['ts'] if comp else t['ts'])


def receiver_wakes(c, t, reply=False):
    m = c.m
    R = t['to_tid']
    if not R:
        return
    wake = next((e for e in m.events if e['ev'] == 'sched_wakeup' and e['f'].get('pid') == R
                 and t['ts'] <= e['ts'] <= t['ts_recv']), None)
    run = None
    if wake:
        run = next((e for e in m.events if e['ev'] == 'sched_switch' and e['f'].get('next_pid') == R
                    and wake['ts'] <= e['ts'] <= t['ts_recv']), None)
    ret = m.find(R, 'binder_return', after=t['ts_recv'], before=t['ts_recv'] + 0.001,
                 pred=lambda e: e['f']['name'] in ('BR_TRANSACTION', 'BR_REPLY'))
    lat = (run['ts'] - wake['ts']) * 1e6 if run and wake else None
    sender_pid = c.pid_of(t['from_tid'])
    dev = ctx_of(t)
    tm = c.binder_map(c.pid_of(R), dev)
    if not reply:
        ni = c.node_info(c.pid_of(R), t['node'], dev)
        btd = parcel.binder_transaction_data(
            target='ptr %s (node->ptr: the BBinder\'s weak-ref address)' % ni['ptr'] if ni else 'node->ptr',
            cookie='%s (node->cookie: the BBinder* itself)' % ni['cookie'] if ni else 'node->cookie',
            code='%d' % t['code'], flags='0x%x' % t['flags'],
            sender_pid='%d (%s), filled in by the kernel, cannot be forged' % (sender_pid, c.pname(sender_pid)),
            sender_euid='set by the kernel from the sender\'s credentials',
            data_size=str(t['data_size']), offsets_size=str(t['offsets_size']),
            buffer='kernel buffer + user_buffer_offset → address inside %s' % (
                '%s-%s' % (tm['start'], tm['end']) if tm else 'the receiver\'s mmap'),
            offsets='buffer + ALIGN(data_size, 8)')
        c.add(R, 'kernel', '%s wakes up and gets BR_TRANSACTION' % c.tname(R),
              '%s was blocked inside its own <code>ioctl()</code> in <code>binder_thread_read()</code>. '
              'It wakes, takes the work item and fills in a <code>binder_transaction_data</code> for userspace. '
              '<code>target.ptr</code>/<code>cookie</code> come from the node and tell libbinder <b>which object</b> '
              '(a BBinder pointer in this process). <b>sender_pid/euid are written by the kernel</b>: this is what '
              '<code>Binder.getCallingPid()</code>/<code>getCallingUid()</code> later return, and why permission checks can '
              'trust them. <code>data.ptr.buffer</code> is just the buffer\'s address inside this process\'s own '
              'read-only binder mapping, so nothing is copied again.' % c.tlabel(R)
              + (' The scheduler took <b>%.1f µs</b> from wakeup to actually running it.' % lat if lat is not None else ''),
              [('woken at', '%s µs' % c.us(wake['ts']) if wake else None),
               ('running at', '%s µs on CPU%d' % (c.us(run['ts']), run['cpu']) if run else None),
               ('wakeup latency', '%.1f µs' % lat if lat is not None else None),
               ('return cmd', '%s (0x%08x)' % (ret['f']['name'], ret['f']['cmd']) if ret else None)],
              [snip('binder.c', [r'static int binder_thread_read\(', r'cmd = BR_TRANSACTION;'], before=13, after=42,
                    hl=[r'tr\.target\.ptr', r'tr\.cookie', r'sender_pid', r'sender_euid', r'user_buffer_offset',
                        r'copy_to_user', r'put_user'])],
              [wake and wake['i'], run and run['i'], t['ev_recv'], ret and ret['i']],
              t['ts_recv'], extra={'struct': {'name': 'binder_transaction_data (as delivered with BR_TRANSACTION)', 'fields': btd}})
    else:
        c.add(R, 'kernel', '%s wakes up with BR_REPLY' % c.tname(R),
              'The blocked caller wakes in <code>binder_thread_read()</code>, finds the reply on its <b>own thread</b> todo '
              'list and gets <code>BR_REPLY</code>. The reply data (%s bytes) is already sitting in this process\'s '
              'mapping%s.' % (t['data_size'], ' (%s-%s)' % (tm['start'], tm['end']) if tm else '')
              + (' Wakeup to running took <b>%.1f µs</b>.' % lat if lat is not None else ''),
              [('woken at', '%s µs' % c.us(wake['ts']) if wake else None),
               ('running at', '%s µs on CPU%d' % (c.us(run['ts']), run['cpu']) if run else None),
               ('return cmd', '%s (0x%08x)' % (ret['f']['name'], ret['f']['cmd']) if ret else None)],
              [snip('binder.c', [r'static int binder_thread_read\(', r'cmd = BR_REPLY;'], before=3, after=3, hl=[r'BR_REPLY'])],
              [wake and wake['i'], run and run['i'], t['ev_recv'], ret and ret['i']], t['ts_recv'])


def reply_freed(c, t):
    """The receiver of a buffer frees it later with BC_FREE_BUFFER."""
    if t.get('ev_free') is None:
        return
    e = c.m.events[t['ev_free']]
    c.add(e['tid'], 'kernel', 'BC_FREE_BUFFER releases transaction %d\'s buffer (%s bytes)' % (t['id'], t['data_size']),
          'The buffer in the receiver\'s mapping stays allocated until the receiver says it is done. libbinder does that '
          'from <code>freeBuffer()</code> when the Parcel that pointed at it is destroyed or recycled. The command is '
          '<b>queued</b> in <code>mOut</code> and sent with the next ioctl.',
          [('freed by', c.tlabel(e['tid'])), ('at', '%s µs' % c.us(e['ts']))],
          [snip('binder.c', r'case BC_FREE_BUFFER: \{', after=30, hl=[r'binder_free_buf', r'binder_buffer_lookup']),
           snip('IPCThreadState', r'void IPCThreadState::freeBuffer\(', after=14, hl=[r'BC_FREE_BUFFER'])],
          [t['ev_free']], e['ts'])


# ---- userspace pieces -------------------------------------------------------------------------

def client_user_send(c, t, hop):
    S = t['from_tid']
    p = c.probe or {}
    mode = c.req['kind']
    meth = c.req.get('method')
    mk = {s['name']: s for s in c.m.markers(S, t['ts'] - 0.05, t['ts'])}
    m_outer = next((s for n, s in mk.items() if not n.startswith('BinderProxy.transact')), None)
    m_tx = next((s for n, s in mk.items() if n.startswith('BinderProxy.transact')), None)
    stack = p.get('stack', [])
    gen = source.find_aidl_gen(p.get('descriptor') or '') if p.get('descriptor') else None
    gen_key = gen or 'IRgbLedService.gen'

    if mode == 'probe-app':
        c.add(S, 'app', 'App code calls RgbLedManager.%s(%s)' % (meth, ', '.join(c.req.get('argv', []))),
              'This is where an app enters. The app got the manager with '
              '<code>context.getSystemService(Context.RGB_LED_SERVICE)</code>; '
              '<code>SystemServiceRegistry</code> built it from <code>ServiceManager.getService("rgbled")</code>, a '
              '<b>BinderProxy</b> for handle %s. The probe here makes exactly the same call, from %s.' % (
                  hop.get('handle'), c.tlabel(S)),
              [('Java stack at transact()', '\n'.join(stack[:4]) if stack else None)],
              [snip('RgbLedManager', r'public [\w@ .\[\]]*\b%s\(' % meth, brace=True, hl=[r'mService\.']),
               snip('IRgbLedService.gen' if False else 'frameworks/base/core/java/android/app/SystemServiceRegistry.java',
                    r'registerService\(Context\.RGB_LED_SERVICE', after=8, hl=[r'getService'],
                    title='how apps get the manager')],
              [m_outer and m_outer['ev']], m_outer['t0'] if m_outer else t['ts'])
    if mode in ('probe-app', 'probe-aidl'):
        writes = source.proxy_writes(gen_key, meth, '_data')
        fields = parcel.annotate_aidl_request(bytes.fromhex(p.get('request', '')), writes)
        c.add(S, 'aidl-proxy', 'Generated %s.Stub.Proxy.%s() builds the Parcel (%d bytes)' % (
            (p.get('descriptor') or '').split('.')[-1], meth, len(bytes.fromhex(p.get('request', '')))),
              'The AIDL compiler generated this proxy at build time. It writes an <b>interface token</b> (a StrictMode '
              'header plus the descriptor string, which the other side checks with <code>enforceInterface()</code>), then '
              'each argument in order. The <b>transaction code</b> is just the method\'s position in the .aidl file: '
              '<code>FIRST_CALL_TRANSACTION + %d = %d</code>. These are the <b>exact bytes</b> that were sent, '
              'captured from <code>Parcel.marshall()</code> at transact time.' % (t['code'] - 1, t['code']),
              [('descriptor', p.get('descriptor')), ('code', '%d = %s' % (t['code'], meth)),
               ('Parcel size', '%d bytes' % (len(p.get('request', '')) // 2))],
              [snip(gen_key, r'public [\w.<>\[\]]+ %s\(' % meth, brace=True,
                    hl=[r'_data\.write', r'mRemote\.transact', r'_reply\.read']),
               snip(gen_key, r'static final int TRANSACTION_%s\b' % meth, before=0, after=0, title='the code'),
               snip('Parcel.cpp', r'status_t Parcel::writeInterfaceToken', brace=True, hl=[r'writeInt32', r'writeString16'],
                    title='native writeInterfaceToken (reached via JNI from Parcel.java)')],
              [], t['ts'] - 0.0001 if not m_tx else m_tx['t0'],
              extra={'parcel': {'title': 'Request Parcel (exact bytes)', 'hex': p.get('request', ''), 'fields': fields}})
    elif mode == 'probe-raw':
        fields = [{'off': 0, 'len': len(p.get('request', '')) // 2, 'label': 'hand-built Parcel', 'value': '', 'kind': 'rest'}]
        c.add(S, 'app', 'A hand-built Parcel for code %d (0x%x)' % (t['code'], t['code']),
              'No generated proxy here: the probe writes the interface token (only for normal method codes) and the raw '
              'arguments, then calls <code>IBinder.transact()</code> directly, just like <code>service call</code>.',
              [('code', '%d = %s' % (t['code'], hop.get('code_name')))], [], [], t['ts'] - 0.0001,
              extra={'parcel': {'title': 'Request Parcel (exact bytes)', 'hex': p.get('request', ''), 'fields': fields}})
    elif mode == 'native':
        req_b, writes = parcel.aidl_from_service_call(c.req.get('descriptor', ''), c.req.get('argv', []))
        fields = parcel.annotate_aidl_request(req_b, writes)
        c.add(S, 'native-cli', '`service call %s %s %s` builds the Parcel in C++' % (
            c.req.get('service'), t['code'], ' '.join(c.req.get('argv', []))),
              '<code>/system/bin/service</code> is a native client. It already looked the service up (see the earlier '
              'transactions to servicemanager), wrote the interface token with <code>Parcel::writeInterfaceToken()</code>, '
              'then each <code>i32</code>/<code>s16</code> argument, and calls <code>service->transact(code, data, &reply)</code>. '
              'There is no Java and no JNI on this side. Bytes are rebuilt exactly as service.cpp writes them; the size '
              'matches the kernel\'s data_size=%s.' % t['data_size'],
              [('Parcel size', '%d bytes (kernel saw %s)' % (len(req_b), t['data_size']))],
              [snip('service.cpp', r'service->transact\(code, data, &reply\)', before=30, after=4,
                    hl=[r'writeInterfaceToken', r'writeInt32', r'writeString16', r'transact\('])],
              [], t['ts'] - 0.0001,
              extra={'parcel': {'title': 'Request Parcel (rebuilt; size verified against the kernel)', 'hex': req_b.hex(),
                                'fields': fields}})

    if mode == 'record':
        meth = hop.get('code_name')
        st = next((x for x in getattr(c, 'record_stacks', []) if x['call'].endswith('.' + str(meth))), None)
        c.add(S, 'app', 'The app calls %s (thread %s)' % (meth, c.tname(S)),
              'This transaction was sent by the real app while you used it. The Java stack below is from '
              '<code>am trace-ipc</code>, which records the call sites of every outgoing binder call; it is matched to this '
              'transaction by method name and was seen %s time(s) during the recording.' % (st['count'] if st else '?'),
              [('Java stack (am trace-ipc)', '\n'.join(st['frames'][:14]) if st else 'no matching stack (native caller, '
                                                                                    'or not an AIDL proxy call)')],
              [snip('RgbLedManager', r'public [\w@ .\[\]]*\b%s\(' % meth, brace=True, hl=[r'mService\.'])]
              if st and 'rgbled' in st['call'] else [], [], t['ts'] - 0.00005)
    if mode.startswith('probe') or mode == 'record':
        c.add(S, 'java', 'BinderProxy.transact() → transactNative()',
              'The proxy\'s <code>mRemote</code> is an <code>android.os.BinderProxy</code>: a Java object wrapping a native '
              '<code>BpBinder</code>, which in turn just holds the <b>handle number</b> (%s). '
              '<code>transact()</code> checks the Parcel size (and logs a warning for ones over 800 KB) and goes native.'
              % hop.get('handle'),
              [('marker', m_tx['name'] if m_tx else None), ('time inside transact()', '%.1f µs (measured by the probe with System.nanoTime)'
                                                             % (p['transactNs'] / 1000.0) if p.get('transactNs') else None)],
              [snip('Binder.java', [r'final class BinderProxy', r'public boolean transact\(int code'], brace=True,
                    hl=[r'transactNative']),
               snip('Binder.java', r'public native boolean transactNative', after=1)],
              [m_tx and m_tx['ev']], m_tx['t0'] if m_tx else t['ts'])
        c.add(S, 'jni', 'JNI: android_os_BinderProxy_transact()',
              'Unwraps the Java Parcels to native <code>Parcel*</code>s (no copy: a Java Parcel is a thin wrapper around a '
              'native one), gets the <code>BpBinder*</code> stored in the BinderProxy, and calls <code>target->transact()</code>.',
              [], [snip('jni_binder', r'static jboolean android_os_BinderProxy_transact', brace=True, cap=64,
                        hl=[r'target->transact', r'parcelForJavaObject', r'gBinderProxyOffsets\.mObject'])],
              [], m_tx['t0'] if m_tx else t['ts'])
    c.add(S, 'libbinder', 'BpBinder::transact() → IPCThreadState::transact(handle=%s)' % hop.get('handle'),
          '<code>BpBinder</code> is the native proxy; its only real state is <code>mHandle</code>. '
          '<code>IPCThreadState</code> is a per-thread object (thread-local storage) that owns the two buffers '
          '<code>mOut</code> (commands to the driver) and <code>mIn</code> (returns from it). <code>transact()</code> adds '
          '<code>TF_ACCEPT_FDS</code> (0x10, which is why the kernel trace shows flags=0x10), writes the command and '
          'waits for the response.',
          [('handle', hop.get('handle')), ('flags passed down', '0x%x' % t['flags'])],
          [snip('BpBinder', r'status_t BpBinder::transact\(', brace=True, hl=[r'IPCThreadState::self\(\)->transact']),
           snip('IPCThreadState', r'status_t IPCThreadState::transact\(', brace=True, cap=60,
                hl=[r'TF_ACCEPT_FDS', r'writeTransactionData\(BC_TRANSACTION', r'waitForResponse'])],
          [], None)
    btd = parcel.binder_transaction_data(
        target='handle %s' % hop.get('handle'), cookie='0', code='%d (0x%x)' % (t['code'], t['code']),
        flags='0x%x' % t['flags'], sender_pid='0 (kernel fills it in)', sender_euid='0 (kernel fills it in)',
        data_size=str(t['data_size']), offsets_size=str(t['offsets_size']),
        buffer='Parcel data pointer (sender heap)', offsets='Parcel objects array (sender heap)')
    c.add(S, 'libbinder', 'writeTransactionData(): BC_TRANSACTION + binder_transaction_data into mOut',
          'The Parcel is <b>not</b> copied here. <code>binder_transaction_data</code> only carries <b>pointers</b> to the '
          'Parcel\'s data and its offsets array (the positions of any binder objects), plus their sizes. The kernel will '
          'copy from those pointers in a moment.',
          [], [snip('IPCThreadState', r'status_t IPCThreadState::writeTransactionData', brace=True,
                    hl=[r'tr\.target\.handle', r'tr\.code', r'tr\.data_size', r'tr\.data\.ptr\.buffer', r'mOut\.write'])],
          [], None, extra={'struct': {'name': 'binder_transaction_data (written by the sender)', 'fields': btd}})


def java_receiver(c, t, hop):
    R = t['to_tid']
    rp = c.pid_of(R)
    end = c.m.txns[t['reply_id']]['ts'] if t['reply_id'] else t['ts_recv'] + 0.05
    mk = c.m.markers(R, t['ts_recv'], end)
    mk = [s for s in mk if s['t0'] >= t['ts_recv']]
    top = mk[0] if mk else None
    impl_cls = top['name'].rsplit(':', 1)[0] if top and ':' in top['name'] else None
    done = c.m.find(R, 'binder_ioctl_done', after=t['ts_recv'], before=end)
    tin = top['t0'] if top else None
    c.add(R, 'libbinder', 'IPCThreadState::executeCommand(BR_TRANSACTION)',
          'Binder threads in %s spend their life in <code>joinThreadPool()</code> → <code>getAndExecuteCommand()</code>. '
          'For <code>BR_TRANSACTION</code> it points a Parcel <b>at the mapped buffer</b> '
          '(<code>ipcSetDataReference</code>, no copy), records the caller\'s pid/uid in the thread state (for '
          '<code>getCallingUid()</code>), and calls <code>BBinder::transact()</code> on the object from '
          '<code>tr.cookie</code>.' % c.pname(rp),
          [('thread', c.tlabel(R)), ('calling pid', '%d (%s)' % (c.pid_of(t['from_tid']), c.pname(c.pid_of(t['from_tid']))))],
          [snip('IPCThreadState', [r'status_t IPCThreadState::executeCommand', r'case BR_TRANSACTION:'], after=70,
                hl=[r'ipcSetDataReference', r'mCallingPid', r'mCallingUid', r'->transact\(', r'sendReply']),
           snip('Binder.cpp', r'status_t BBinder::transact\(', brace=True, hl=[r'onTransact', r'PING_TRANSACTION'])],
          [done and done['i']], done['ts'] if done else None)
    c.add(R, 'jni', 'JavaBBinder::onTransact() calls up into Java',
          'Every Java <code>Binder</code> object has a native <code>JavaBBinder</code> twin; that is what the kernel\'s '
          'node points at. Its <code>onTransact()</code> attaches to the VM and calls the Java method '
          '<code>Binder.execTransact(code, dataPtr, replyPtr, flags)</code> through JNI.',
          [], [snip('jni_binder', r'virtual status_t onTransact\(', brace=True, cap=40, hl=[r'CallBooleanMethod', r'mExecTransact'])],
          [], None)
    c.add(R, 'java', 'Binder.execTransact() → onTransact()',
          'Wraps the native Parcels as Java Parcels and calls the generated <code>Stub.onTransact()</code>. With IPC tracing '
          'on (<code>am trace-ipc start</code>, which this capture used) it writes a trace marker named after the class and '
          'code. The marker in the evidence below is real and was written by system_server itself.',
          [('trace marker', top['name'] if top else None),
           ('time in Java onTransact', '%.1f µs' % ((top['t1'] - top['t0']) * 1e6) if top and top['t1'] else None)],
          [snip('Binder.java', r'private boolean execTransact', brace=True, cap=40, hl=[r'onTransact\(code', r'traceBegin'])],
          [top and top['ev']], top['t0'] if top else t['ts_recv'])
    meth = hop.get('code_name')
    gen = source.find_aidl_gen((c.probe or {}).get('descriptor') or c.req.get('descriptor') or '') or 'IRgbLedService.gen'
    if t['code'] <= 0x00ffffff and not re.match(r'^\w+$', str(meth)):
        c.add(R, 'aidl-stub', '%s.onTransact(code %d)' % (impl_cls or c.pname(rp), t['code']),
              'The generated Stub for this interface switches on the code and calls the implementation. (The method name '
              'is not resolved here because this interface\'s generated code is not mapped by the explorer.)',
              [('implementation class (from trace marker)', impl_cls)], [], [], tin)
    elif t['code'] <= 0x00ffffff:
        c.add(R, 'aidl-stub', 'Generated Stub.onTransact(): case TRANSACTION_%s' % meth,
              'A plain <code>switch(code)</code>. <code>enforceInterface()</code> reads the interface token and throws if '
              'the descriptor does not match (so a Parcel meant for another interface cannot be misread), then it reads '
              'the arguments in the same order the proxy wrote them and calls the real method.',
              [('code', '%d → %s' % (t['code'], meth))],
              [snip(gen, r'case TRANSACTION_%s:' % meth, brace=True, hl=[r'enforceInterface', r'read\w+\(', r'this\.%s' % meth,
                                                                       r'writeNoException', r'reply\.write'])],
              [], tin)
        impl = source.find_java_class(impl_cls) if impl_cls else None
        if impl:
            c.add(R, 'service', '%s.%s()' % (impl_cls.split('.')[-1], meth),
                  'The actual service implementation, in %s. %s' % (c.pname(rp),
                      'This one checks the channel and calls <b>the HAL</b> over a second binder hop (hwbinder), shown next.'
                      if 'rgbled' in impl_cls and t['children'] else ''),
                  [('class', impl_cls)],
                  [snip(impl, r'public [\w.<>\[\]]+ %s\(' % meth, brace=True, hl=[r'hal\.', r'enforce', r'check'])],
                  [], tin)
    else:
        c.add(R, 'libbinder', 'Special code handled before your code: %s' % meth,
              'Codes built from letters (<code>_PNG</code>, <code>_NTF</code>, <code>_DMP</code>...) are caught by '
              '<code>BBinder::transact()</code> / <code>Binder.onTransact()</code> before the generated switch.',
              [], [snip('Binder.cpp', r'status_t BBinder::onTransact\(', brace=True, cap=60)], [], t['ts_recv'])
    return mk


def java_reply(c, t, hop, mk):
    R = t['to_tid']
    rep = c.m.txns.get(t['reply_id'])
    if not rep:
        return
    top = mk[0] if mk else None
    p = c.probe or {}
    reads = source.proxy_writes(source.find_aidl_gen(p.get('descriptor') or '') or 'IRgbLedService.gen',
                                hop.get('code_name'), '_reply') if re.match(r'^\w+$', str(hop.get('code_name'))) else []
    rb = bytes.fromhex(p.get('reply', '')) if p.get('reply') and hop.get('depth') == 0 else None
    if rb is None and c.native_out and hop.get('depth') == 0:
        rb = parcel.reply_from_service_output(c.native_out)
    c.add(R, 'aidl-stub', 'Stub writes the reply: writeNoException() + the return value',
          'Back in <code>onTransact()</code>: an int32 0 means "no exception", followed by the result. If the service had '
          'thrown, the exception code and message would go here instead, and the client\'s '
          '<code>readException()</code> would re-throw it. Java exceptions cross process boundaries this way.',
          [('Java slice ended', '%s µs' % c.us(top['t1']) if top and top.get('t1') else None)],
          [snip('Parcel.java', r'public final void writeNoException\(', brace=True, cap=30)],
          [top and top['ev']], top['t1'] if top and top.get('t1') else rep['ts'],
          extra={'parcel': {'title': 'Reply Parcel (exact bytes)', 'hex': rb.hex(),
                            'fields': parcel.annotate_aidl_reply(rb, reads)}} if rb else None)
    c.add(R, 'libbinder', 'sendReply(): BC_REPLY',
          '<code>executeCommand()</code> sends the reply with <code>BC_REPLY</code> and waits only for '
          '<code>BR_TRANSACTION_COMPLETE</code> (not for an answer). The request buffer (transaction %d) is freed '
          'when the request Parcel goes out of scope: <code>BC_FREE_BUFFER</code>.' % t['id'],
          [('reply data_size', rep['data_size'])],
          [snip('IPCThreadState', r'status_t IPCThreadState::sendReply', brace=True, hl=[r'BC_REPLY', r'waitForResponse'])],
          [], rep['ts'])


def hidl_sender(c, t, hop):
    S = t['from_tid']
    hm = hop.get('code_name')
    writes = source.proxy_writes('IRgbLed.gen', hm, '_hidl_request')
    vals = [str(v) for v in c.req.get('argv_int', [])]
    rebuilt = parcel.hidl_request(writes, 'vendor.lineage.rgbled@1.0::IRgbLed', vals) if writes else None
    ok = rebuilt and len(rebuilt[0]) == t['data_size']
    c.add(S, 'hidl-proxy', 'Generated HIDL Java proxy IRgbLed.Proxy.%s() → HwBinder transact(%d)' % (hm, t['code']),
          'system_server talks to the vendor HAL over <b>hwbinder</b> (<code>/dev/hwbinder</code>): the same kernel '
          'driver with a <b>separate context</b>, so it has its own context manager (hwservicemanager), its own handle '
          'numbers and its own mmap. HIDL numbers methods from 1 in .hal order: <code>%s</code> is #%d. '
          'HwParcel uses its own wire format (C-string token, scatter-gather buffers for strings and vectors).%s'
          % (hm, t['code'], ' The rebuilt bytes below match the kernel\'s data_size=%d.' % t['data_size'] if ok else ''),
          [('HAL method', '%d = %s' % (t['code'], hm)), ('handle (system_server\'s hwbinder ref)', hop.get('handle'))],
          [snip('IRgbLed.gen', r'public [\w.<>\[\]]+ %s\(' % hm, brace=True,
                hl=[r'_hidl_request\.write', r'mRemote\.transact', r'_hidl_reply\.']),
           snip('IRgbLed.hal', r'\b%s\(' % hm, after=1, title='IRgbLed.hal'),
           snip('HwRemoteBinder.java', r'public native final void transact', after=3),
           snip('jni_hwremote', r'static void JHwRemoteBinder_native_transact', brace=True, cap=50, hl=[r'->transact\(']),
           snip('hw_BpHwBinder', r'status_t BpHwBinder::transact\(', brace=True, hl=[r'IPCThreadState::self\(\)->transact']),
           snip('hw_IPCThreadState', r'status_t IPCThreadState::transact\(', brace=True, cap=40, hl=[r'BC_TRANSACTION_SG'])],
          [], t['ts'],
          extra={'parcel': {'title': 'HIDL request Parcel (rebuilt from the generated proxy\'s writes, argument values as '
                                      'passed through by RgbLedService; size %s)' % (
              'matches the kernel\'s data_size' if ok else 'NOT verified against the kernel'),
              'hex': rebuilt[0].hex(), 'fields': rebuilt[1]}} if rebuilt else None)


def hal_receiver(c, t, hop):
    R = t['to_tid']
    hm = hop.get('code_name')
    c.add(R, 'libhwbinder', 'HAL thread: hardware::IPCThreadState::executeCommand(BR_TRANSACTION)',
          'The HAL process (%s) runs <code>joinRpcThreadpool()</code>. It was configured with '
          '<b>one</b> thread (<code>configureRpcThreadpool(1, true)</code>), so all calls to this HAL are serialised on it. '
          'libhwbinder is a fork of libbinder with the same structure.' % c.pname(c.pid_of(R)),
          [('thread', c.tlabel(R))],
          [snip('hal_service.cpp', r'int main\(', brace=True, hl=[r'configureRpcThreadpool', r'registerAsService', r'joinRpcThreadpool']),
           snip('hw_IPCThreadState', [r'status_t IPCThreadState::executeCommand', r'case BR_TRANSACTION:'], after=60,
                hl=[r'ipcSetDataReference', r'->transact\(', r'sendReply']),
           snip('hw_Binder', r'status_t BHwBinder::transact\(', brace=True, hl=[r'onTransact'])],
          [], t['ts_recv'])
    c.add(R, 'hidl-stub', 'Generated BnHwRgbLed::onTransact(): case %d /* %s */' % (t['code'], hm),
          'hidl-gen wrote this C++ stub. It checks the interface token, reads the arguments, calls your implementation, and '
          'writes the result through a callback (<code>_hidl_cb</code>) that sends the reply.',
          [], [snip('RgbLedAll.cpp', r'case %d /\* %s \*/:' % (t['code'], hm), after=12, hl=[r'_hidl_%s' % hm]),
               snip('RgbLedAll.cpp', r'::android::status_t BnHwRgbLed::_hidl_%s\(' % hm, brace=True, cap=70,
                    hl=[r'enforceInterface', r'readInt32|readUint8|readEmbedded|readBuffer', r'->%s\(' % hm,
                        r'writeStatus', r'_hidl_cb'])],
          [], t['ts_recv'])
    end = c.m.txns[t['reply_id']]['ts'] if t['reply_id'] else t['ts_recv'] + 0.02
    sc = [s for s in c.m.syscalls(R, t['ts_recv'], end) if s['name'] not in ('ioctl',)]
    st = [l for l in c.hal_strace if not l['call'].startswith(('ioctl', 'futex'))]
    # line strace detail up with the ftrace syscalls by order and name
    k = 0
    for s in sc:
        j = next((j for j in range(k, len(st)) if st[j]['name'] == s['name']), None)
        if j is not None:
            s['detail'] = st[j]['call']
            k = j + 1
    path = next((s['detail'] for s in sc if s.get('detail') and s['name'] == 'openat'), None)
    c.add(R, 'hal', 'RgbLed::%s() — the real work' % hm,
          'Your HAL implementation. For LED state it reads or writes sysfs files under <code>/sys/class/leds/</code> with '
          'plain <code>open/read/write/close</code> system calls, so it leaves binder entirely and talks to the LED '
          'driver through the VFS. %s' % ('' if c.hal_strace else
                                          '<i>Turn on "strace HAL" to see the file paths and the bytes read/written '
                                          '(it slows the HAL down while attached).</i>'),
          [('syscalls', '\n'.join(s['detail'] if s.get('detail') else '%s(%s) = %s' % (s['name'], ', '.join(s['args'][:3]), s['ret'])
                                  for s in sc) or None)],
          [snip('RgbLed.cpp', r'RgbLed::%s\(' % hm, brace=True, hl=[r'ReadFileToString|WriteStringToFile|writeNode|nodePath']),
           snip('RgbLed.cpp', r'std::string nodePath', brace=True)],
          [s['ev'] for s in sc], sc[0]['t0'] if sc else t['ts_recv'])
    if sc:
        rd = any(s['name'] == 'read' for s in sc)
        wr = any(s['name'] == 'write' for s in sc)
        c.add(R, 'led', 'sysfs → LED class → qpnp LED driver',
              'The <code>%s</code> on a sysfs attribute lands in the LED class driver. %s The LED hardware is on the PMI8994 '
              'PMIC, which the qpnp driver programs over the SPMI bus.' % (
                  'read' if rd else 'write',
                  '<code>led_brightness_show()</code> calls <code>led_update_brightness()</code>, which on this device returns '
                  'the value the driver cached (<code>qpnp_led_get()</code>), formatted as text "N\\n".' if rd else
                  '<code>led_brightness_store()</code> parses the number and calls <code>led_set_brightness()</code>, which '
                  'reaches <code>qpnp_led_set()</code> and schedules the PMIC register write.'),
              [('file', path)],
              ([snip('led-class', r'static ssize_t led_brightness_show', brace=True, hl=[r'led_update_brightness', r'snprintf']),
                snip('led-class', r'static void led_update_brightness', brace=True, hl=[r'brightness_get']),
                snip('leds-qpnp', r'static enum led_brightness qpnp_led_get', brace=True)] if rd else []) +
              ([snip('led-class', r'static ssize_t led_brightness_store', brace=True, hl=[r'led_set_brightness', r'kstrtoul']),
                snip('leds-qpnp', r'static void qpnp_led_set\(', brace=True, cap=40, hl=[r'schedule_work', r'brightness'])]
               if wr else []),
              [], sc[0]['t0'])
    rep = c.m.txns.get(t['reply_id'])
    if rep:
        c.add(R, 'hidl-stub', 'HIDL reply via _hidl_cb → sendReply(BC_REPLY_SG)',
              'The stub writes a status word (0 = OK) and the return value, then libhwbinder sends '
              '<code>BC_REPLY_SG</code>. Reply size: %s bytes.' % rep['data_size'],
              [], [snip('hw_IPCThreadState', r'status_t IPCThreadState::sendReply', brace=True, hl=[r'BC_REPLY_SG'])],
              [], rep['ts'])


def native_receiver_generic(c, t, hop):
    R = t['to_tid']
    rp = c.pid_of(R)
    if rp == c.sm_pid:
        c.add(R, 'svcmgr', 'servicemanager: svcmgr_handler(%s)' % hop.get('code_name'),
              'servicemanager is a small C program with its own tiny binder library (it predates libbinder\'s use here). '
              '<code>binder_loop()</code> reads <code>BR_TRANSACTION</code>, <code>svcmgr_handler()</code> looks the name up '
              'in a linked list and answers with <code>bio_put_ref(reply, handle)</code>: a <b>handle object</b>. The '
              'kernel then translates that handle into a new one for the caller (see the translation step).',
              [('code', '%d = %s' % (t['code'], hop.get('code_name')))],
              [snip('service_manager.c', r'int svcmgr_handler\(', brace=True, cap=80,
                    hl=[r'SVC_MGR_CHECK_SERVICE', r'do_find_service', r'bio_put_ref', r'PING_TRANSACTION']),
               snip('sm_binder.c', r'void binder_loop\(', brace=True)], [], t['ts_recv'])
    else:
        c.add(R, 'libbinder', '%s handles code %s' % (c.pname(rp), hop.get('code_name')),
              'A native process: libbinder\'s <code>executeCommand()</code> calls <code>BBinder::transact()</code> → '
              'the object\'s <code>onTransact()</code>.',
              [('thread', c.tlabel(R))],
              [snip('IPCThreadState', [r'status_t IPCThreadState::executeCommand', r'case BR_TRANSACTION:'], after=40,
                    hl=[r'->transact\('])], [], t['ts_recv'])


# ---- one hop (request → nested hops → reply) --------------------------------------------------

def receiver_class(c, t):
    """Java implementation class, from the Binder.execTransact trace marker on the serving thread."""
    if not t['to_tid'] or not t['ts_recv']:
        return None
    end = c.m.txns[t['reply_id']]['ts'] if t['reply_id'] in c.m.txns else t['ts_recv'] + 0.05
    for s in c.m.markers(t['to_tid'], t['ts_recv'], end):
        if s['t0'] >= t['ts_recv'] and ':' in s['name']:
            return s['name'].rsplit(':', 1)[0]
    return None


def name_for(c, t, depth):
    hw = ctx_of(t) == 'hwbinder'
    if t['code'] > 0x00ffffff:
        return code_name(t['code'])
    if t['to_proc'] == c.sm_pid:
        return code_name(t['code'], to_sm=True)
    if hw:
        if 'rgbled' in c.pname(t['to_proc']):
            return code_name(t['code'], hw=True, hal_methods=c.hal)
        return 'HIDL method #%d' % t['code']
    if depth == 0 and c.req.get('kind') != 'record' and c.req.get('method'):
        return c.req['method']
    cls = receiver_class(c, t)
    if (depth == 0 and c.req.get('service') == 'rgbled') or (cls and 'rgbled' in cls):
        return code_name(t['code'], methods=c.aidl)
    if cls:
        return '%s #%d' % (cls.split('.')[-1], t['code'])
    return 'code %d' % t['code']


def hop(c, tid_, depth=0, handle=None):
    t = c.m.txns[tid_]
    hw = ctx_of(t) == 'hwbinder'
    to_sm = t['to_proc'] == c.sm_pid
    cname = name_for(c, t, depth)
    if handle is None:
        handle = c.handle_for(c.pid_of(t['from_tid']), t['node'], ctx_of(t))
    h = {'depth': depth, 'handle': handle, 'code_name': cname}
    c.add(t['from_tid'], 'hop', 'Hop %s: %s → %s over %s, code %s' % (
        depth + 1, c.pname(c.pid_of(t['from_tid'])), c.pname(t['to_proc']), '/dev/' + ctx_of(t), cname),
          '', [], [], [], t['ts'], extra={'divider': True, 'hop_depth': depth})
    if depth == 0:
        client_user_send(c, t, h)
    elif hw and c.is_java(c.pid_of(t['from_tid'])):
        hidl_sender(c, t, h)
    kernel_send(c, t, h)
    sender_waits(c, t)
    receiver_wakes(c, t)
    rp = c.pid_of(t['to_tid']) if t['to_tid'] else t['to_proc']
    mk = None
    if c.is_java(rp) and not hw:
        mk = java_receiver(c, t, h)
    elif hw and 'rgbled' in c.pname(rp):
        hal_receiver(c, t, h)
    else:
        native_receiver_generic(c, t, h)
    if depth == 0 or not hw:
        pass
    for ch in t['children']:
        if ch in c.m.txns:
            hop(c, ch, depth + 1)
    if c.is_java(rp) and not hw:
        java_reply(c, t, h, mk)
    rep = c.m.txns.get(t['reply_id'])
    if rep:
        kernel_send(c, rep, h)
        receiver_wakes(c, rep, reply=True)
        if depth == 0:
            client_finish(c, t, rep, h)
        else:
            c.add(rep['to_tid'], 'libhwbinder' if hw else 'libbinder', '%s continues with the reply' % c.tname(rep['to_tid']),
                  '<code>waitForResponse()</code> sees <code>BR_REPLY</code>, points the reply Parcel at the buffer and returns '
                  'up the stack to the caller, which reads the result out of it.',
                  [], [snip('hw_IPCThreadState' if hw else 'IPCThreadState', [r'status_t IPCThreadState::waitForResponse', r'case BR_REPLY:'],
                            after=24, hl=[r'ipcSetDataReference'])], [], rep['ts_recv'])
        reply_freed(c, t)
        reply_freed(c, rep)


def client_finish(c, t, rep, h):
    S = t['from_tid']
    p = c.probe or {}
    mk = c.m.markers(S, rep['ts_recv'] or rep['ts'], (rep['ts_recv'] or rep['ts']) + 0.05)
    ends = [s for s in c.m.markers(S, t['ts'] - 0.05, (rep['ts_recv'] or rep['ts']) + 0.05) if s.get('t1')]
    last = max((s['t1'] for s in ends), default=None)
    c.add(S, 'libbinder', 'waitForResponse(): BR_REPLY → reply Parcel points into the client\'s mapping',
          'libbinder hands the reply Parcel a pointer into this process\'s own binder mapping plus a '
          '<code>freeBuffer</code> callback. When the Java Parcel is recycled, that callback queues '
          '<code>BC_FREE_BUFFER</code> for the next ioctl.',
          [], [snip('IPCThreadState', [r'status_t IPCThreadState::waitForResponse', r'case BR_REPLY:'], after=26,
                    hl=[r'ipcSetDataReference', r'freeBuffer'])], [], rep['ts_recv'])
    result = p.get('result') if p else None
    if c.native_out:
        result = c.native_out.strip()
    c.add(S, 'aidl-proxy' if c.req['kind'] in ('probe-app', 'probe-aidl') else 'app',
          'Back in the caller: readException(), read the result → %s' % (result if result is not None else '?'),
          'The generated proxy reads the exception header (re-throwing if the service threw), then the return value, '
          'recycles both Parcels and returns. End to end this call took <b>%.1f µs</b> from the first trace marker / '
          'send to the end.' % (((last or rep['ts_recv']) - c.base) * 1e6),
          [('result', result)], [], [], last or rep['ts_recv'])


# ---- lookup (servicemanager) hops shown compactly ----------------------------------------------

def lookup_hop(c, t):
    trs = [c.m.events[i] for i in (c.m.txns[t['reply_id']]['translations'] if t['reply_id'] and t['reply_id'] in c.m.txns else [])]
    hw = ctx_of(t) == 'hwbinder'
    cname = code_name(t['code'], hw=hw, to_sm=t['to_proc'] == c.sm_pid, methods=c.aidl, hal_methods=c.hal)
    vals = [('code', '%d (0x%x) = %s' % (t['code'], t['code'], cname)), ('to', '%s (pid %d)' % (c.pname(t['to_proc']), t['to_proc'])),
            ('data_size', t['data_size'])]
    for e in trs:
        vals.append(('handle translation in the reply', e['body']))
    what = {
        'PNG': 'A <b>ping</b> to handle 0. <code>ProcessState::getContextObject()</code> does this once to make sure '
               'servicemanager is alive before trusting handle 0.',
        'CHECK_SERVICE': 'Ask servicemanager for a service by name. The reply contains a <b>handle object</b>; the kernel '
                         'rewrote servicemanager\'s own handle into a fresh one for this process (see the translation line). '
                         'That number is what this process will use from now on.',
        'GET_SERVICE': 'Ask servicemanager for a service by name (Java ServiceManager.getService). The reply carries a handle '
                       'object that the kernel translates into this process\'s own numbering.',
        'NTF': '<b>INTERFACE_TRANSACTION</b> (<code>_NTF</code>): asks the object for its descriptor string. '
               '<code>service call</code> needs it to write the interface token.',
    }.get(cname, 'Transaction code %s.' % cname)
    srcs = []
    if cname == 'PNG':
        srcs.append(snip('ProcessState', r'IBinder::PING_TRANSACTION', before=20, after=4, hl=[r'PING_TRANSACTION']))
    if cname in ('CHECK_SERVICE', 'GET_SERVICE'):
        srcs.append(snip('service_manager.c', r'case SVC_MGR_CHECK_SERVICE:', before=1, after=10, hl=[r'do_find_service', r'bio_put_ref']))
        srcs.append(snip('binder.c', r'static int binder_translate_handle\(', brace=True, cap=60,
                         hl=[r'binder_get_ref_for_node', r'fp->handle', r'trace_binder_transaction_ref_to_ref']))
    if cname == 'NTF':
        srcs.append(snip('service.cpp', r'IBinder::INTERFACE_TRANSACTION', before=6, after=6))
    c.add(t['from_tid'], 'kernel' if cname != 'NTF' else 'libbinder', 'Setup call: %s → %s' % (cname, c.pname(t['to_proc'])),
          what, vals, srcs, [t['ev_send'], t.get('ev_recv')] + [e['i'] for e in trs], t['ts'], extra={'lookup': True})


# ---- entry point -------------------------------------------------------------------------------

def build(c):
    m = c.m
    kind = c.req['kind']
    if kind.startswith('probe'):
        tid = c.probe['tid']
        roots = [t for t in m.txns.values() if t['from_tid'] == tid and not t['reply']]
    else:
        tids = [t for t, cm in m.comm.items() if cm == 'service']
        roots = [t for t in m.txns.values() if t['from_tid'] in tids and not t['reply']]
    roots.sort(key=lambda t: t['ts'])
    if not roots:
        return {'error': 'No transactions from the client were found in the trace.'}
    want = c.req.get('code')
    main = next((t for t in reversed(roots) if t['code'] == want and t['to_proc'] != c.sm_pid), roots[-1])
    starts = [main['ts']]
    if kind.startswith('probe'):
        mk = m.markers(main['from_tid'], main['ts'] - 0.05, main['ts'])
        starts += [s['t0'] for s in mk]
    c.base = min([r['ts'] for r in roots] + starts)

    handle = None
    if kind.startswith('probe'):
        handle = c.handle_for(c.probe['pid'], main['node'], 'binder')
    else:
        for r in roots:
            rep = m.txns.get(r['reply_id'])
            for i in (rep['translations'] if rep else []):
                f = m.events[i]['f']
                if f.get('node') == main['node']:
                    handle = f.get('dest_desc')
    for r in roots:
        if r is not main and r['ts'] < main['ts']:
            lookup_hop(c, r)
    hop(c, main['id'], 0, handle)
    return assemble(c, main, roots)


def build_one(c, txn_id):
    """Journey for one transaction picked from a recording of a real app."""
    m = c.m
    main = m.txns[txn_id]
    c.base = main['ts'] - 0.0001
    pid = c.pid_of(main['from_tid'])
    handle = c.handle_for(pid, main['node'], ctx_of(main))
    if ctx_of(main) == 'binder' and main['to_proc'] == c.meta.get('system_server_pid'):
        pass
    c.req['method'] = code_name(main['code'], methods=c.aidl) if 'rgbled' in c.pname(main['to_proc']) or \
        any(ch for ch in main['children']) else None
    hop(c, main['id'], 0, handle)
    return assemble(c, main, [main])


def assemble(c, main, roots):
    m = c.m

    t0, t1 = m.tree_span(main['id'])
    t0 = min(t0, c.base)
    ends = [s['t1'] for s in m.markers(main['from_tid'], t0, t1 + 0.05) if s.get('t1')]
    t1 = max([t1] + ends) + 0.0002
    lanes = []
    tids = m.tree_threads(main['id'])
    for r in roots:
        if r['to_tid'] and r['to_tid'] not in tids:
            tids.append(r['to_tid'])
    for tid in tids:
        pid = c.pid_of(tid)
        lanes.append({
            'tid': tid, 'pid': pid, 'thread': c.tname(tid), 'proc': c.pname(pid),
            'states': [{'s': s['s'], 't0': c.us(s['t0']), 't1': c.us(s['t1'])} for s in m.thread_states(tid, t0, t1)],
            'markers': [{'name': s['name'], 't0': c.us(s['t0']), 't1': c.us(s['t1'] or t1), 'depth': s['depth']}
                        for s in m.markers(tid, t0, t1)],
            'syscalls': [{'name': s['name'], 't0': c.us(s['t0']), 't1': c.us(s['t1'] or s['t0']), 'ret': s['ret'],
                          'args': s['args'][:3], 'detail': s.get('detail')} for s in m.syscalls(tid, t0, t1)],
            'binder': [{'ev': e['ev'], 'ts': c.us(e['ts']), 'body': e['body']} for e in m.tid_events(tid, t0, t1)
                       if e['ev'].startswith('binder_') and e['ev'] not in ('binder_lock', 'binder_locked', 'binder_unlock')],
            'locks': _locks(m, tid, t0, t1, c),
        })
    flows = []
    for i in m.tree_ids(main['id']) + [r['id'] for r in roots if r is not main]:
        t = m.txns.get(i)
        if t and t['to_tid'] and t['ts_recv']:
            flows.append({'id': t['id'], 'from': t['from_tid'], 'to': t['to_tid'], 't0': c.us(t['ts']), 't1': c.us(t['ts_recv']),
                          'reply': t['reply'], 'code': t['code'], 'size': t['data_size'], 'dev': ctx_of(t)})
    wakes = []
    for e in m.events:
        if e['ev'] == 'sched_wakeup' and e['f'].get('pid') in tids and t0 <= e['ts'] <= t1:
            wakes.append({'by': e['tid'], 'by_comm': e['comm'], 'to': e['f']['pid'], 'ts': c.us(e['ts'])})
    txns = []
    for i in m.tree_ids(main['id']) + [r['id'] for r in roots if r is not main]:
        t = m.txns.get(i)
        if t:
            txns.append({k: t[k] for k in ('id', 'from_tid', 'to_tid', 'to_proc', 'node', 'code', 'flags', 'reply', 'data_size',
                                          'offsets_size', 'bc')} | {'t0': c.us(t['ts']), 't1': c.us(t['ts_recv']),
                                                                  'dev': ctx_of(t), 'from_proc': c.pname(c.pid_of(t['from_tid']))})
    raw = []
    for e in m.events:
        if t0 <= e['ts'] <= t1 and (e['tid'] in tids or (e['ev'] == 'sched_wakeup' and e['f'].get('pid') in tids)):
            raw.append({'ts': c.us(e['ts']), 'line': e['raw'], 'tid': e['tid'], 'ev': e['ev']})
    return {'steps': c.steps, 'lanes': lanes, 'flows': flows, 'wakes': wakes, 'txns': txns, 'raw': raw,
            'span': [0, c.us(t1)], 'main': main['id']}


def _locks(m, tid, t0, t1, c):
    out, pend = [], None
    for e in m.tid_events(tid, t0, t1):
        if e['ev'] == 'binder_lock':
            pend = e
        elif e['ev'] == 'binder_locked' and pend:
            if (e['ts'] - pend['ts']) * 1e6 > 2:
                out.append({'t0': c.us(pend['ts']), 't1': c.us(e['ts']), 'tag': pend['f'].get('tag')})
            pend = None
    return out
