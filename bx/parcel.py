"""Byte-level annotation of Parcels, driven by the write/read calls the generated
proxy actually makes (see source.proxy_writes)."""
import struct


def _i32(b, o):
    return struct.unpack_from('<i', b, o)[0]


def _pad4(n):
    return (n + 3) & ~3


def string16(b, o, label):
    """Parcel::writeString16: int32 length (chars), UTF-16LE chars, NUL, pad to 4."""
    fields = []
    n = _i32(b, o)
    fields.append({'off': o, 'len': 4, 'label': label + ' length', 'value': '%d chars' % n if n >= 0 else 'null (-1)',
                   'kind': 'len'})
    o += 4
    if n < 0:
        return fields, o
    raw = (n + 1) * 2
    s = b[o:o + n * 2].decode('utf-16-le', errors='replace')
    fields.append({'off': o, 'len': n * 2, 'label': label, 'value': '"%s"' % s, 'kind': 'str'})
    fields.append({'off': o + n * 2, 'len': 2, 'label': 'NUL terminator (UTF-16)', 'value': '0x0000', 'kind': 'pad'})
    padded = _pad4(raw)
    if padded > raw:
        fields.append({'off': o + raw, 'len': padded - raw, 'label': 'padding to 4 bytes', 'value': '', 'kind': 'pad'})
    return fields, o + padded


def annotate_aidl_request(b, writes, args=None):
    fields, o = [], 0
    args = list(args or [])
    try:
        for w in writes:
            c = w['call']
            if c == 'writeInterfaceToken':
                pol = _i32(b, o)
                fields.append({'off': o, 'len': 4, 'label': 'StrictMode policy header', 'value': '0x%08x' % (pol & 0xffffffff),
                               'kind': 'hdr', 'note': 'IPCThreadState strict-mode policy | STRICT_MODE_PENALTY_GATHER (0x400000)',
                               'src': w['line']})
                o += 4
                f, o = string16(b, o, 'interface descriptor')
                fields += f
            elif c in ('writeInt', 'writeInt32'):
                fields.append({'off': o, 'len': 4, 'label': 'int %s' % w['arg'], 'value': str(_i32(b, o)), 'kind': 'arg',
                               'src': w['line']})
                o += 4
            elif c == 'writeLong':
                fields.append({'off': o, 'len': 8, 'label': 'long %s' % w['arg'], 'value': str(struct.unpack_from('<q', b, o)[0]),
                               'kind': 'arg', 'src': w['line']})
                o += 8
            elif c == 'writeString':
                f, o = string16(b, o, 'String %s' % w['arg'])
                for x in f:
                    x['src'] = w['line']
                    if x['kind'] == 'str':
                        x['kind'] = 'arg'
                fields += f
            else:
                break
    except struct.error:
        pass
    if o < len(b):
        fields.append({'off': o, 'len': len(b) - o, 'label': 'remaining bytes', 'value': '', 'kind': 'rest'})
    return fields


EXCEPTIONS = {0: 'no exception', -1: 'SecurityException', -2: 'BadParcelableException', -3: 'IllegalArgumentException',
              -4: 'NullPointerException', -5: 'IllegalStateException', -6: 'NetworkOnMainThreadException',
              -7: 'UnsupportedOperationException', -8: 'ServiceSpecificException', -128: 'has reply header'}


def annotate_aidl_reply(b, reads):
    fields, o = [], 0
    try:
        for r in reads:
            c = r['call']
            if c == 'readException':
                code = _i32(b, o)
                fields.append({'off': o, 'len': 4, 'label': 'exception code', 'value': '%d (%s)' % (code, EXCEPTIONS.get(code, '?')),
                               'kind': 'hdr', 'src': r['line'], 'note': 'written by Parcel.writeNoException() in the Stub'})
                o += 4
                if code != 0:
                    break
            elif c in ('readInt', 'readInt32'):
                v = _i32(b, o)
                fields.append({'off': o, 'len': 4, 'label': 'return value (int)', 'value': '%d (0x%x)' % (v, v & 0xffffffff),
                               'kind': 'arg', 'src': r['line']})
                o += 4
            elif c == 'readString':
                f, o = string16(b, o, 'return value (String)')
                fields += f
            elif c == 'createStringArray':
                n = _i32(b, o)
                fields.append({'off': o, 'len': 4, 'label': 'String[] count', 'value': str(n), 'kind': 'len', 'src': r['line']})
                o += 4
                for k in range(max(0, n)):
                    f, o = string16(b, o, 'String[%d]' % k)
                    fields += f
            else:
                break
    except struct.error:
        pass
    if o < len(b):
        fields.append({'off': o, 'len': len(b) - o, 'label': 'remaining bytes', 'value': '', 'kind': 'rest'})
    return fields


def hidl_request(writes, iface_name, values):
    """Rebuilds a HIDL (hwbinder) request Parcel when it only holds the token and scalars.

    libhwbinder's Parcel::writeInterfaceToken() writes a NUL-terminated C string padded
    to 4 bytes; scalar writes are padded to 4 bytes. Returns (bytes, fields) or None.
    """
    b = bytearray()
    fields = []
    vals = list(values)
    for w in writes:
        c = w['call']
        if c == 'writeInterfaceToken':
            s = iface_name.encode() + b'\0'
            p = _pad4(len(s))
            fields.append({'off': len(b), 'len': len(s) - 1, 'label': 'interface token (C string)',
                           'value': '"%s"' % iface_name, 'kind': 'hdr', 'src': w['line']})
            fields.append({'off': len(b) + len(s) - 1, 'len': 1 + p - len(s), 'label': 'NUL + padding to 4', 'value': '',
                           'kind': 'pad'})
            b += s + b'\0' * (p - len(s))
        elif c == 'writeInt32':
            v = int(vals.pop(0)) if vals else 0
            fields.append({'off': len(b), 'len': 4, 'label': 'int32 %s' % w['arg'], 'value': str(v),
                           'kind': 'arg', 'src': w['line']})
            b += struct.pack('<i', v)
        elif c in ('writeInt8', 'writeBool'):
            # Parcel::write(&val, 1) then zero padding to 4 bytes
            v = int(vals.pop(0)) if vals else 0
            fields.append({'off': len(b), 'len': 1, 'label': '%s %s' % (c[5:].lower(), w['arg']), 'value': str(v & 0xff),
                           'kind': 'arg', 'src': w['line']})
            fields.append({'off': len(b) + 1, 'len': 3, 'label': 'padding to 4', 'value': '', 'kind': 'pad'})
            b += bytes([v & 0xff, 0, 0, 0])
        elif c == 'writeInt64':
            v = int(vals.pop(0)) if vals else 0
            fields.append({'off': len(b), 'len': 8, 'label': 'int64 %s' % w['arg'], 'value': str(v), 'kind': 'arg',
                           'src': w['line']})
            b += struct.pack('<q', v)
        else:
            return None
    return bytes(b), fields


def aidl_from_service_call(descriptor, args):
    """Exact bytes `service call` builds: Parcel::writeInterfaceToken + its i32/s16/i64 args."""
    b = bytearray(struct.pack('<i', 0x00400000))
    s = descriptor.encode('utf-16-le') + b'\0\0'
    b += struct.pack('<i', len(descriptor)) + s + b'\0' * (_pad4(len(s)) - len(s))
    writes = [{'call': 'writeInterfaceToken', 'arg': 'ifName', 'line': None}]
    for a in args:
        if a.startswith('i32:') or a.lstrip('-').isdigit():
            b += struct.pack('<i', int(a.split(':')[-1], 0))
            writes.append({'call': 'writeInt32', 'arg': a, 'line': None})
        elif a.startswith('i64:'):
            b += struct.pack('<q', int(a[4:], 0))
            writes.append({'call': 'writeLong', 'arg': a, 'line': None})
        elif a.startswith('s16:'):
            t = a[4:]
            s = t.encode('utf-16-le') + b'\0\0'
            b += struct.pack('<i', len(t)) + s + b'\0' * (_pad4(len(s)) - len(s))
            writes.append({'call': 'writeString', 'arg': a, 'line': None})
    return bytes(b), writes


def reply_from_service_output(text):
    """`service call` prints the reply as 32-bit little-endian words: Result: Parcel(00000000 000000ff ...)."""
    import re
    words = []
    for line in text.splitlines():
        line = re.sub(r"'.*?'\)?\s*$", '', line)
        line = re.sub(r'^.*?Parcel\(', '', line)
        line = re.sub(r'0x[0-9a-f]+:', '', line)
        words += re.findall(r'\b[0-9a-f]{8}\b', line)
    return b''.join(struct.pack('<I', int(w, 16)) for w in words)


def binder_transaction_data(**kw):
    """Field list for struct binder_transaction_data (64 bytes on arm64), uapi/binder.h."""
    return [
        {'off': 0, 'len': 8, 'name': 'target.handle / target.ptr', 'value': kw.get('target', '?')},
        {'off': 8, 'len': 8, 'name': 'cookie', 'value': kw.get('cookie', '0')},
        {'off': 16, 'len': 4, 'name': 'code', 'value': kw.get('code', '?')},
        {'off': 20, 'len': 4, 'name': 'flags', 'value': kw.get('flags', '?')},
        {'off': 24, 'len': 4, 'name': 'sender_pid', 'value': kw.get('sender_pid', '0')},
        {'off': 28, 'len': 4, 'name': 'sender_euid', 'value': kw.get('sender_euid', '0')},
        {'off': 32, 'len': 8, 'name': 'data_size', 'value': kw.get('data_size', '?')},
        {'off': 40, 'len': 8, 'name': 'offsets_size', 'value': kw.get('offsets_size', '?')},
        {'off': 48, 'len': 8, 'name': 'data.ptr.buffer', 'value': kw.get('buffer', '?')},
        {'off': 56, 'len': 8, 'name': 'data.ptr.offsets', 'value': kw.get('offsets', '?')},
    ]
