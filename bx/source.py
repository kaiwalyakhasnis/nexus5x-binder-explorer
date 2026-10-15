"""Reads real code out of the LineageOS tree: snippets for each layer, the binder
UAPI header (the kernel <-> userspace protocol) and AIDL / HIDL method numbering."""
import os
import re

ROOT = os.environ.get('LINEAGE_ROOT', os.path.expanduser('~/Desktop/android/lineage'))
KERNEL = os.path.join(ROOT, 'kernel/lge/bullhead')

P = {
    'binder.c': 'kernel/lge/bullhead/drivers/staging/android/binder.c',
    'uapi': 'kernel/lge/bullhead/drivers/staging/android/uapi/binder.h',
    'led-class': 'kernel/lge/bullhead/drivers/leds/led-class.c',
    'leds-qpnp': 'kernel/lge/bullhead/drivers/leds/leds-qpnp.c',
    'IPCThreadState': 'frameworks/native/libs/binder/IPCThreadState.cpp',
    'BpBinder': 'frameworks/native/libs/binder/BpBinder.cpp',
    'Binder.cpp': 'frameworks/native/libs/binder/Binder.cpp',
    'Parcel.cpp': 'frameworks/native/libs/binder/Parcel.cpp',
    'ProcessState': 'frameworks/native/libs/binder/ProcessState.cpp',
    'IBinder.h': 'frameworks/native/libs/binder/include/binder/IBinder.h',
    'IServiceManager.cpp': 'frameworks/native/libs/binder/IServiceManager.cpp',
    'service.cpp': 'frameworks/native/cmds/service/service.cpp',
    'service_manager.c': 'frameworks/native/cmds/servicemanager/service_manager.c',
    'sm_binder.c': 'frameworks/native/cmds/servicemanager/binder.c',
    'jni_binder': 'frameworks/base/core/jni/android_util_Binder.cpp',
    'jni_hwremote': 'frameworks/base/core/jni/android_os_HwRemoteBinder.cpp',
    'Binder.java': 'frameworks/base/core/java/android/os/Binder.java',
    'Parcel.java': 'frameworks/base/core/java/android/os/Parcel.java',
    'ServiceManager.java': 'frameworks/base/core/java/android/os/ServiceManager.java',
    'IBinder.java': 'frameworks/base/core/java/android/os/IBinder.java',
    'HwRemoteBinder.java': 'frameworks/base/core/java/android/os/HwRemoteBinder.java',
    'hw_IPCThreadState': 'system/libhwbinder/IPCThreadState.cpp',
    'hw_BpHwBinder': 'system/libhwbinder/BpHwBinder.cpp',
    'hw_Binder': 'system/libhwbinder/Binder.cpp',
    'hidl_Interface.cpp': 'system/tools/hidl/Interface.cpp',
    'RgbLedManager': 'frameworks/base/core/java/android/hardware/rgbled/RgbLedManager.java',
    'IRgbLedService.aidl': 'frameworks/base/core/java/android/hardware/rgbled/IRgbLedService.aidl',
    'IRgbLedService.gen': 'out/target/common/obj/JAVA_LIBRARIES/framework_intermediates/core/java/android/hardware/rgbled/IRgbLedService.java',
    'RgbLedService': 'frameworks/base/services/core/java/com/android/server/rgbled/RgbLedService.java',
    'IRgbLed.hal': 'hardware/lineage/interfaces/rgbled/1.0/IRgbLed.hal',
    'IRgbLed.gen': 'out/target/common/gen/JAVA_LIBRARIES/vendor.lineage.rgbled-V1.0-java-static_intermediates/vendor/lineage/rgbled/V1_0/IRgbLed.java',
    'RgbLedAll.cpp': 'out/soong/.intermediates/hardware/lineage/interfaces/rgbled/1.0/vendor.lineage.rgbled@1.0_genc++/gen/vendor/lineage/rgbled/1.0/RgbLedAll.cpp',
    'RgbLed.cpp': 'device/lge/bullhead/rgbled/RgbLed.cpp',
    'hal_service.cpp': 'device/lge/bullhead/rgbled/service.cpp',
    'android_base_file': 'system/core/base/file.cpp',
}

_cache = {}


def lines(rel):
    if rel not in _cache:
        try:
            with open(os.path.join(ROOT, rel), errors='replace') as fh:
                _cache[rel] = fh.read().split('\n')
        except OSError:
            _cache[rel] = None
    return _cache[rel]


def path(key):
    return P.get(key, key)


def snip(key, anchors, before=0, after=None, hl=(), brace=False, cap=48, title=None):
    """Excerpt of a real source file.

    anchors: regex or list of regexes searched one after another (each starts
    after the previous match). brace=True extends to the end of the function body.
    """
    rel = path(key)
    src = lines(rel)
    if src is None:
        return {'file': rel, 'missing': True, 'title': title}
    if isinstance(anchors, str):
        anchors = [anchors]
    pos = 0
    for a in anchors:
        rx = re.compile(a)
        for i in range(pos, len(src)):
            if rx.search(src[i]):
                pos = i
                break
        else:
            return {'file': rel, 'missing': True, 'anchor': a, 'title': title}
    start = max(0, pos - before)
    if brace:
        depth, seen, end = 0, False, pos
        for i in range(pos, min(len(src), pos + 2000)):
            depth += src[i].count('{') - src[i].count('}')
            seen = seen or '{' in src[i]
            end = i
            if seen and depth <= 0:
                break
        end = min(end, pos + cap)
    else:
        end = min(len(src) - 1, pos + (after if after is not None else 12))
    hls = []
    hrx = [re.compile(h) for h in hl]
    for i in range(start, end + 1):
        if any(r.search(src[i]) for r in hrx):
            hls.append(i + 1)
    body = src[start:end + 1]
    # strip common indentation so deep kernel code stays readable
    ind = min((len(l) - len(l.lstrip()) for l in body if l.strip()), default=0)
    body = [l[ind:] if len(l) >= ind else l for l in body]
    return {'file': rel, 'start': start + 1, 'anchor_line': pos + 1, 'lines': body, 'hl': hls,
            'title': title, 'truncated': brace and end == pos + cap}


# ---- AIDL / HIDL numbering ---------------------------------------------------

def aidl_methods(key='IRgbLedService.aidl'):
    """[(code, name, [(type, name)], return_type, oneway)] in declaration order (code = index+1)."""
    src = lines(path(key)) or []
    text = '\n'.join(src)
    text = re.sub(r'/\*.*?\*/', '', text, flags=re.S)
    text = re.sub(r'//.*', '', text)
    body = text[text.find('{') + 1:text.rfind('}')]
    out = []
    for m in re.finditer(r'(oneway\s+)?([\w.<>\[\]]+)\s+(\w+)\s*\(([^)]*)\)\s*;', body):
        params = []
        for p in [x.strip() for x in m.group(4).split(',') if x.strip()]:
            parts = p.replace('in ', '').replace('out ', '').replace('inout ', '').split()
            params.append((parts[-2] if len(parts) > 1 else parts[0], parts[-1]))
        out.append({'code': len(out) + 1, 'name': m.group(3), 'params': params, 'ret': m.group(2),
                    'oneway': bool(m.group(1))})
    return out


def hal_methods(key='IRgbLed.hal'):
    src = lines(path(key)) or []
    text = re.sub(r'/\*.*?\*/', '', '\n'.join(src), flags=re.S)
    body = text[text.find('{') + 1:text.rfind('}')]
    out = []
    for m in re.finditer(r'(oneway\s+)?(\w+)\s*\(([^)]*)\)\s*(?:generates\s*\(([^)]*)\))?\s*;', body):
        out.append({'code': len(out) + 1, 'name': m.group(2), 'args': m.group(3).strip(),
                    'gen': (m.group(4) or '').strip(), 'oneway': bool(m.group(1))})
    return out


def proxy_writes(gen_key, method, var):
    """The exact Parcel write/read calls the generated proxy makes for a method."""
    src = lines(path(gen_key)) or []
    rx = re.compile(r'public [\w.<>\[\]]+ %s\(' % re.escape(method))
    for i, l in enumerate(src):
        if rx.search(l):
            calls, depth, seen = [], 0, False
            for j in range(i, min(len(src), i + 80)):
                for m in re.finditer(r'%s\.(write\w+|read\w+|create\w+|verifySuccess|enforceInterface)\(([^;]*)\)' % var, src[j]):
                    calls.append({'call': m.group(1), 'arg': m.group(2), 'line': j + 1})
                depth += src[j].count('{') - src[j].count('}')
                seen = seen or '{' in src[j]
                if seen and depth <= 0:
                    break
            return calls
    return []


# ---- the protocol: binder UAPI header ----------------------------------------

STRUCT_SIZES = {  # arm64 sizes, as the kernel and bionic see them
    '__s32': 4, '__u32': 4, 'int': 4, '__s64': 8, '__u64': 8, 'binder_uintptr_t': 8, 'binder_size_t': 8,
    'struct binder_write_read': 48, 'struct binder_version': 4,
    'struct binder_transaction_data': 64, 'struct binder_transaction_data_sg': 72,
    'struct binder_ptr_cookie': 16, 'struct binder_handle_cookie': 12, 'struct binder_pri_desc': 8,
    'struct binder_pri_ptr_cookie': 24,
}
DIRS = {'': 0, 'W': 1, 'R': 2, 'WR': 3}


def ioc(direction, typ, nr, size):
    return (DIRS[direction] << 30) | (size << 16) | (ord(typ) << 8) | nr


def protocol():
    rel = path('uapi')
    src = lines(rel) or []
    out = {'file': rel, 'commands': [], 'returns': [], 'ioctls': [], 'structs': []}
    entry = re.compile(r"^\s*(B[CR]_\w+)\s*=\s*_IO(WR|W|R)?\('(.)',\s*(\d+)(?:,\s*([^)]+))?\)")
    current = None
    for i, l in enumerate(src):
        m = entry.match(l)
        if m:
            name, d, typ, nr, arg = m.group(1), m.group(2) or '', m.group(3), int(m.group(4)), (m.group(5) or '').strip()
            size = STRUCT_SIZES.get(arg, 0)
            current = {'name': name, 'value': ioc(d, typ, nr, size), 'nr': nr, 'payload': arg or None,
                       'size': size, 'line': i + 1, 'doc': []}
            out['commands' if name.startswith('BC_') else 'returns'].append(current)
            continue
        if current is not None:
            s = l.strip()
            if s.startswith(('/*', '*')) and not s.startswith('*/'):
                txt = s.lstrip('/*').strip()
                if txt:
                    current['doc'].append(txt)
            elif s and not s.startswith('*/'):
                current = None
    for i, l in enumerate(src):
        m = re.match(r"#define\s+(BINDER_\w+)\s+_IO(WR|W|R)?\('(.)',\s*(\d+)(?:,\s*([^)]+))?\)", l)
        if m:
            arg = (m.group(5) or '').strip()
            out['ioctls'].append({'name': m.group(1), 'value': ioc(m.group(2) or '', m.group(3), int(m.group(4)),
                                                                   STRUCT_SIZES.get(arg, 0)),
                                  'payload': arg, 'line': i + 1})
    for name in ('flat_binder_object', 'binder_write_read', 'binder_transaction_data', 'binder_buffer_object',
                 'binder_object_header', 'binder_fd_object'):
        for i, l in enumerate(src):
            if re.match(r'^struct %s\s*\{' % name, l):
                body = []
                for j in range(i, min(len(src), i + 60)):
                    body.append(src[j])
                    if src[j].startswith('}'):
                        break
                out['structs'].append({'name': name, 'line': i + 1, 'lines': body})
                break
    for i, l in enumerate(src):
        m = re.match(r'^\s*(TF_\w+|FLAT_BINDER_FLAG_\w+|BINDER_TYPE_\w+)\s*=\s*(.+?),?\s*(?:/\*\s*(.*?)\s*\*/)?$', l)
        if m:
            out.setdefault('constants', []).append({'name': m.group(1), 'expr': m.group(2).rstrip(','),
                                                    'doc': m.group(3) or '', 'line': i + 1})
    return out


def special_codes():
    out = []
    src = lines(path('IBinder.h')) or []
    for i, l in enumerate(src):
        m = re.search(r"(\w+_TRANSACTION)\s*=\s*B_PACK_CHARS\('(.)',\s*'(.)',\s*'(.)',\s*'(.)'\)", l)
        if m:
            s = ''.join(m.group(2, 3, 4, 5))
            out.append({'name': m.group(1), 'chars': s, 'value': int.from_bytes(s.encode(), 'big'),
                        'file': path('IBinder.h'), 'line': i + 1, 'kind': 'binder'})
    src = lines(path('IBinder.java')) or []
    for i, l in enumerate(src):
        m = re.search(r"int (\w+_TRANSACTION)\s*=\s*\('(.)'<<24\)\|\('(.)'<<16\)\|\('(.)'<<8\)\|'(.)'", l)
        if m and m.group(1) not in [o['name'] for o in out]:
            s = ''.join(m.group(2, 3, 4, 5))
            out.append({'name': m.group(1), 'chars': s, 'value': int.from_bytes(s.encode(), 'big'),
                        'file': path('IBinder.java'), 'line': i + 1, 'kind': 'binder (Java only)'})
    src = lines(path('hidl_Interface.cpp')) or []
    for i, l in enumerate(src):
        m = re.search(r"(HIDL_\w+_TRANSACTION)\s*=\s*B_PACK_CHARS\(0x0f,\s*'(.)',\s*'(.)',\s*'(.)'\)", l)
        if m:
            s = ''.join(m.group(2, 3, 4))
            out.append({'name': m.group(1), 'chars': '\\x0f' + s, 'value': (0x0f << 24) | int.from_bytes(s.encode(), 'big'),
                        'file': path('hidl_Interface.cpp'), 'line': i + 1, 'kind': 'hwbinder (HIDL)'})
    return out


def find_java_class(cls):
    """Source file for a Java class name like com.android.server.rgbled.RgbLedService$BinderService."""
    outer = cls.split('$')[0]
    relp = outer.replace('.', '/') + '.java'
    for base in ('frameworks/base/services/core/java', 'frameworks/base/core/java', 'frameworks/base/services/java',
                 'frameworks/base/telephony/java', 'frameworks/base/wifi/java', 'frameworks/base/location/java',
                 'frameworks/base/media/java', 'frameworks/base/graphics/java',
                 'out/target/common/obj/JAVA_LIBRARIES/framework_intermediates/core/java',
                 'out/target/common/obj/JAVA_LIBRARIES/services.core_intermediates'):
        if os.path.exists(os.path.join(ROOT, base, relp)):
            return os.path.join(base, relp)
    return None


def find_aidl_gen(descriptor):
    rel = descriptor.replace('.', '/') + '.java'
    for base in ('out/target/common/obj/JAVA_LIBRARIES/framework_intermediates/core/java',
                 'out/target/common/obj/JAVA_LIBRARIES/framework_intermediates/telephony/java',
                 'out/target/common/obj/JAVA_LIBRARIES/framework_intermediates/media/java',
                 'out/target/common/obj/JAVA_LIBRARIES/framework_intermediates/location/java',
                 'out/target/common/obj/JAVA_LIBRARIES/framework_intermediates/wifi/java',
                 'out/target/common/obj/JAVA_LIBRARIES/framework_intermediates/graphics/java'):
        if os.path.exists(os.path.join(ROOT, base, rel)):
            return os.path.join(base, rel)
    return None
