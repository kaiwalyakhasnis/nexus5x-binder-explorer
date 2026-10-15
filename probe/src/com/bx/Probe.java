package com.bx;

import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import android.os.RemoteException;
import android.os.ResultReceiver;
import android.os.ServiceManager;
import android.os.ShellCallback;

import java.io.BufferedReader;
import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

/**
 * Binder Explorer probe. Runs on the phone through app_process:
 *
 *   CLASSPATH=/data/local/tmp/bx/probe.dex app_process /system/bin com.bx.Probe \
 *       <app|aidl|raw> <service> <method|code> [i32:N | s16:TEXT | i64:N]... [--lookup]
 *
 *   app   rgbled only: RgbLedManager -> IRgbLedService.Stub.Proxy -> BinderProxy (what an app does)
 *   aidl  any AIDL service: <Descriptor>$Stub.asInterface(binder).<method>(args)
 *   raw   binder.transact(code) with a hand-built Parcel (interface token + args)
 *
 * The IBinder handed to the generated proxy is a thin "tap" that forwards to the
 * real BinderProxy, so the generated code runs unmodified while we record the exact
 * Parcel bytes and the Java stack at the moment transact() is called.
 *
 * Kernel tracing is switched on just around the call, and trace_marker lines are
 * written so the Java layers show up in the ftrace timeline.
 */
public class Probe {
    static final String T = "/sys/kernel/debug/tracing/";
    static FileOutputStream marker;
    static int pid, tid;

    static String requestHex = "", replyHex = "";
    static long transactNs = -1;
    static List<String> stack = new ArrayList<>();
    static int transactCode = -1;
    static int transactFlags = 0;

    public static void main(String[] argv) {
        StringBuilder out = new StringBuilder();
        try {
            run(argv, out);
        } catch (Throwable t) {
            json(out, "error", t.toString());
        }
        System.out.println("BXJSON:{" + out + "}");
        System.exit(0);
    }

    static void run(String[] argv, StringBuilder out) throws Exception {
        pid = android.os.Process.myPid();
        tid = android.os.Process.myTid();
        String mode = argv[0], service = argv[1], what = argv[2];
        boolean lookupTraced = false;
        List<String> args = new ArrayList<>();
        for (int i = 3; i < argv.length; i++) {
            if (argv[i].equals("--lookup")) lookupTraced = true;
            else args.add(argv[i]);
        }
        json(out, "pid", pid);
        json(out, "tid", tid);
        json(out, "mode", mode);
        json(out, "service", service);

        marker = new FileOutputStream(T + "trace_marker");

        if (lookupTraced) tracing(true);
        mark("B|" + pid + "|ServiceManager.getService(\"" + service + "\")");
        IBinder real = ServiceManager.getService(service);
        mark("E");
        if (real == null) throw new IllegalStateException("service not found: " + service);
        String descriptor = real.getInterfaceDescriptor();   // _NTF, outside the traced window
        json(out, "descriptor", descriptor);
        json(out, "binderClass", real.getClass().getName());

        Tap tap = new Tap(real);
        Object result;
        String label;

        if (!lookupTraced) tracing(true);
        Thread.sleep(2);
        if (mode.equals("raw")) {
            int code = Integer.decode(what);
            Parcel data = Parcel.obtain(), reply = Parcel.obtain();
            if (code > 0 && code <= 0x00ffffff && descriptor != null) data.writeInterfaceToken(descriptor);
            for (String a : args) writeArg(data, a);
            label = "raw transact(" + code + ")";
            mark("B|" + pid + "|" + label);
            tap.transact(code, data, reply, 0);
            mark("E");
            result = "dataSize=" + reply.dataSize();
            data.recycle();
            reply.recycle();
        } else {
            Object target;
            String proxyLayer;
            IInterface iface = asInterface(descriptor, tap);
            if (mode.equals("app")) {
                Class<?> mgr = Class.forName("android.hardware.rgbled.RgbLedManager");
                target = mgr.getConstructor(android.content.Context.class,
                        Class.forName("android.hardware.rgbled.IRgbLedService")).newInstance(null, iface);
                proxyLayer = "RgbLedManager";
            } else {
                target = iface;
                proxyLayer = iface.getClass().getName();
            }
            Method m = findMethod(target.getClass(), what, args.size());
            Object[] callArgs = convertArgs(m, args);
            label = proxyLayer.substring(proxyLayer.lastIndexOf('.') + 1) + "." + what;
            mark("B|" + pid + "|" + label);
            try {
                result = m.invoke(target, callArgs);
            } finally {
                mark("E");
            }
            json(out, "method", m.toString());
        }
        Thread.sleep(3);   // let the server threads go back to sleep so the tail is captured
        tracing(false);

        json(out, "label", label);
        json(out, "code", transactCode);
        json(out, "flags", transactFlags);
        json(out, "result", render(result));
        json(out, "request", requestHex);
        json(out, "reply", replyHex);
        json(out, "transactNs", transactNs);
        jsonArr(out, "stack", stack);
        json(out, "debugfs", read("/sys/kernel/debug/binder/proc/" + pid));
        StringBuilder maps = new StringBuilder();
        for (String l : read("/proc/self/maps").split("\n"))
            if (l.contains("binder")) maps.append(l).append('\n');
        json(out, "maps", maps.toString());
    }

    /** IBinder that forwards to the real BinderProxy and records what passes through. */
    static class Tap implements IBinder {
        final IBinder real;
        Tap(IBinder real) { this.real = real; }

        @Override
        public boolean transact(int code, Parcel data, Parcel reply, int flags) throws RemoteException {
            for (StackTraceElement e : new Throwable().getStackTrace()) stack.add(e.toString());
            transactCode = code;
            transactFlags = flags;
            requestHex = hex(data.marshall());
            mark("B|" + pid + "|BinderProxy.transact(code=" + code + ", " + data.dataSize() + " bytes)");
            long t0 = System.nanoTime();
            boolean ok;
            try {
                ok = real.transact(code, data, reply, flags);
            } finally {
                transactNs = System.nanoTime() - t0;
                mark("E");
            }
            if (reply != null) {
                int pos = reply.dataPosition();
                replyHex = hex(reply.marshall());
                reply.setDataPosition(pos);
            }
            return ok;
        }

        @Override public String getInterfaceDescriptor() throws RemoteException { return real.getInterfaceDescriptor(); }
        @Override public boolean pingBinder() { return real.pingBinder(); }
        @Override public boolean isBinderAlive() { return real.isBinderAlive(); }
        @Override public IInterface queryLocalInterface(String d) { return null; }
        @Override public void dump(FileDescriptor fd, String[] a) throws RemoteException { real.dump(fd, a); }
        @Override public void dumpAsync(FileDescriptor fd, String[] a) throws RemoteException { real.dumpAsync(fd, a); }
        @Override public void shellCommand(FileDescriptor in, FileDescriptor o, FileDescriptor e, String[] a,
                ShellCallback cb, ResultReceiver r) throws RemoteException { real.shellCommand(in, o, e, a, cb, r); }
        @Override public void linkToDeath(DeathRecipient d, int f) throws RemoteException { real.linkToDeath(d, f); }
        @Override public boolean unlinkToDeath(DeathRecipient d, int f) { return real.unlinkToDeath(d, f); }
    }

    static IInterface asInterface(String descriptor, IBinder b) throws Exception {
        Class<?> stub = Class.forName(descriptor + "$Stub");
        return (IInterface) stub.getMethod("asInterface", IBinder.class).invoke(null, b);
    }

    static Method findMethod(Class<?> c, String name, int argc) {
        for (Method m : c.getMethods())
            if (m.getName().equals(name) && m.getParameterTypes().length == argc) return m;
        throw new IllegalArgumentException("no method " + name + " with " + argc + " args on " + c.getName());
    }

    static Object[] convertArgs(Method m, List<String> args) {
        Class<?>[] types = m.getParameterTypes();
        Object[] r = new Object[types.length];
        for (int i = 0; i < types.length; i++) {
            String v = args.get(i).replaceFirst("^(i32|i64|s16|bool):", "");
            Class<?> t = types[i];
            if (t == int.class) r[i] = Integer.decode(v);
            else if (t == long.class) r[i] = Long.decode(v);
            else if (t == boolean.class) r[i] = v.equals("1") || v.equalsIgnoreCase("true");
            else if (t == String.class) r[i] = v;
            else throw new IllegalArgumentException("unsupported arg type " + t.getName());
        }
        return r;
    }

    static void writeArg(Parcel p, String a) {
        if (a.startsWith("i32:")) p.writeInt(Integer.decode(a.substring(4)));
        else if (a.startsWith("i64:")) p.writeLong(Long.decode(a.substring(4)));
        else if (a.startsWith("s16:")) p.writeString(a.substring(4));
        else p.writeInt(Integer.decode(a));
    }

    static void tracing(boolean on) {
        try (FileOutputStream f = new FileOutputStream(T + "tracing_on")) {
            f.write(on ? '1' : '0');
        } catch (Exception ignored) {
        }
    }

    static void mark(String s) {
        try {
            marker.write(s.getBytes());
        } catch (Exception ignored) {
        }
    }

    static String read(String path) {
        StringBuilder sb = new StringBuilder();
        try (BufferedReader r = new BufferedReader(new FileReader(path))) {
            String l;
            while ((l = r.readLine()) != null) sb.append(l).append('\n');
        } catch (Exception e) {
            sb.append(e);
        }
        return sb.toString();
    }

    static String render(Object o) {
        if (o instanceof String[]) return java.util.Arrays.toString((String[]) o);
        return String.valueOf(o);
    }

    static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x & 0xff));
        return sb.toString();
    }

    static void json(StringBuilder sb, String k, Object v) {
        if (sb.length() > 0) sb.append(',');
        sb.append('"').append(k).append("\":");
        if (v instanceof Number) sb.append(v);
        else sb.append('"').append(esc(String.valueOf(v))).append('"');
    }

    static void jsonArr(StringBuilder sb, String k, List<String> v) {
        if (sb.length() > 0) sb.append(',');
        sb.append('"').append(k).append("\":[");
        for (int i = 0; i < v.size(); i++) {
            if (i > 0) sb.append(',');
            sb.append('"').append(esc(v.get(i))).append('"');
        }
        sb.append(']');
    }

    static String esc(String s) {
        StringBuilder sb = new StringBuilder();
        for (char c : s.toCharArray()) {
            if (c == '"' || c == '\\') sb.append('\\').append(c);
            else if (c == '\n') sb.append("\\n");
            else if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
            else sb.append(c);
        }
        return sb.toString();
    }
}
