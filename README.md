> [!WARNING]
> **Disclaimer: this project is completely AI-generated.** All of the code, the explanations in the UI, the
> screenshots and this README were written by an AI assistant (Claude) in one session, with a human asking
> questions and pointing it at a phone. Call it AI slop if you like. It was built to help one person learn how
> binder works, and it was checked against a real device, but it has not been reviewed by Android or kernel
> experts. Treat the explanations as a study aid, not as documentation, and check anything important against
> the source.

# Binder Explorer (Nexus 5X / LineageOS 15.1)

A local web page that makes a **real binder call on a connected phone** and shows, step by step, how it
travels through every layer:

```
app Java → generated AIDL proxy → BinderProxy → JNI → libbinder → ioctl(BINDER_WRITE_READ)
  → binder driver (kernel) → system_server binder thread → JNI → Java Stub → RgbLedService
  → HIDL proxy → libhwbinder → /dev/hwbinder → LED HAL process → sysfs → leds-qpnp driver
  → … and all the way back
```

Every value on screen comes from that capture (kernel tracepoints, the probe's exact Parcel bytes,
`/sys/kernel/debug/binder`, `/proc`) or from the source in your own LineageOS tree. Nothing is simulated.
The explanations are written to match what the trace shows. For example, if the caller was preempted
instead of going to sleep, the step says so.

It was built around the custom RGB LED stack from
[nexus5x-rgbled](https://github.com/kaiwalyakhasnis/nexus5x-rgbled) (kernel driver → HIDL HAL → system service →
app SDK). That stack gives a short call path that crosses both `/dev/binder` and `/dev/hwbinder`.

---

## Screenshots

All screenshots are real captures from the phone. The step lists, timings and addresses differ on every run.

### Trace a call: overview
The process × layer map, the timeline (built from `sched_switch` / `sched_wakeup` / `raw_syscalls` /
`binder_*` tracepoints and trace markers), the step list, and the detail for the selected step.
![Trace overview](docs/screenshots/01-trace-overview.png)

### The exact Parcel bytes
Bytes captured from `Parcel.marshall()` at the moment of `transact()`. Each field is labelled (StrictMode header,
interface token, arguments) and linked to the generated proxy lines that wrote it. Hovering a field highlights its bytes.
![Parcel bytes](docs/screenshots/02-parcel-bytes.png)

### Inside the binder driver: the single copy
`binder_alloc_buf()` + `copy_from_user()` straight into the receiver's mapping, with the real receiver mapping
address and the real `binder.c` lines from the device's kernel tree.
![Kernel copy](docs/screenshots/03-kernel-single-copy.png)

### What the scheduler actually did
The textbook says the caller sleeps until the reply arrives. On this device the sync wakeup usually hands the CPU to the
server thread, which preempts the caller before it even starts waiting. The step is written from the trace.
![Scheduler](docs/screenshots/04-scheduler-preemption.png)

### The HAL doing the real work (with strace)
With "strace the HAL" on, you see the real `openat("/sys/class/leds/red/brightness")` and `read → "255\n"`.
The timeline shows the cost: the purple segments are the HAL stopped by ptrace.
![HAL and sysfs](docs/screenshots/05-hal-sysfs-strace.png)

### Down to the LED driver
sysfs → LED class (`led_brightness_show`) → `qpnp_led_get()` in `leds-qpnp.c`.
![LED driver](docs/screenshots/06-led-driver.png)

### A write: `setChannel(0, 255)`
The write path: `led_brightness_store()` → `qpnp_led_set()`, and the HAL writing `rgb_start`.
![setChannel](docs/screenshots/09-set-channel-write.png)

### Native client: `service call` with the servicemanager lookup
No Java on the client side. Shows `_PNG` to handle 0, `CHECK_SERVICE`, and the kernel **translating
servicemanager's handle 54 into handle 1** for the caller (`binder_transaction_ref_to_ref`).
![Native service call](docs/screenshots/07-native-service-call-lookup.png)

### Raw special codes (`_PNG`, `_NTF`, `_TWT`…)
Send any transaction code with a hand-built Parcel.
![Raw ping](docs/screenshots/08-raw-ping-code.png)

### Any AIDL service, not just the LED
Example: `IPowerManager.isInteractive()` through its generated proxy. The implementation class comes from
the trace marker `Binder.execTransact()` writes.
![Other AIDL service](docs/screenshots/10-aidl-other-service.png)

### Record what the real app does
Records every transaction `com.example.rgbleddemo` sends while you use it. Click any row to get its journey.
![Record the app](docs/screenshots/15-record-app.png)

### Protocol: where is it defined?
The three stacked protocols (kernel ABI, libbinder conventions, AIDL/HIDL interface contracts). Also a decoder for any
BC/BR/ioctl/code value, every special code with its decimal for `service call`, and all BC_*/BR_* commands and
structs parsed from this device's `uapi/binder.h`.
![Protocol](docs/screenshots/11-protocol.png)

### Live binder state of any process
`/sys/kernel/debug/binder/proc/<pid>` with every handle resolved to the process that owns the node, looper
flags decoded, and the binder mappings.
![Live state: system_server](docs/screenshots/12-live-state-system-server.png)
![Live state: HAL](docs/screenshots/13-live-state-hal.png)

### Dark mode
Follows the OS setting, or force it with `#theme=dark`.
![Dark mode](docs/screenshots/14-dark-mode.png)

---

## How it works

```
 Browser (web/app.js)  ──HTTP──▶  server.py (PC)  ──adb──▶  device/capture.sh (phone, root)
                                                              1. enable ftrace: binder/*, sched_switch,
                                                                 sched_wakeup, raw_syscalls (+ am trace-ipc)
                                                              2. run the call (Java probe or `service call`)
                                                              3. disable tracing, save trace, restore settings
 Browser  ◀──JSON──  server.py: parse trace → link requests/replies/nested hops → thread states
                     → ask the phone for tid→pid, /proc/<pid>/maps, debugfs, fd paths
                     → build the steps (bx/journey.py) with source excerpts from the tree (bx/source.py)
```

- **The probe** (`probe/src/com/bx/Probe.java`, run with `app_process`) makes the same calls an app makes:
  `RgbLedManager` → generated `IRgbLedService.Stub.Proxy` → `BinderProxy`. The proxy gets a pass-through
  `IBinder` wrapper that forwards to the real `BinderProxy`. The generated code runs unchanged while the wrapper
  records the exact request and reply bytes and the Java stack at `transact()`. It also writes trace markers and
  switches `tracing_on` only around the call.
- **System_server's Java layer** shows up because `Binder.execTransact()` writes a `B|pid|Class:code`
  marker while `am trace-ipc` is on. The capture switches that on and off.
- **Source excerpts** are found by searching for function names in the tree, so the line numbers always match your
  checkout. Click any `file:line` to open more of the file.

## Environment this was built and tested on

| | |
|---|---|
| Phone | Google/LG **Nexus 5X** (`bullhead`), Snapdragon 808, 6 cores |
| ROM | **LineageOS 15.1** (Android **8.1.0**), unofficial `userdebug` build `15.1-20261013-UNOFFICIAL-bullhead` |
| Kernel | **3.10.73** (lineage `kernel/lge/bullhead`). Binder lives in `drivers/staging/android/binder.c` with one global lock |
| Extra stack | [nexus5x-rgbled](https://github.com/kaiwalyakhasnis/nexus5x-rgbled): `leds-qpnp` sysfs → `vendor.lineage.rgbled@1.0` HIDL HAL → `RgbLedService` (`rgbled`) in system_server → `RgbLedManager` SDK + demo app `com.example.rgbleddemo` |
| Root | `adb root` works (userdebug + "Rooted debugging" in developer options) |
| Device tools used | `strace` (`/system/xbin/strace`), `app_process`, `service`, `am trace-ipc`, ftrace at `/sys/kernel/debug/tracing`, binder debugfs |
| Host | Ubuntu 24.04.1 LTS, Python 3.12.3 (standard library only), adb 1.0.41, OpenJDK 1.8.0_442 (only to rebuild the probe), Chromium (only for the screenshots) |
| Source tree | A **built** LineageOS 15.1 tree at `~/Desktop/android/lineage` (or `$LINEAGE_ROOT`). `out/` is needed for the generated AIDL/HIDL code and for the framework jars to build the probe |

### Setup

1. Build and flash LineageOS 15.1 for bullhead with the RGB LED stack from
   [nexus5x-rgbled](https://github.com/kaiwalyakhasnis/nexus5x-rgbled). Keep the built tree around.
2. On the phone: Developer options → enable **USB debugging** and **Rooted debugging**. Connect it over USB.
3. On the PC:
   ```sh
   git clone https://github.com/kaiwalyakhasnis/nexus5x-binder-explorer
   cd nexus5x-binder-explorer
   export LINEAGE_ROOT=~/Desktop/android/lineage    # your built tree
   python3 server.py                                # runs `adb root` if needed, pushes the probe
   ```
4. Open **http://127.0.0.1:8765** and press **Run on the phone**.

`probe/probe.dex` is committed prebuilt. To rebuild it against your own tree:
`LINEAGE_ROOT=/path/to/lineage ./probe/build.sh`.

### Using it on another device or ROM
Most of it is generic, because it works from kernel tracepoints and from searching for function names in your
tree. The device-specific bits are the kernel path in `bx/source.py` (`P['binder.c']` etc.), the HAL process name
(`HAL_NAME` in `server.py`, `device/capture.sh`), and the RGB LED file paths. Newer kernels (4.14+) moved binder
to `drivers/android/` and split out `binder_alloc.c`, so those anchors would need updating. Android 9+ also adds
Perfetto, which records much of the same data.

## Deep links

The page reads options from the URL hash, which makes runs repeatable (the screenshots were taken this way):

| Example | Does |
|---|---|
| `#run` | run `getBrightness(0)` via the app path |
| `#meth=setChannel&args=0,255&run&s=led` | run a method with arguments, jump to the LED driver step |
| `#kind=native&lookup&run&s=2` | `service call` with the servicemanager lookup, open step 2 |
| `#kind=probe-raw&code=1599098439&run` | send `_PNG` |
| `#kind=probe-aidl&svc=power&meth=isInteractive&run` | call another AIDL service |
| `#strace&run&s=hal` | also strace the HAL |
| `#tab=state&pid=791` | live state of a process |
| `#tab=record&rec&secs=6` | start recording the app |
| `#theme=dark` | force the dark theme |

`kind` is `probe-app` (default), `probe-aidl`, `native` or `probe-raw`. `s` is a step number or one of `hal`, `led`, `sched`.

## Repository layout

| Path | What |
|---|---|
| `server.py` | HTTP server (stdlib), drives adb, collects metadata (tid→pid, maps, debugfs, fd targets) |
| `bx/trace.py` | ftrace parser: rebuilds transactions, matches replies, finds nested hops, works out thread states |
| `bx/journey.py` | turns one transaction tree into the steps, with values, source and evidence |
| `bx/source.py` | finds source excerpts in the tree; parses `uapi/binder.h`, AIDL/HIDL method numbering, special codes |
| `bx/parcel.py` | labels Parcel bytes from the generated proxy's write/read calls |
| `device/capture.sh` | runs on the phone: enables tracepoints, runs the call, restores the tracing state |
| `probe/` | the Java probe (`Probe.java`, prebuilt `probe.dex`, `build.sh`) |
| `web/` | the page: `index.html`, `app.css`, `app.js` (no external dependencies) |
| `docs/screenshots/` | the screenshots above |

## Limitations and honesty notes

- **AIDL request and reply bytes are exact** (captured in the probe). **HIDL request bytes are rebuilt** from the
  generated proxy's writes, and only their size is checked against the kernel's `data_size`.
- **strace on the HAL slows it by about 5–8 ms** (ptrace stops). Leave it off when you care about timing.
- In **record mode**, method names are only resolved for the RGB LED interface. Other services show the implementation
  class from the trace marker plus the code number, and the Java call-site stack does not always attach.
- Each capture briefly switches on `am trace-ipc` and ftrace and switches them off again afterwards. Don't run it while you
  are taking your own system traces.
- It needs root and debugfs. It is a learning tool for your own development device, not something to point at a
  phone you care about.
