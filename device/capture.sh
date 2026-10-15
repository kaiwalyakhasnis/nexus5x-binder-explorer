#!/system/bin/sh
# Binder Explorer capture script (runs on the phone as root).
#
#   capture.sh <kind> <strace_hal 0|1> <syscalls 0|1> <ipc_markers 0|1> -- <args...>
#
#   kind=probe   args are passed to the Java probe (it switches tracing_on itself)
#   kind=native  args are passed to `service call`
#   kind=record  args = <seconds>; records everything for that long
#
# Leaves the tracing state as it found it (events off, buffer size restored).

T=/sys/kernel/debug/tracing
D=/data/local/tmp/bx
kind=$1; strace_hal=$2; syscalls=$3; ipc=$4; shift 5

HAL=$(pidof vendor.lineage.rgbled@1.0-service.bullhead)
OLD_BUF=$(cat $T/buffer_size_kb)
OLD_ON=$(cat $T/tracing_on)
rm -f $D/trace.txt $D/hal.st $D/out.txt $D/ipc.txt

echo 0 > $T/tracing_on
echo > $T/trace
if [ "$kind" = record ]; then echo 8192 > $T/buffer_size_kb; else echo 4096 > $T/buffer_size_kb; fi
echo 1 > $T/events/binder/enable
echo 1 > $T/events/sched/sched_switch/enable
echo 1 > $T/events/sched/sched_wakeup/enable
[ "$syscalls" = 1 ] && echo 1 > $T/events/raw_syscalls/enable

# Binder.execTransact() writes "B|pid|Class:code" trace markers while IPC tracing is on
[ "$ipc" = 1 ] && am trace-ipc start > /dev/null 2>&1

SP=
if [ "$strace_hal" = 1 ] && [ -n "$HAL" ]; then
    strace -p $HAL -f -tt -x -s 128 -o $D/hal.st > /dev/null 2>&1 &
    SP=$!
    sleep 0.4
fi

case $kind in
probe)
    CLASSPATH=$D/probe.dex app_process /system/bin com.bx.Probe "$@" > $D/out.txt 2>&1
    ;;
native)
    echo 1 > $T/tracing_on
    service call "$@" > $D/out.txt 2>&1
    echo 0 > $T/tracing_on
    ;;
record)
    echo 1 > $T/tracing_on
    sleep "$1"
    echo 0 > $T/tracing_on
    ;;
esac
echo 0 > $T/tracing_on

[ -n "$SP" ] && { sleep 0.1; kill $SP; }
[ "$ipc" = 1 ] && am trace-ipc stop --dump-file $D/ipc.txt > /dev/null 2>&1

echo 0 > $T/events/binder/enable
echo 0 > $T/events/sched/sched_switch/enable
echo 0 > $T/events/sched/sched_wakeup/enable
echo 0 > $T/events/raw_syscalls/enable
cat $T/trace > $D/trace.txt
echo > $T/trace
echo $OLD_BUF > $T/buffer_size_kb
echo $OLD_ON > $T/tracing_on
echo "HAL=$HAL"
echo CAPTURE_DONE
