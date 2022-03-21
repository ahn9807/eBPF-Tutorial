#!/usr/bin/python3

from bcc import BPF

bpf = BPF(text="""
#include <uapi/linux/ptrace.h>

BPF_HASH(last);

int do_trace(struct pt_regs *ctx) {
    u64 ts, *tsp, count=1, key = 0;

    tsp = last.lookup(&key);
    if(tsp!=NULL) {
        count = *tsp;
        count += 1;
        last.delete(&key);
    }

    last.update(&key, &count);
    bpf_trace_printk("%d\\n", count);
    return 0;
}
""")

bpf.attach_kprobe(event=bpf.get_syscall_fnname("sync"), fn_name="do_trace")
print("Tracing for quick sync's... Ctrl-C to end")

# format output
start = 0
while 1:
    (task, pid, cpu, flags, ts, ms) = bpf.trace_fields()
    if start == 0:
        start = ts
    ts = ts - start
    print("At time %.2f s: multiple syncs detected, last %s ms ago" % (ts, ms))