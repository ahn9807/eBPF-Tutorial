from bcc import BPF

prog = """
int hello(void *ctx) {
    bpf_trace_printk("Hello World!\\n");
    return 0;
}
"""

bpf = BPF(text=prog)
bpf.attach_kprobe(event=bpf.get_syscall_fnname("clone"), fn_name="hello")

# header
print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "MESSAGE"))

# format output
while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = bpf.trace_fields()
    except ValueError:
        continue
    print("%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))