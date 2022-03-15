#!/usr/bin/python3

from bcc import BPF

bpf_txt = """
#include <linux/sched.h>

// Default: BPF_HASH(name, key_type=u64, value_type=u64, size=10240)
BPF_HASH(start, u32);
BPF_PERF_OUTPUT(events);

struct data_t {
	u32 pid;
	u64 ts;
	char comm[TASK_COMM_LEN];
	u64 exe_time;
};

int start_execve(struct pt_regs *ctx) {
	u64 ts;
	u32 pid;

	pid = bpf_get_current_pid_tgid();
	ts = bpf_ktime_get_ns();

	start.update(&pid, &ts);
	return 0;
}

int end_execve(struct pt_regs *ctx) {
	u64 *tsp, ts, delta;
	struct data_t data = {};

	data.pid = bpf_get_current_pid_tgid();
	ts = bpf_ktime_get_ns();

	// This returns the first argument address of the current process name
	bpf_get_current_comm(&data.comm, sizeof(data.comm));
	tsp = start.lookup(&data.pid);
	if(tsp != NULL) {
		data.ts = *tsp;
		data.exe_time = ts - *tsp;
		start.delete(&data.pid);
		events.perf_submit(ctx, &data, sizeof(data));
	}

	return 0;
}
"""

bpf_ctx = BPF(text = bpf_txt)
attach_point = bpf_ctx.get_syscall_fnname("execve")
bpf_ctx.attach_kprobe(event=attach_point, fn_name="start_execve")
bpf_ctx.attach_kretprobe(event=attach_point, fn_name="end_execve")

# Print header
print("%-18s %-16s %-6s %-16s" %
    ("TIME(ns)", "COMM", "PID", "EXE TIME(ns)"))

def handle_event(cpu, data, size):
	output = bpf_ctx["events"].event(data)
	print("%-18d %-16s %-6d %-16d" % (output.ts, output.comm, output.pid, output.exe_time))

# Open perf "events" buffer
bpf_ctx["events"].open_perf_buffer(handle_event)

# Poll for events
while 1:
    try:
        bpf_ctx.perf_buffer_poll()
    except KeyboardInterrupt:
        print()
        exit()