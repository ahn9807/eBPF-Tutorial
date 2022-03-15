#!/usr/bin/python3

from bcc import BPF

# Define BPF program
bpf_txt = """

#include <linux/sched.h>

// Default key value is u64, but PID is u32
BPF_HASH(start, u32);

BPF_PERF_OUTPUT(events);
BPF_PERF_OUTPUT(args);

#define ARGSIZE 128
#define MAXARGS 8

struct args {
    char argv[ARGSIZE];
};

struct data_t {
    u32 pid;
    u64 ts;
    char comm[TASK_COMM_LEN];
    u64 exe_time;
    int retval;
};

int syscall_execve(struct pt_regs *ctx,
    const char __user *filename,
    const char __user *const __user *__argv,
    const char __user *const __user *__envp) {

    u64 ts;
    u32 pid;
    struct args arg_data = {};

    // Get PID and timestamp (in ns)
    pid = bpf_get_current_pid_tgid();
    ts = bpf_ktime_get_ns();

    // Save the start time (with key=PID) and return
    start.update(&pid, &ts);

    // Get full filepath for command
    bpf_probe_read(&arg_data.argv, sizeof(arg_data.argv), (void *)filename);
    args.perf_submit(ctx, &arg_data, sizeof(arg_data));

    // Read arguments (up to MAXARGS arguments)
    #pragma unroll
    for (int i = 1; i < MAXARGS; i++) {
        const char *argp = NULL;
        bpf_probe_read(&argp, sizeof(argp), (void *)&__argv[i]);
        if (argp) {
            bpf_probe_read(&arg_data.argv, sizeof(arg_data.argv), (void *)(argp));
            args.perf_submit(ctx, &arg_data, sizeof(arg_data));
        }
        else break;
    }

    return 0;
}

int end_execve(struct pt_regs *ctx) {
    u64 *tsp, ts, delta;
    struct data_t data = {};

    // Get PID and end timestamp (in ns)
    data.pid = bpf_get_current_pid_tgid();
    ts = bpf_ktime_get_ns();

    // Get the process's name
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // Lookup start time for corresponding PID
    tsp = start.lookup(&data.pid);
    if (tsp != NULL) {

        // Start time is also the timestamp, find delta
        data.ts = *tsp;
        data.exe_time = ts - *tsp;

        // Delete the hash entry and submit data
        start.delete(&data.pid);

        // Save return value of execve
        data.retval = PT_REGS_RC(ctx);

        events.perf_submit(ctx, &data, sizeof(data));
    }

    return 0;
}
"""

argvs = ""

def arg_builder(cpu, data, size):
    global argvs
    output = bpf_ctx["args"].event(data)
    argvs = argvs + str(output.argv) + " "

def handle_event(cpu, data, size):
    global argvs
    output = bpf_ctx["events"].event(data)
    print("%-18d %-16s %-6d %-10d %-35s %-5d" %
        (output.ts, output.comm, output.pid, output.exe_time, argvs, output.retval))
    argvs = ""

# Load BPF program
bpf_ctx = BPF(text=bpf_txt)
event_name = bpf_ctx.get_syscall_fnname("execve")
bpf_ctx.attach_kprobe(event=event_name, fn_name="syscall_execve")
bpf_ctx.attach_kretprobe(event=event_name, fn_name="end_execve")

# Print header
print("%-18s %-16s %-6s %-10s %-35s %-5s" %
    ("TIME(ns)", "COMM", "PID", "EXE TIME", "ARGS", "RETVAL"))

# Open perf "events" buffer
bpf_ctx["events"].open_perf_buffer(handle_event)
bpf_ctx["args"].open_perf_buffer(arg_builder)

# Poll for events
while 1:
    try:
        bpf_ctx.perf_buffer_poll()
    except KeyboardInterrupt:
        print()
        exit()