#!/usr/bin/python3

from bcc import BPF

bpf_txt = """

// Create a BPF table for pushing custom data (perf ring buffer)
BPF_PERF_OUTPUT(events);

struct data_t {
	char str[12];
};

// This function runs in kernel context
int hello_world_perf(struct pt_regs *ctx) {
	struct data_t data = {};
	__builtin_memcpy(&data.str, "Hello World!", sizeof(data.str));

	// submit the perf data to userspace
	events.perf_submit(ctx, &data, sizeof(data));
	return 0;
}
"""

def handle_event(cpu, data, size):
	# This python struct is auto-generated from provided c-data structure
	output = bpf_ctx["events"].event(data)
	print("%s" % output.str)

# Load BPF program
bpf_ctx = BPF(text=bpf_txt)
attach_point = bpf_ctx.get_kprobe_functions(b"execve")
# Attach bpf program using kprobe attach hook
bpf_ctx.attach_kprobe(event="set_binfmt",
    fn_name="hello_world_perf")

# Print header
print("%s" % "MESSAGE")

# Register the callback function 
bpf_ctx["events"].open_perf_buffer(handle_event)

# Format output
while 1:
    try:
		# If there exist new data in perf buffer, call registered callback function
        bpf_ctx.perf_buffer_poll()
    except KeyboardInterrupt:
        print("Exit")
        exit()