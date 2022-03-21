#!/usr/bin/python3

from bcc import BPF

bpf_txt = """

int hello_world_printk(void *ctx) {
	bpf_trace_printk("Hello World!\\n");
	return 0;
}
"""

bpf_ctx = BPF(text=bpf_txt)
bpf_ctx.attach_kprobe(event=bpf_ctx.get_syscall_fnname("fsync"), fn_name="hello_world_printk")

print("%s" % "MESSAGE")

while 1:
	try:
		bpf_ctx.trace_print(fmt="{5}")
	except KeyboardInterrupt:
		print()
		exit()
