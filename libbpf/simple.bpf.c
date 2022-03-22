#include <linux/bpf.h>
#include <stdlib.h>
#include <bpf/bpf_helpers.h>


SEC("tracepoint/syscalls/sys_enter_sync")
int ebpf_simple(void *ctx) {
	bpf_printk("Hello!\n");

	return 0;
}

char _license[] SEC("license") = "GPL";