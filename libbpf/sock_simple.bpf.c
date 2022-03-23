#include <linux/bpf.h>
#include <stdlib.h>
#include <bpf/bpf_helpers.h>


SEC("socket")
int ebpf_simple(struct __sk_buff *sk_buff) {
	bpf_printk("Hello! %d\n", sk_buff->hash);
	return 0;
}

char _license[] SEC("license") = "GPL";
