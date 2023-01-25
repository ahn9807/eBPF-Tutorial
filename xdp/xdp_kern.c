#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp_prog1")
int xdp_prog_drop(struct xdp_md *ctx) {
	return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
