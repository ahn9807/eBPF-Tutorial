#include <linux/bpf.h>
#include <stdlib.h>
#include <bpf/bpf_helpers.h>


SEC("sockops")
int do_sockops(struct bpf_sock_ops *skops) {
	bpf_printk("sock_ops num:%d\n", skops->op);
    return 0;
}

char _license[] SEC("license") = "GPL";