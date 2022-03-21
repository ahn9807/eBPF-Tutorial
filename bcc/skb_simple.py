#!/usr/bin/python3

from bcc import BPF

bpf_txt = """

int hello_skb(struct __sk_buff *skb) {
    bpf_trace_printk("sk_buff\\n");
    return 1;
}
"""

bpf_ctx = BPF(text=bpf_txt)
bpf_ctx.load_func("hello_skb", BPF.SCHED_CLS)

while 1:
    try:
        bpf_ctx.trace_print(fmt="{5}")
    except KeyboardInterrupt:
        print()
        exit()