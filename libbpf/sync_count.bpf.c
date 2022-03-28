#include <linux/bpf.h>
#include <stdlib.h>
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, long);
	__type(value, long);
	__uint(max_entries, 64);
} sync_map SEC(".maps");

struct syscalls_enter_read_args {
	long pad;
	unsigned int fd;
	char *buf;
	size_t count;
};

SEC("tracepoint/syscalls/sys_enter_sync")
int ebpf_enter(struct syscalls_enter_read_args *ctx) {
	long key = ctx->fd;
	int *value = bpf_map_lookup_elem((void *)&sync_map, (const void *)&key);
	int new_value = 1;

	if(value != NULL)
		new_value = *value + 1;

	bpf_map_update_elem((void *)&sync_map, (const void *)&key, (const void *)&new_value, BPF_ANY);
	
	return 0;
}

char _license[] SEC("license") = "GPL";