#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/bpf.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>

int main(int argc, char **argv)
{
	int prog_fd;
	int sock_fd;
	struct bpf_object *obj;
	struct bpf_program *prog;
	int prev_value = 0;

	// BPF object file is parsed.
	obj = bpf_object__open("./sync_count.bpf.o");
	if (libbpf_get_error(obj))
	{
		fprintf(stderr, "ERROR: opening eBPF program failed\n");
		return -1;
	}

	// BPF maps are creased, various relocations are resolved and BPF programs are loaded into the
	// kernel and verfied. But BPF program is yet executed.
	bpf_object__load(obj);
	if (libbpf_get_error(obj))
	{
		fprintf(stderr, "ERROR: loading eBPF program failed\n");
		return -1;
	}

	// Attachment phase, This is the pahse for BPF program attached to various BPF hook such as
	// tracepoints, kprobes, cgroup hooks and network packet pipeline etc.
	prog = bpf_object__find_program_by_name(obj, "ebpf_enter");
	bpf_program__attach(prog);

	// We have to give some time to eBPF program.
	while (1)
	{
		struct bpf_map *socket_map = bpf_object__find_map_by_name(obj, "sync_map");
		int socket_map_fd = bpf_map__fd(socket_map);
		long key = -1, prev_key = 0;

		while (bpf_map_get_next_key(socket_map_fd, &prev_key, &key) == 0)
		{
			int value;
			if (bpf_map_lookup_elem(socket_map_fd, &key, &value) == 0)
			{
				if (prev_value != value)
				{
					prev_value = value;
					fprintf(stdout, "fd %ld read %d times\n", key, value);
					fflush(stdout);
				}
			}
			prev_key = key;
		}

		sleep(1);
	}

	// After return his program, fd will be free with eBPF unloading.
	return 0;
}
