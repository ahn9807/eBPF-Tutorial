#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stddef.h>
#include <signal.h>

static int cgroup_fd;

#define BPF_ATTACH_TYPE BPF_CGROUP_SOCK_OPS

void signal_handler(int sig) {
	int ret = bpf_prog_detach(cgroup_fd, BPF_ATTACH_TYPE);
	if(ret < 0) {
		fprintf(stderr, "ERROR: detaching eBPF program failed\n");
		exit(-1);
	} else {
		printf("\nebpf detach all ebpf program from unified cgroup\n");
	}

	exit(0);
}

int main(int argc, char **argv) {
	int prog_fd;
	int ret;
	struct bpf_object *obj;
	struct bpf_program *prog;

	// Register handler
	signal(SIGINT, signal_handler);

	// BPF object file is parsed.
	obj = bpf_object__open("./sockops_simple.bpf.o");
	if(libbpf_get_error(obj)) {
		fprintf(stderr, "ERROR: opening eBPF program failed\n");
		return -1;
	}

	// BPF maps are creased, various relocations are resolved and BPF programs are loaded into the
	// kernel and verfied. But BPF program is yet executed.
	bpf_object__load(obj);
	if(libbpf_get_error(obj)) {
		fprintf(stderr, "ERROR: loading eBPF program failed\n");
		return -1;
	}

	// Attachment pahse, This is the pahse for BPF program attached to various BPF hook such as 
	// tracepoints, kprobes, cgroup hooks and network packet pipeline etc.
	prog = bpf_object__find_program_by_name(obj, "do_sockops");
	if(prog == NULL) {
		fprintf(stderr, "ERROR: find eBPF prog failed\n");
		return -1;
	}

	// Fetch cgroup of this process
	cgroup_fd = open("/sys/fs/cgroup/unified", O_DIRECTORY | O_RDONLY);
	if(cgroup_fd < 0) {
		fprintf(stderr, "ERROR: failed to get cgroup\n");
		return -1;
	}

	prog_fd = bpf_program__fd(prog);
	ret = bpf_prog_attach(prog_fd, cgroup_fd, BPF_ATTACH_TYPE, BPF_F_ALLOW_OVERRIDE);
	if(ret < 0) {
		fprintf(stderr, "ERROR: attaching eBPF prog failed errno: %d\n", ret);
		return -1;
	}

	// We have to give some time to eBPF program.
	while(1);

	// After return his program, fd will be free with eBPF unloading.
	return 0;
}