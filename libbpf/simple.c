#include <bpf/libbpf.h>
#include <bpf/bpf.h>

int main(int argc, char **argv)
{
	int prog_fd;
	struct bpf_object *obj;
	struct bpf_program *prog;

	// BPF object file is parsed.
	obj = bpf_object__open("/home/ahn9807/ebpf/libbpf/simple.bpf.o");
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
	prog = bpf_object__find_program_by_name(obj, "ebpf_simple");
	bpf_program__attach(prog);

	// We have to give some time to eBPF program.
	while(1);

	// After return his program, fd will be free with eBPF unloading.
	return 0;
}