#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/bpf.h>
#include <errno.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <unistd.h>

static int open_raw_sock(const char *name)
{
	struct sockaddr_ll sll;
	int sock;

	sock = socket(PF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, htons(ETH_P_ALL));
	if (sock < 0) {
		printf("cannot create raw socket\n");
		return -1;
	}

	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = if_nametoindex(name);
	sll.sll_protocol = htons(ETH_P_ALL);
	if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
		printf("bind to %s: %s\n", name, strerror(errno));
		close(sock);
		return -1;
	}

	return sock;
}


int main(int argc, char **argv)
{
	int prog_fd;
	int sock_fd;
	struct bpf_object *obj;
	struct bpf_program *prog;

	// BPF object file is parsed.
	obj = bpf_object__open("./sock_simple.bpf.o");
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

	// Attachment phase, This is the pahse for BPF program attached to various BPF hook such as 
	// tracepoints, kprobes, cgroup hooks and network packet pipeline etc.
	prog = bpf_object__find_program_by_name(obj, "ebpf_simple");
	prog_fd = bpf_program__fd(prog);

	// Open raw socket and attaching the eBPF program
	sock_fd = open_raw_sock("lo");	
	if(setsockopt(sock_fd, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd))) {
		fprintf(stderr, "ERROR: attaching socket eBPF program failed %s\n", strerror(errno));
		return -1;
	}

	// We have to give some time to eBPF program.
	while(1);

	// After return his program, fd will be free with eBPF unloading.
	return 0;
}