TARGET_xdp_kern := xdp_kern

LIBS = -lbpf -lelf

all: $(TARGET_xdp_kern)

.PHONY: clean

clean:
	rm -f $(TARGET_xdp_kern)
	rm -f *.o

$(TARGET_xdp_kern):
	clang -O2 -target bpf -c xdp_kern.c -o xdp_kern.o

attach_generic:
	@sudo ip link set eno2 xdpgeneric obj xdp_kern.o sec xdp_prog1

attach_offload:
	@sudo ip link set eno2 xdpoffload obj xdp_kern.o sec xdp_prog1

unload:
	@sudo ip link set eno2 xdpgeneric off
	@sudo ip link set eno2 xdpoffload off

