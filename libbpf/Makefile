TARGET_simple := simple
TARGET_sock_simple := sock_simple
TARGET_sync_count := sync_count
TARGET_sockops_simple := sockops_simple

LIBS = -lbpf -lelf

all: $(TARGET_simple) $(TARGET_sock_simple) $(TARGET_sync_count) $(TARGET_sockops_simple)

.PHONY: clean

clean:
	rm -f $(TARGET_simple) $(TARGET_sock_simple) $(TARGET_sync_count) $(TARGET_sockops_simple)
	rm -f *.o

$(TARGET_simple): simple.bpf.o simple.c
	gcc simple.c -o $(TARGET_simple) $(LIBS)

$(TARGET_sock_simple): sock_simple.bpf.o sock_simple.c
	gcc sock_simple.c -o $(TARGET_sock_simple) $(LIBS)

$(TARGET_sync_count): sync_count.bpf.o sync_count.c
	gcc sync_count.c -o $(TARGET_sync_count) $(LIBS)

$(TARGET_sockops_simple): sockops_simple.bpf.o sockops_simple.c
	gcc sockops_simple.c -o $(TARGET_sockops_simple) $(LIBS)

simple.bpf.o:
	clang -target bpf -Wall -Werror -O2  -c simple.bpf.c -o simple.bpf.o

sock_simple.bpf.o:
	clang -target bpf -Wall -Werror -O2  -c sock_simple.bpf.c -o sock_simple.bpf.o
	
sync_count.bpf.o:
	clang -target bpf -Wall -Werror -O2 -g -c sync_count.bpf.c -o sync_count.bpf.o

sockops_simple.bpf.o:
	clang -target bpf -Wall -Werror -O2 -c sockops_simple.bpf.c -o sockops_simple.bpf.o