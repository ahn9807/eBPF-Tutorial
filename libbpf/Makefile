TARGET := simple

LIBS = -lbpf -lelf

all: $(TARGET) simple.bpf.o

.PHONY: clean

clean:
	rm -f $(TARGET)
	rm -f simple.bpf.o

$(TARGET): simple.bpf.o simple.c
	gcc simple.c -o $(TARGET) $(LIBS)

simple.bpf.o:
	clang -target bpf -Wall -Werror -O2  -c simple.bpf.c -o simple.bpf.o
	
