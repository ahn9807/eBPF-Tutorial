## Installing bcc
> https://github.com/iovisor/bcc

In ubuntu 20.04
```bash
sudo apt-get install bpfcc-tools linux-headers-$(uname -r)
```

## libbpf
```bash
make \
sudo LD_LIBRARY_PATH=/usr/lib64 ./simple
cat /sys/kernel/debug/tracing/trace_pipe
```
