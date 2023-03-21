VMLINUX=vmlinux.h
OUTPUT=exec
SRC=cmd
BPF_CFLAGS= -target $(uname -m) -O2 -Wall

build: gen
	go build -o ./$(OUTPUT)/ ./cmd/...

gen: 
	go generate ./...

install headers: bpf_headers
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > ./headers/$(VMLINUX)

bpf_headers: 
	cp /usr/include/bpf/bpf_helpers.h ./headers/bpf_helpers.h &
	cp /usr/include/bpf/bpf_helper_defs.h ./headers/bpf_helper_defs.h

.PHONY: clean


clean:
	rm -rf $(SRC)/*/*_bpfel.* $(SRC)/*/*_bpfeb.* $(SRC)/*/*.o ./$(OUTPUT)