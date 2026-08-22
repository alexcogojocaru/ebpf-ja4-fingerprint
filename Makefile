.PHONY: all
all: build

.PHONY: generate
generate:
	@bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
	@go run github.com/cilium/ebpf/cmd/bpf2go \
 		-go-package main \
		-type tls_event \
		ebpf bpf/tls.c

.PHONY: build
build: generate
	@mkdir -p build
	@go build -o build/ja4 .
