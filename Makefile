GO ?= go
CLANG ?= clang
GOFMT ?= gofmt

UNAME_M := $(shell uname -m)
ifeq ($(UNAME_M),x86_64)
BPF_ARCH := x86
MULTIARCH := x86_64-linux-gnu
else ifeq ($(UNAME_M),aarch64)
BPF_ARCH := arm64
MULTIARCH := aarch64-linux-gnu
else
BPF_ARCH := $(UNAME_M)
MULTIARCH := $(UNAME_M)-linux-gnu
endif

BPF_SOURCE := cmd/ghostport/ghostport.bpf.c
BPF_OBJECT := cmd/ghostport/ghostport.bpf.o
# -fdebug-prefix-map rewrites the build directory recorded in DWARF debug info
# to a fixed value so the object is byte-identical regardless of the checkout
# path (e.g. a contributor's home directory vs. a GitHub Actions runner path).
BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_$(BPF_ARCH) -I/usr/include/$(MULTIARCH) -fdebug-prefix-map=$(CURDIR)=.

.PHONY: all bpf build clean fmt test vet verify

all: verify build

bpf:
	$(CLANG) $(BPF_CFLAGS) -c $(BPF_SOURCE) -o $(BPF_OBJECT)

build: bpf
	mkdir -p bin
	CGO_ENABLED=0 $(GO) build -trimpath -o bin/ghostport ./cmd/ghostport

fmt:
	$(GOFMT) -w cmd/ghostport/*.go

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

verify: test vet

clean:
	rm -rf bin
