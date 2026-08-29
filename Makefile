# SPDX-License-Identifier: Apache-2.0

.PHONY: build build-bpf clean install

build-bpf:
	$(MAKE) -C bpf sslsniff

build: build-bpf

clean:
	$(MAKE) -C bpf clean

# libssl-dev is bpftool's, not ours: its bootstrap build compiles sign.c
# against OpenSSL, and without the headers the whole tree stops at
# `openssl/opensslv.h: No such file or directory` — after libbpf has already
# built, so it looks like a problem in our code rather than a missing package.
install:
	apt-get update && apt-get install -y \
		clang llvm gcc libelf-dev zlib1g-dev libssl-dev make git
