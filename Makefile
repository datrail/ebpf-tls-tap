.PHONY: build build-bpf clean install

build-bpf:
	$(MAKE) -C bpf sslsniff

build: build-bpf

clean:
	$(MAKE) -C bpf clean

install:
	apt-get update && apt-get install -y \
		clang llvm gcc libelf-dev zlib1g-dev make git
