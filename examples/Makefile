# This Makefile contains the rules required to set up our
# Dapper-based build environment; it can be copied as-is to
# other projects (and needs to be copied, it can't be shared
# via the Dapper image since it's needed to retrieve the image)

.dapper:
	@echo Downloading dapper
	@curl -sL https://releases.rancher.com/dapper/latest/dapper-`uname -s`-`uname -m` > .dapper.tmp
	@@chmod +x .dapper.tmp
	@./.dapper.tmp -v
	@mv .dapper.tmp .dapper

all: xdp-example.o tc-example.o

xdp-example.o: .dapper xdp-example.c
	./.dapper -m bind scripts/sh clang -O2 -Wall -target bpf -c xdp-example.c -o xdp-example.o

tc-example.o: .dapper tc-example.c
	./.dapper -m bind scripts/sh clang -O2 -Wall -target bpf -c tc-example.c -o tc-example.o



shell: .dapper
	./.dapper -m bind -s

.PHONY: shell
