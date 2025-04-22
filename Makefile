all: udpgrm examples/venv/.ok mmdecoy

BPFTOOL?=bpftool
BPFTOOL:=$(shell PATH=$$PATH:/usr/local/sbin:/usr/sbin which $(BPFTOOL))

ifeq ($(BPFTOOL),)
$(error bpftool not found)
endif


CLANG_DIR?=
CLANG_BIN?=$(CLANG_DIR)clang-18

HOST_ARCH       := $(shell uname -m)
TARGET_ARCH     ?= $(HOST_ARCH)

ifeq ($(HOST_ARCH),x86_64)
INCLUDES_X86_64         := /usr/include/x86_64-linux-gnu
INCLUDES_AARCH64        := /usr/aarch64-linux-gnu/include
else ifeq ($(HOST_ARCH),aarch64)
INCLUDES_X86_64     := /usr/x86_64-linux-gnu/include
INCLUDES_AARCH64        := /usr/include/aarch64-linux-gnu
else
$(error unsupported host architecture $(HOST_ARCH))
endif

INCLUDES :=
CFLAGS :=
ifeq ($(TARGET_ARCH),x86_64)
KERNEL_HEADER_DIRS      := asm bits gnu sys
define link-kernel-headers
arch/$(TARGET_ARCH)/include/$1:
	mkdir -p arch/$(TARGET_ARCH)/include
	ln -sf $(INCLUDES_X86_64)/$1 $$@
endef

$(foreach d,$(KERNEL_HEADER_DIRS),$(eval $(call link-kernel-headers,$(d))))
KERNEL_HEADERS:=$(foreach d,$(KERNEL_HEADER_DIRS),arch/$(TARGET_ARCH)/include/$(d))

INCLUDES        += -I$(shell pwd)/arch/$(TARGET_ARCH)/include
CFLAGS          += -target x86_64-pc-linux-gnu
ifneq ($(HOST_ARCH),x86_64)
CFLAGS  += --ld-path=/usr/x86_64-linux-gnu/bin/ld
endif
else ifeq ($(TARGET_ARCH),aarch64)
INCLUDES        += -I$(INCLUDES_AARCH64)
CFLAGS          += -target aarch64-pc-linux-gnu
ifneq ($(HOST_ARCH),aarch64)
CFLAGS  += --ld-path=/usr/aarch64-linux-gnu/bin/ld
endif
endif


EBPF_SOURCE=ebpf/*.c
EBPF_HEADERS=include/udpgrm*.h ebpf/*.h
EBPF_DEPS=$(EBPF_SOURCE) $(EBPF_HEADERS) Makefile $(KERNEL_HEADERS)
ebpf.o: $(EBPF_DEPS) Makefile $(KERNEL_HEADERS)
	$(CLANG_BIN) \
		$(CFLAGS) $(EXTRA_CFLAGS) \
		-g -O2 -Wall -Wextra -target bpf -mcpu=v3  \
		-Wall -Wextra -fwrapv -Wno-address-of-packed-member \
		ebpf/ebpf.c \
		$(INCLUDES) \
		-c -o $@
.PHONY: info
info: $(EBPF_DEPS) Makefile $(KERNEL_HEADERS)
	rm -f ebpf.o ebpf.su bpftool-log.tmp cov.info
	rm -rf cov_verifier_html
	$(MAKE) ebpf.o EXTRA_CFLAGS="-fstack-usage"
	sudo $(BPFTOOL) prog -d loadall ebpf.o \
		/sys/fs/bpf/tmp-info-load > bpftool-log.tmp 2>&1
	sudo rm -rf /sys/fs/bpf/tmp-info-load
	rm ebpf.o
	@echo "**** stack usage by function ****"
	@cat ebpf.su | sed -E 's/^([^ ]*):(.*)/\1\t\2/' | egrep -v "\s0\s" | column -t
	@echo "**** verifier instruction count ****"
	@egrep -e "(BEGIN PROG LOAD LOG)|^processed" bpftool-log.tmp | awk -F"'" '/BEGIN PROG LOAD LOG/ {name=$$2} /processed/ {print name,"\t", $$0}' |column -t
	@echo "*** verifier instruction count expressed as code coverage ****"
	@cat bpftool-log.tmp | bash tools/verifier_log_to_cov_2.sh > cov.info
	@genhtml -q cov.info -o cov_verifier_html --config-file .lcovrc --ignore-errors unmapped,unmapped --synthesize-missing
	@echo "xdg-open file://$(CURDIR)/cov_verifier_html/ebpf/ebpf/ebpf.c.gcov.html"


ebpf.skel.h: ebpf.o
	$(BPFTOOL) gen skeleton ebpf.o name ebpf > $@

UDPGRM_SOURCE=src/*.c
UDPGRM_HEADERS=src/*.h include/udpgrm*.h
UDPGRM_DEPS=$(UDPGRM_SOURCE) $(UDPGRM_HEADERS) ebpf.skel.h

udpgrm: $(UDPGRM_DEPS)
	$(CLANG_BIN) \
		$(UDPGRM_SOURCE) \
		$(CFLAGS) \
		$(LDFLAGS) \
		$(EXTRA_CFLAGS) \
		-g -O2 -Wall -Wextra -fwrapv -fno-omit-frame-pointer \
		-lbpf -lelf -lz -lsystemd \
		-DPACKAGE_VERSION=\"$(VERSION)\" \
		$(LIBS) \
		-o $@


MMDECOY_DEPS=tools/mmdecoy.c
mmdecoy: $(MMDECOY_DEPS)
	$(CLANG_BIN) \
		$(MMDECOY_DEPS) \
		$(CFLAGS) \
		$(LDFLAGS) \
		$(EXTRA_CFLAGS) \
		-g -O2 -Wall -Wextra -fno-omit-frame-pointer \
		-lsystemd \
		$(LIBS) \
		-o mmdecoy

udpgrm-test: $(UDPGRM_DEPS)
	rm -f udpgrm
	$(MAKE) udpgrm EXTRA_CFLAGS="-fprofile-instr-generate -fcoverage-mapping"
	mv -f udpgrm $@


tqserver: crates/udpgrm/examples/*.rs
	(cd crates/udpgrm; cargo build --release --example $@)
	cp crates/udpgrm/target/release/examples/$@ $@

client: crates/udpgrm/examples/*.rs
	(cd crates/udpgrm; cargo build --release --example $@)
	cp crates/udpgrm/target/release/examples/$@ $@

.PHONY: format
format:
	@which markdownfmt || (echo '[*] Install markdownfmt:\n\tgo install github.com/shurcooL/markdownfmt@latest'; exit 1)
	$(CLANG_DIR)clang-format -i \
		$(UDPGRM_SOURCE) \
		$(UDPGRM_HEADERS) \
		$(EBPF_SOURCE) \
		$(EBPF_HEADERS) \
		$(MMDECOY_DEPS)
	autopep8 -i *.py tests/*py examples/*py
	markdownfmt -w README.md
	@grep -n "TODO" *.[ch] *.md || true

examples/venv/.ok:
	(cd examples; virtualenv venv)
	(cd examples; ./venv/bin/pip install -r requirements.txt)
	touch $@

DATE		:= $(shell date -u '+%Y.%-m.%-d')
BUILD_NUMBER	?= 0
REVISION	:= $(shell git rev-parse --short HEAD)
TIMESTAMP	:= $(shell date -u '+%Y-%m-%d-%H:%MUTC')

VERSION		:= $(shell git describe --tags --always --exclude 'crate/*')

ifndef CI
VERSION := $(VERSION)-dev
endif


.PHONY: clean
clean:
	rm -f ebpf.skel.h ebpf.o udpgrm udpgrm_*.deb mmdecoy bpftool-log.tmp client tqserver udpgrm-test ebpf.su cov.info
	rm -rf arch cov_html crates/udpgrm/target/release/examples crates/udpgrm/target/debug/examples cov_verifier_html

TEST:=tests
.PHONY: test
test: udpgrm-test tqserver client
	@rm -rf *.profraw cov_html coverage.profdata
	sudo \
		LLVM_PROFILE_FILE="udpgrm_%p.profraw" \
		UDPGRMBIN="./udpgrm-test" \
		PYTHONPATH=. PYTHONIOENCODING=utf-8 \
		python3 -m tests.runner $(TEST)
	llvm-profdata merge -sparse udpgrm*.profraw -o coverage.profdata
	llvm-cov export \
		--instr-profile=coverage.profdata \
		./udpgrm-test --format=lcov > cov.info
	genhtml -q cov.info -o cov_html -t udpgrm --config-file .lcovrc --ignore-errors unmapped
	llvm-cov report   ./udpgrm-test   -instr-profile=coverage.profdata
	@rm -rf *.profraw cov.info coverage.profdata
	@echo "[*] Run:\n  xdg-open file://$(CURDIR)/cov_html/udpgrm/index.html"
