CC       = gcc
CFLAGS   = -O2 -Wall -Wno-unused-function
RV64_CC  = riscv64-linux-gnu-gcc
RV64_FLAGS = -O2 -Wall -Wno-unused-function -static
QEMU     = qemu-riscv64-static

.PHONY: all test.x86-64 test.rv64 clean

all: test.x86-64 test.rv64

test.x86-64: test.x86-64.c jit.h
	$(CC) $(CFLAGS) -o $@ $<
	./$@

test.rv64: test.rv64.c jit.h
	$(RV64_CC) $(RV64_FLAGS) -o $@ $<
	$(QEMU) ./$@

run: test.x86-64

run-rv64:
	$(QEMU) ./test.rv64

clean:
	rm -f test.x86-64 test.rv64
