# Makefile for eBPF project

BPF_CLANG	= clang
BPF_OBJ		= WeBPF.bpf.o
USER_OBJ	= WeBPF_user
BPF_SRC		= WeBPF.bpf.c
USER_SRC	= WeBPF_user.c
CFLAGS		= -g -Wall -O2

INCLUDES	= -I. -I/usr/include -I/usr/include/aarch64-linux-gnu
LIBS		= -lbpf -lelf -lz

all: $(BPF_OBJ) $(USER_OBJ)

$(BPF_OBJ): $(BPF_SRC) event.h
	$(BPF_CLANG) -target bpf -D__TARGET_ARCH_$(shell uname -m) -Wall -O2 -g \
		-c $(BPF_SRC) -o $(BPF_OBJ) -I.

$(USER_OBJ): $(USER_SRC) event.h
	gcc $(CFLAGS) $(USER_SRC) -o $(USER_OBJ) $(INCLUDES) $(LIBS)

clean:
	rm -f *.o $(USER_OBJ)
