# 준비
---
`libbpf`에 필요한 준비물
- `clang`
	- eBPF 커널 프로그램을 BPF 바이트코드로 컴파일하는 프로그램이다.
	- `gcc`는 eBPF 타겟을 지원하지 않기 때문에, `clang`이 필수적이다.
- `llvm`
	- `clang`이 내부적으로 사용하는 컴파일 백엔드다.
	- `clang`이 C 프로그램을 읽고 LLVM IR을 생성하면, llvm은 그 IR을 eBPF 바이트코드로 컴파일한다.
- `libbpf-dev`
	- 사용자 공간에서 eBPF 파일을 로딩하고, attach하고, map에 접근하기 위한 API를 제공한다.
	- `libbpf.so` 동적 라이브러리 자체,
	- `/usr/include/bpf/libbpf.h` 등 헤더 파일을 포함한다.
- `libelf-dev`
	- ELF 포멧의 eBPF 오브젝트 파일을 파싱하고 조작하기 위한 라이브러리다.
- `zlib1g-dev`
	- ELF 압축 데이터 해제 등에 사용된다.
	- libelf의 의존성으로 사용된다.
- `make`
	- 빌드 자동화 도구다.
- `bpftool`
	- eBPF 프로그램을 확인, 관리, 디버깅하기 위한 공식 CLI 도구다.

`vmlinux.h` 생성 (CO-RE 용)
- CO-RE란?
	- Compile Once - Run Everywhere의 약자로, 한 번 컴파일한 eBPF 프로그램을 커널 버전에 상관 없이 돌릴 수 있게 만드는 기술
	- 리눅스 커널 버전마다 내부 구조체가 바뀐다. 따라서 바이트 위치를 하드코딩하면 커널 버전마다 새로 프로그래밍 한 뒤 컴파일해야 한다.
	- 구조체의 멤버로 접근하게 되면 상대적인 위치로 접근하기 때문에 구조체의 바이트가 바뀌어도 문제가 없다.
	- 이를 위해선 커널의 구조체 정보를 받아와야 한다. 다음은 커널의 구조체 정보를 받아오는 코드다.

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```
- 커널이 BTF를 지원해야 `/sys/kernel/btf/vmlinux`가 존재한다.
- 해당 파일 내용을 C 코드로 변환하여 `vmlinux.h` 파일에 저장한다.

# BPF 커널 코드 (`process_monitor.bpf.c`)
---
```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct event {
    u32 pid;
    char comm[16];
    char type; // 'F' or 'E'
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("tracepoint/sched/sched_process_fork")
int on_fork(struct trace_event_raw_sched_process_fork *ctx) {
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = ctx->child_pid;
    e->type = 'F';
    bpf_core_read_str(&e->comm, sizeof(e->comm), ctx->child_comm);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int on_exit(struct trace_event_raw_sched_process_template *ctx) {
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->type = 'E';
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
```

```c
struct event {
    u32 pid;
    char comm[16];
    char type; // 'F' or 'E'
};
```
- 사용자 공간에 전달할 이벤트의 구조체다.
- `pid`와 프로그램 이름인 `comm`, 그리고 프로세스 진입인지 종료인지에 따라 `type`이 `F` 혹은 `E`가 된다.

```c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");
```
- `events`라는 이름을 갖는 구조체 변수를 하나 선언한다.
- 해당 구조체에는 `map`을 정의하는 명세서가 들어있다.
	- `type`은 링버퍼이고, 크기는 `2^24B = 16MB`이다.
- `SEC(".maps");`를 통해 이 구조체를 `.maps` 섹션에 추가한다.

```c
SEC("tracepoint/sched/sched_process_fork")
int on_fork(struct trace_event_raw_sched_process_fork *ctx) {
    ...
    return 0;
}
```
- 마찬가지로 `SEC`를 통해 해당 섹션에 다음 함수의 바이트 코드를 추가한다.

```c
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
```
- `events`의 링버퍼에서, `struct event`의 크기만큼을 예약한다. 문제가 없다면 예약된 메모리의 주소가 반환된다.
- 문제가 생기면 `NULL` 포인터가 반환된다. 따라서 이어지는 조건문에서 종료된다.
- 세 번째 인자는 `flags`로, `0`을 두면 기본값을 사용한다. 기본값은 버퍼에 내용물을 채우면 유저공간을 깨운다.

```c
    e->pid = ctx->child_pid;
    e->type = 'F';
    bpf_core_read_str(&e->comm, sizeof(e->comm), ctx->child_comm);
```
- `ctx`에 담긴 값으로 유저 공간에 전할 구조체 값을 채운다.
- eBPF에서는 다른 주소에 있는 메모리에서 값을 복사하려면 반드시 helper 함수를 써야 한다.

```c
    bpf_ringbuf_submit(e, 0);
    return 0;
```
- 이전에 예약해둔 `e`를 실제로 전송한다.
- 두 번째 인자인 `flags`는 현재 `0`만 가능하다.

```c
    e->pid = bpf_get_current_pid_tgid() >> 32;
```
- `bpf_get_current_pid_tgid()`는 현재 실행 중인 프로세스의 PID와 Thread Group ID를 함께 64bit로 반환하는 eBPF helper 함수다.
- PID는 상위 32bit에 저장되어있기 때문에, shift 연산을 수행한다.

```c
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
```
- 현재 실행중인 task의 이름(`comm`)을, `e->comm`에 `sizeof(e->comm)`만큼 저장한다.

# 사용자 공간 코드(`WeBPF_user.c`)
---
```c
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "event.h"

#define BPF_OBJ_FILE "WeBPF.bpf.o"

static volatile sig_atomic_t exiting = 0;

// 1) 반환형을 int로 바꾸고 맨 끝에 return 0 추가
int handle_event(void *ctx, void *data, size_t len) {
    struct event *e = data;
    printf("{\"event\":\"%c\",\"pid\":%u,\"comm\":\"%s\"}\n",
           e->type, e->pid, e->comm);
    fflush(stdout);
    return 0;
}

void sig_handler(int sig) {
    exiting = 1;
}

int main() {
    struct bpf_object *obj;
    struct bpf_map *rb_map;
    struct bpf_program *prog;
    struct ring_buffer *rb;
    int map_fd;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // 2) open_file 수정: obj = bpf_object__open_file(...)
    obj = bpf_object__open_file(BPF_OBJ_FILE, NULL);
    if (!obj) {
        fprintf(stderr, "failed to open BPF object\n");
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "failed to load BPF object\n");
        return 1;
    }

    rb_map = bpf_object__find_map_by_name(obj, "events");
    if (!rb_map) {
        fprintf(stderr, "failed to find map\n");
        return 1;
    }

    map_fd = bpf_map__fd(rb_map);
    rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "failed to create ring buffer\n");
        return 1;
    }

    // 3) prog_exit 제거, 한 변수(prog)로 처리
    bpf_object__for_each_program(prog, obj) {
        const char *sec = bpf_program__section_name(prog);
        if (strstr(sec, "sched_process_fork") ||
            strstr(sec, "sched_process_exit")) {
            bpf_program__attach_tracepoint(
                prog, "sched",
                strstr(sec, "fork") ? "sched_process_fork"
                                     : "sched_process_exit");
        }
    }

    printf("Monitoring process events...\n");
    while (!exiting)
        ring_buffer__poll(rb, 100);

    ring_buffer__free(rb);
    bpf_object__close(obj);
    return 0;
}
```

# Makefile
---
```makefile
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
```

# `fork()` 이벤트의 `comm`이 빈 문자열로 나오는 문제
---
`bpf_core_read_str`은 CO-RE 대상만 지원한다. 따라서 임의 커널 메모리에서
문자열을 복사하려면 `bpf_probe_read_str`을 사용해야 한다.

```diff
--- process_monitor.bpf.c
@@ SEC("tracepoint/sched/sched_process_fork")
-   bpf_core_read_str(&e->comm, sizeof(e->comm), ctx->child_comm);
+   bpf_probe_read_str(e->comm, sizeof(e->comm), ctx->child_comm);
```

# `fork()` 이벤트의 `comm`이 `fork()`를 호출한 프로세스의 것으로 나오는 문제
---
`bash`에서 `./a.out`을 실행하게 되면 해당 `fork()`의 `comm`이 `a.out`이 아니라 `bash`로 나온다. 이는 자식 프로세스가 생성되고 `exec`를 호출하기 전에 로그를 수집해 발생한 문제로 추정된다.