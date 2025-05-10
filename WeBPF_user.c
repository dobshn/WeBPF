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

