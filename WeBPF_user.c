#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "vmlinux.h"
#include "event.h"

#define BPF_OBJ_FILE "WeBPF.bpf.o"

static volatile sig_atomic_t exiting = 0;

void handle_event(void *ctx, void *data, size_t len) {
	struct event *e = data;
	printf("{\"event\":\"%c\",\"pid\":%u,\"comm\":\"%s\"}\n", e->type, e->pid, e->comm);
	fflush(stdout);
}

void sig_handler(int sig) {
	exiting = 1;
}

int main() {
	struct bpf_object *obj = NULL;
	struct bpf_map *rb_map = NULL;
	struct bpf_program *prog_fork = NULL, *prog_exit = NULL;
	struct ring_buffer *rb = NULL;
	int err;

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	err = bpf_object__open_file(BPF_OBJ_FILE, NULL, &obj);
	if (err || !obj) {
		fprintf(stderr, "failed to open BPF object: %d\n", err);
		return 1;
	}

	err = bpf_object__load(obj);
    	if (err) {
        	fprintf(stderr, "failed to load BPF object: %d\n", err);
        	return 1;
    	}

	rb_map = bpf_object__find_map_by_name(obj, "events");
    	if (!rb_map) {
        	fprintf(stderr, "failed to find map\n");
        	return 1;
    	}

	int map_fd = bpf_map__fd(rb_map);

	rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "failed to create ring buffer\n");
		return 1;
	}

	bpf_object__for_each_program(prog_fork, obj) {
		const char *sec_name = bpf_program__section_name(prog_fork);
		if (strstr(sec_name, "sched_process_fork") || strstr(sec_name, "sched_process_exit")) {
			bpf_program__attach_tracepoint(prog_fork, "sched", strstr(sec_name, "fork") ? "sched_process_fork" : "sched_process_exit");
		}
	}

	printf("Monitoring process events...\n");
	while (!exiting) {
		ring_buffer__poll(rb, 100);
	}

	ring_buffer__free(rb);
	bpf_object__close(obj);
	return 0;
}

