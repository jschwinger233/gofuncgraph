// +build ignore

#include "vmlinux.h"
#include "bpf_helpers.h"

#define MAX_STACK_LAYERS 1000
#define MAX_DATA_SIZE 100
#define BPF_MAX_VAR_SIZ	(1 << 29)

#define ENTPOINT 0
#define RETPOINT 1

#define STACKOVERFLOWERR 1

#define GOID_OFFSET 152

char __license[] SEC("license") = "Dual MIT/GPL";

struct event {
    __u64 goid;
    __u64 caller_ip;
    __u64 ip;
    __u64 time_ns;
    __u8 location;
    __u8 errno;
    __u8 data[MAX_DATA_SIZE];
};

// force emitting struct event into the ELF.
const struct event *unused __attribute__((unused));

// event_queue is for events commit
struct bpf_map_def SEC("maps") event_queue = {
    .type = BPF_MAP_TYPE_QUEUE,
    .key_size = 0,
    .value_size = sizeof(struct event),
    .max_entries = 1000000,
};

struct bpf_map_def SEC("maps") bpf_stack = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct event),
    .max_entries = 1,
};

struct {
   __uint(type, BPF_MAP_TYPE_RINGBUF);
   __uint(max_entries, BPF_MAX_VAR_SIZ);
} heap SEC(".maps");

static __always_inline
__u64 get_goid()
{
    __u64  _goid, goid;
    size_t g_addr;
    struct task_struct *task;
    task = bpf_ringbuf_reserve(&heap, sizeof(struct task_struct), 0);
    if (!task)
        return 0;

    __u64 task_ptr = bpf_get_current_task();
    if (!task_ptr)
	    goto exit;

    bpf_probe_read_kernel(task, sizeof(struct task_struct), (void*)(task_ptr));
    bpf_probe_read_user(&g_addr, sizeof(void *), (void*)(task->thread.fsbase-8));
    bpf_probe_read_user(&_goid, sizeof(void *), (void*)(g_addr+GOID_OFFSET));
    goid = _goid;

exit:
    bpf_ringbuf_discard(task, 0);
    return goid;
}

SEC("uprobe/ent")
int ent(struct pt_regs *ctx) {
    __u32 key = 0;
    struct event *e = bpf_map_lookup_elem(&bpf_stack, &key);
    if (!e)
        return 0; // should not happen
    __builtin_memset(e, 0, sizeof(*e));

    // manipulate bpf inst
    //void *a, *b;
    //__u8 c;
    //bpf_probe_read_user(&b, sizeof(a), (void*)a);
    //bpf_probe_read_user(&e->data, 8, (void*)a);
    //__builtin_memcpy(&e->data, &ctx->ax, 4);
    // manipulation ends

    __u64 this_bp = ctx->bp;
    e->goid = get_goid();
    e->location = ENTPOINT;
    e->ip = ctx->ip;
    e->time_ns = bpf_ktime_get_ns();

    void *ra;
    ra = (void*)ctx->bp+8;
    bpf_probe_read_user(&e->caller_ip, sizeof(e->caller_ip), ra);

    return bpf_map_push_elem(&event_queue, e, BPF_EXIST);
}

SEC("uprobe/ret")
int ret(struct pt_regs *ctx) {
    __u32 key = 0;
    struct event *e = bpf_map_lookup_elem(&bpf_stack, &key);
    if (!e)
        return 0; // should not happen
    __builtin_memset(e, 0, sizeof(*e));

    e->goid = get_goid();
    e->location = RETPOINT;
    e->ip = ctx->ip;
    e->time_ns = bpf_ktime_get_ns();

    return bpf_map_push_elem(&event_queue, e, BPF_EXIST);
}
