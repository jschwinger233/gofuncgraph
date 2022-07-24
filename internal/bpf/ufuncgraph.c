// +build ignore

#include "common.h"
#include "bpf_tracing.h"

#define MAX_STACK_LAYERS 1000
#define MAX_BT_LAYERS 50
#define MAX_DATA_SIZE 100

#define ENTPOINT 0
#define RETPOINT 1

#define STACKOVERFLOWERR 1

char __license[] SEC("license") = "Dual MIT/GPL";

struct event {
    __u64 stack_id;
    __u64 caller_ip;
    __u64 ip;
    __u64 time_ns;
    __u16 stack_depth;
    __u8 location;
    __u8 errno;
    __u8 bt[MAX_BT_LAYERS*8];
    __u8 data[MAX_DATA_SIZE];
};

// force emitting struct event into the ELF.
const struct event *unused __attribute__((unused));

struct stackwalk {
    __u64 depth;
    __u64 root_bp;
    __u64 stack_id;
};

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

// goids is for stack_id generation
struct bpf_map_def SEC("maps") goids = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 1,
};

void static backtrace(__u64 bp, struct stackwalk *walk, __u8 *bt_data, __u8 bt) {
    for (walk->depth = 0; walk->depth < MAX_STACK_LAYERS; walk->depth++) {
        if (bpf_probe_read_user(&walk->stack_id, sizeof(walk->stack_id), (void*)bp) < 0) {
            walk->stack_id = bp;
            return;
        }
        walk->root_bp = bp;
        bp = walk->stack_id;
        if (bt == 1 && walk->depth < MAX_BT_LAYERS)
            if (bpf_probe_read_user(bt_data + walk->depth*8, sizeof(__u8)*8, (void*)bp+8) < 0)
                return;
    }
    walk->depth = 0xffffffffffffffff;
    return;
}

__u64 static new_stack_id() {
    __u32 key = 0;
    __u32 *stack_id = bpf_map_lookup_elem(&goids, &key);;
    if (!stack_id)
        return 0; // should not happen
    (*stack_id)++;
    __u32 cpu = bpf_get_smp_processor_id();
    return (*stack_id) | ((__u64)cpu << 32);
}

int static do_entpoint(struct pt_regs *ctx, __u8 bt) {
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
    //__builtin_memcpy(&e->data, &ctx->rax, 4);
    // manipulation ends

    __u64 this_bp = ctx->rbp;
    e->location = ENTPOINT;
    e->ip = ctx->rip;
    bpf_probe_read_user(&e->caller_ip, sizeof(e->caller_ip), (void*)ctx->rbp+8);
    e->time_ns = bpf_ktime_get_ns();

    __u64 caller_bp;
    bpf_probe_read_user(&caller_bp, sizeof(caller_bp), (void*)ctx->rbp);

    struct stackwalk walk;
    __builtin_memset(&walk, 0, sizeof(walk));
    backtrace(ctx->rbp, &walk, e->bt, bt);
    e->stack_depth = walk.depth;
    e->stack_id = walk.stack_id;
    if (walk.depth == 0xffffffffffffffff) {
        e->errno = STACKOVERFLOWERR;
        goto submit_event;
    }

    if (e->stack_id == 0) {
        e->stack_id = new_stack_id();
        bpf_probe_write_user((void*)walk.root_bp, &e->stack_id, sizeof(e->stack_id));
        goto submit_event;
    }

submit_event:
    bpf_map_push_elem(&event_queue, e, BPF_EXIST);
    return 0;
}

SEC("uprobe/entpoint_with_bt")
int entpoint_with_bt(struct pt_regs *ctx) {
    return do_entpoint(ctx, 1);
}

SEC("uprobe/entpoint")
int entpoint(struct pt_regs *ctx) {
    return do_entpoint(ctx, 0);
}

SEC("uprobe/retpoint")
int retpoint(struct pt_regs *ctx) {
    __u32 key = 0;
    struct event *e = bpf_map_lookup_elem(&bpf_stack, &key);
    if (!e)
        return 0; // should not happen
    __builtin_memset(e, 0, sizeof(*e));
    e->location = RETPOINT;
    e->ip = ctx->rip;
    e->time_ns = bpf_ktime_get_ns();

    __u64 this_bp = ctx->rsp - 8;

    struct stackwalk walk;
    __builtin_memset(&walk, 0, sizeof(walk));
    backtrace(this_bp, &walk, NULL, 0);
    e->stack_depth = walk.depth;
    e->stack_id = walk.stack_id;
    if (walk.depth == 0xffffffffffffffff) {
        e->errno = STACKOVERFLOWERR;
        goto submit_event;
    }

    if (e->stack_id == 0) {
        return 0; // dangling exit, do nothing
    }

submit_event:
    bpf_map_push_elem(&event_queue, e, BPF_EXIST);
    return 0;
}
