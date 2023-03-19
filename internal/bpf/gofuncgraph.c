// +build ignore

#include "vmlinux.h"
#include "bpf_helpers.h"

#define MAX_DATA_SIZE 100

#define ENTPOINT 0
#define RETPOINT 1

#define GOID_OFFSET 152

#define fsbase_off (offsetof(struct task_struct, thread) \
		    + offsetof(struct thread_struct, fsbase))

char __license[] SEC("license") = "Dual MIT/GPL";

struct event {
	__u64 goid;
	__u64 ip;
	__u64 bp;
	__u64 caller_ip;
	__u64 caller_bp;
	__u64 time_ns;
	__u8 location;
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

struct bpf_map_def SEC("maps") event_stack = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct event),
	.max_entries = 1,
};

static __always_inline
__u64 get_goid()
{
	__u64 tls_base, g_addr, goid;
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	bpf_probe_read_kernel(&tls_base, sizeof(tls_base), (void *)task + fsbase_off);
	bpf_probe_read_user(&g_addr, sizeof(g_addr), (void *)(tls_base-8));
	bpf_probe_read_user(&goid, sizeof(goid), (void *)(g_addr+GOID_OFFSET));
	return goid;
}

SEC("uprobe/ent")
int ent(struct pt_regs *ctx)
{
	__u32 key = 0;
	struct event *e = bpf_map_lookup_elem(&event_stack, &key);
	if (!e)
		return 0;
	__builtin_memset(e, 0, sizeof(*e));

	// manipulate bpf inst
	//void *a, *b;
	//__u8 c;
	//bpf_probe_read_user(&b, sizeof(a), (void*)a);
	//bpf_probe_read_user(&e->data, 8, (void*)a);
	//__builtin_memcpy(&e->data, &ctx->ax, 4);
	// manipulation ends

	e->goid = get_goid();
	e->location = ENTPOINT;
	e->ip = ctx->ip;
	e->time_ns = bpf_ktime_get_ns();
	e->bp = ctx->sp - 8;
	e->caller_bp = ctx->bp;

	void *ra;
	ra = (void*)ctx->sp;
	bpf_probe_read_user(&e->caller_ip, sizeof(e->caller_ip), ra);

	return bpf_map_push_elem(&event_queue, e, BPF_EXIST);
}

SEC("uprobe/ret")
int ret(struct pt_regs *ctx)
{
	__u32 key = 0;
	struct event *e = bpf_map_lookup_elem(&event_stack, &key);
	if (!e)
		return 0;
	__builtin_memset(e, 0, sizeof(*e));

	e->goid = get_goid();
	e->location = RETPOINT;
	e->ip = ctx->ip;
	e->time_ns = bpf_ktime_get_ns();

	return bpf_map_push_elem(&event_queue, e, BPF_EXIST);
}
