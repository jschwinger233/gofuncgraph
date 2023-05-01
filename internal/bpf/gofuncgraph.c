// +build ignore

#include "vmlinux.h"
#include "bpf_helpers.h"

#define MAX_DATA_SIZE 64

#define ENTPOINT 0
#define RETPOINT 1

#define fsbase_off (offsetof(struct task_struct, thread) \
		    + offsetof(struct thread_struct, fsbase))

char __license[] SEC("license") = "Dual MIT/GPL";

struct config {
	__s64 goid_offset;
	__s64 g_offset;
	bool fetch_args;
	__u8 padding[7];
};

static volatile const struct config CONFIG = {};

struct event {
	__u64 goid;
	__u64 ip;
	__u64 bp;
	__u64 caller_ip;
	__u64 caller_bp;
	__u64 time_ns;
	__u8 location;
};

// force emitting struct event into the ELF.
const struct event *_ __attribute__((unused));

struct arg_rule {
	__u8 type;
	__u8 reg;
	__u8 size;
	__u8 length;
	__s16 offsets[8];
};

struct arg_rules {
	__u8 length;
	struct arg_rule rules[8];
};

const struct arg_rules *__ __attribute__((unused));

struct arg_data {
	__u64 goid;
	__u8 data[MAX_DATA_SIZE];
};

const struct arg_data *___ __attribute__((unused));

struct bpf_map_def SEC("maps") arg_rules_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(struct arg_rules),
	.max_entries = 100,
};

struct bpf_map_def SEC("maps") arg_queue = {
	.type = BPF_MAP_TYPE_QUEUE,
	.key_size = 0,
	.value_size = sizeof(struct arg_data),
	.max_entries = 10000,
};

struct bpf_map_def SEC("maps") arg_stack = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct arg_data),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") event_queue = {
	.type = BPF_MAP_TYPE_QUEUE,
	.key_size = 0,
	.value_size = sizeof(struct event),
	.max_entries = 10000,
};

struct bpf_map_def SEC("maps") event_stack = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct event),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") should_trace_goid = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(bool),
	.max_entries = 10000,
};

struct bpf_map_def SEC("maps") should_trace_rip = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(bool),
	.max_entries = 10000,
};

static __always_inline
__u64 get_goid()
{
	__u64 tls_base, g_addr, goid;
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	bpf_probe_read_kernel(&tls_base, sizeof(tls_base), (void *)task + fsbase_off);
	bpf_probe_read_user(&g_addr, sizeof(g_addr), (void *)(tls_base+CONFIG.g_offset));
	bpf_probe_read_user(&goid, sizeof(goid), (void *)(g_addr+CONFIG.goid_offset));
	return goid;
}

static __always_inline
void read_reg(struct pt_regs *ctx, __u8 reg, __u64 *regval)
{
	switch (reg) {
	case 0:
		bpf_probe_read_kernel(regval, sizeof(ctx->ax), &ctx->ax);
		break;
	case 1:
		bpf_probe_read_kernel(regval, sizeof(ctx->dx), &ctx->dx);
		break;
	case 2:
		bpf_probe_read_kernel(regval, sizeof(ctx->cx), &ctx->cx);
		break;
	case 3:
		bpf_probe_read_kernel(regval, sizeof(ctx->bx), &ctx->bx);
		break;
	case 4:
		bpf_probe_read_kernel(regval, sizeof(ctx->si), &ctx->si);
		break;
	case 5:
		bpf_probe_read_kernel(regval, sizeof(ctx->di), &ctx->di);
		break;
	case 6:
		bpf_probe_read_kernel(regval, sizeof(ctx->bp), &ctx->bp);
		break;
	case 7:
		bpf_probe_read_kernel(regval, sizeof(ctx->sp), &ctx->sp);
		break;
	case 8:
		bpf_probe_read_kernel(regval, sizeof(ctx->r8), &ctx->r8);
		break;
	case 9:
		bpf_probe_read_kernel(regval, sizeof(ctx->r9), &ctx->r9);
		break;
	case 10:
		bpf_probe_read_kernel(regval, sizeof(ctx->r10), &ctx->r10);
		break;
	case 11:
		bpf_probe_read_kernel(regval, sizeof(ctx->r11), &ctx->r11);
		break;
	case 12:
		bpf_probe_read_kernel(regval, sizeof(ctx->r12), &ctx->r12);
		break;
	case 13:
		bpf_probe_read_kernel(regval, sizeof(ctx->r13), &ctx->r13);
		break;
	case 14:
		bpf_probe_read_kernel(regval, sizeof(ctx->r14), &ctx->r14);
		break;
	case 15:
		bpf_probe_read_kernel(regval, sizeof(ctx->r15), &ctx->r15);
		break;
	}
	return;
}

static __always_inline
void fetch_args_from_reg(struct pt_regs *ctx, struct arg_data *data, struct arg_rule *rule)
{
	read_reg(ctx, rule->reg, (__u64 *)&data->data);
	bpf_map_push_elem(&arg_queue, data, BPF_EXIST);
	return;
}

static __always_inline
void fetch_args_from_memory(struct pt_regs *ctx, struct arg_data *data, struct arg_rule *rule)
{
	__u64 addr = 0;
	read_reg(ctx, rule->reg, &addr);

	for (int i = 0; i < 8; i++) {
		if (i == rule->length - 1)
			break;
		bpf_probe_read_user(&addr, sizeof(addr), (void *)addr+rule->offsets[i]);
	}
	bpf_probe_read_user(&data->data,
			    rule->size < MAX_DATA_SIZE ? rule->size : MAX_DATA_SIZE,
			    (void *)addr);
	bpf_map_push_elem(&arg_queue, data, BPF_EXIST);
	return;
}

static __always_inline
void fetch_args(struct pt_regs *ctx, __u64 goid, __u64 ip)
{
	struct arg_rules *rules = bpf_map_lookup_elem(&arg_rules_map, &ip);
	if (!rules)
		return;

	__u32 key = 0;
	struct arg_data *data = bpf_map_lookup_elem(&arg_stack, &key);
	if (!data)
		return;

	__builtin_memset(data, 0, sizeof(*data));
	data->goid = goid;

	for (int i = 0; i < 8; i++) {
		if (rules->length == i)
			break;
		switch (rules->rules[i].type) {
		case 0:
			fetch_args_from_reg(ctx, data, &rules->rules[i]);
			break;
		case 1:
			fetch_args_from_memory(ctx, data, &rules->rules[i]);
			break;
		}
	}
}

SEC("uprobe/ent")
int ent(struct pt_regs *ctx)
{
	__u32 key = 0;
	struct event *e = bpf_map_lookup_elem(&event_stack, &key);
	if (!e)
		return 0;
	__builtin_memset(e, 0, sizeof(*e));

	e->goid = get_goid();
	e->ip = ctx->ip;
	if (!bpf_map_lookup_elem(&should_trace_rip, &e->ip)) {
		if (!bpf_map_lookup_elem(&should_trace_goid, &e->goid))
			return 0;

	} else if (!bpf_map_lookup_elem(&should_trace_goid, &e->goid)) {
		__u64 should_trace = true;
		bpf_map_update_elem(&should_trace_goid, &e->goid, &should_trace,
				    BPF_ANY);
	}

	e->location = ENTPOINT;
	e->time_ns = bpf_ktime_get_ns();
	e->bp = ctx->sp - 8;
	e->caller_bp = ctx->bp;

	void *ra;
	ra = (void*)ctx->sp;
	bpf_probe_read_user(&e->caller_ip, sizeof(e->caller_ip), ra);

	if (!CONFIG.fetch_args)
		goto cont;

	fetch_args(ctx, e->goid, e->ip);

cont:
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
	if (!bpf_map_lookup_elem(&should_trace_goid, &e->goid))
		return 0;

	e->location = RETPOINT;
	e->ip = ctx->ip;
	e->time_ns = bpf_ktime_get_ns();

	return bpf_map_push_elem(&event_queue, e, BPF_EXIST);
}

SEC("uprobe/goroutine_exit")
int goroutine_exit(struct pt_regs *ctx)
{
	__u64 goid = get_goid();
	bpf_map_delete_elem(&should_trace_goid, &goid);
	return 0;
}
