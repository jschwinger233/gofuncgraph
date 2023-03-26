// +build ignore

#include "vmlinux.h"
#include "bpf_helpers.h"

#define MAX_DATA_SIZE 64

#define ENTPOINT 0
#define RETPOINT 1

#define GOID_OFFSET 152

#define fsbase_off (offsetof(struct task_struct, thread) \
		    + offsetof(struct thread_struct, fsbase))

char __license[] SEC("license") = "Dual MIT/GPL";

struct config {
	bool fetch_args;
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
	__u64 ip;
	__u64 regval;
	__u8 data[MAX_DATA_SIZE];
};

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

static __always_inline
void fetch_args_from_reg(struct pt_regs *ctx, struct arg_data *data, struct arg_rule *rule)
{
	switch (rule->type) {
	case 0:
		data->regval = ctx->ax;
	case 1:
		data->regval = ctx->dx;
	case 2:
		data->regval = ctx->cx;
	case 3:
		data->regval = ctx->bx;
	case 4:
		data->regval = ctx->si;
	case 5:
		data->regval = ctx->di;
	case 6:
		data->regval = ctx->bp;
	case 7:
		data->regval = ctx->sp;
	case 8:
		data->regval = ctx->r8;
	case 9:
		data->regval = ctx->r9;
	case 10:
		data->regval = ctx->r10;
	case 11:
		data->regval = ctx->r11;
	case 12:
		data->regval = ctx->r12;
	case 13:
		data->regval = ctx->r13;
	case 14:
		data->regval = ctx->r14;
	case 15:
		data->regval = ctx->r15;
	}
	bpf_map_push_elem(&arg_queue, data, BPF_EXIST);
	return;
}

static __always_inline
void fetch_args_from_stack(struct pt_regs *ctx, struct arg_data *data, struct arg_rule *rule)
{
	__u64 addr = ctx->sp;
	for (int i = 0; i < 8; i++) {
		if (i == rule->length)
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
	data->ip = ip;

	for (int i = 0; i < 8; i++) {
		if (rules->length == i)
			break;
		switch (rules->rules[i].type) {
		case 0:
			fetch_args_from_reg(ctx, data, &rules->rules[i]);
			break;
		case 1:
			fetch_args_from_stack(ctx, data, &rules->rules[i]);
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
	e->location = ENTPOINT;
	e->ip = ctx->ip;
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
	e->location = RETPOINT;
	e->ip = ctx->ip;
	e->time_ns = bpf_ktime_get_ns();

	return bpf_map_push_elem(&event_queue, e, BPF_EXIST);
}
