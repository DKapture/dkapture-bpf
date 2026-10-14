// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
//
// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "com.h"

#define MAX_ENTRIES 1000
#define MAX_EVENT_SIZE 10240
#define RINGBUF_SIZE (1024 * 256)
#define PERF_MAX_STACK_DEPTH 127
#define STACK_TRACE_ENTRIES 1024
char _license[] SEC("license") = "GPL";


const volatile __u64 skip_frame = 0;

struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, RINGBUF_SIZE);
} events SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, pid_t);
} filter SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(max_entries, STACK_TRACE_ENTRIES);
	__type(key, u32);
	__uint(value_size, PERF_MAX_STACK_DEPTH * sizeof(u64));
} stack_traces SEC(".maps");

struct tp_page_fault_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;

	unsigned long address;
	unsigned long ip;
	unsigned long error_code;
};

struct page_fault_t
{
	pid_t pid;
	pid_t tid;
	char comm[16];
	int stack_id;
	u64 timestamp;
	unsigned long address;
	unsigned long ip;
	unsigned long error_code;
};
/* Shared event filling for the fentry/kprobe variants (aarch64/loongarch);
 * the x86 tracepoint variants fill inline. */
static int fill_page_fault_event(struct pt_regs *ctx,
				 struct page_fault_t *event,
				 bool user_fault)
{
	long ret = 0;
	int key = 0;
	int stack_id = 0;
	pid_t filter_pid = 0;
	pid_t *p_filter_pid = 0;
	pid_t pid;
	u64 pid_tgid = bpf_get_current_pid_tgid();

	pid = pid_tgid >> 32;
	p_filter_pid = bpf_map_lookup_elem(&filter, &key);
	if (!p_filter_pid)
	{
		bpf_err("bpf_map_lookup_elem failed for filter: %ld", pid_tgid);
	}
	else
	{
		filter_pid = *p_filter_pid;
	}
	if (filter_pid && filter_pid != pid)
	{
		DEBUG(0, "Skipping page fault for PID: %d", pid);
		return 0;
	}
	event->pid = pid;
	event->tid = pid_tgid & 0xFFFFFFFF;
	ret = bpf_get_current_comm(event->comm, sizeof(event->comm));
	if (ret)
	{
		bpf_err("bpf_get_current_comm failed: %ld", ret);
	}
	stack_id = bpf_get_stackid(
		ctx,
		&stack_traces,
		skip_frame | (user_fault ? BPF_F_USER_STACK : 0)
	);
	if (stack_id < 0)
	{
		bpf_err("bpf_get_stackid failed: %d", stack_id);
		return 0;
	}
	event->stack_id = stack_id;
	event->timestamp = bpf_ktime_get_ns();
	ret = bpf_ringbuf_output(&events, event, sizeof(*event), 0);
	if (ret < 0)
	{
		bpf_err("bpf_ringbuf_output failed: %ld", ret);
	}
	return 0;
}

#if defined(__x86_64__)
SEC("tracepoint/exceptions/page_fault_kernel")
int page_fault_kernel(struct tp_page_fault_t *ctx)
{
	long ret = 0;
	struct page_fault_t event = {};
	int key = 0;
	int stack_id = 0;
	pid_t filter_pid = 0;
	pid_t *p_filter_pid = 0;
	pid_t pid;
	u64 pid_tgid = bpf_get_current_pid_tgid();
	pid = pid_tgid >> 32; // Get PID
	p_filter_pid = bpf_map_lookup_elem(&filter, &key);
	if (!p_filter_pid)
	{
		bpf_err("bpf_map_lookup_elem failed for filter: %ld", pid_tgid);
	}
	else
	{
		filter_pid = *p_filter_pid;
	}
	if (filter_pid && filter_pid != pid)
	{
		DEBUG(0, "Skipping page fault for PID: %d", pid);
		return 0; // Skip if not matching filter PID
	}

	event.address = ctx->address;
	event.ip = ctx->ip;
	event.error_code = ctx->error_code;
	event.pid = pid;				   // Get PID
	event.tid = pid_tgid & 0xFFFFFFFF; // Get TID
	ret = bpf_get_current_comm(event.comm, sizeof(event.comm));
	if (ret)
	{
		bpf_err("bpf_get_current_comm failed: %ld", ret);
	}
	stack_id = bpf_get_stackid(ctx, &stack_traces, skip_frame);
	if (stack_id < 0)
	{
		bpf_err("bpf_get_stackid failed: %d", stack_id);
		return 0; // Skip if stack trace retrieval failed
	}
	event.stack_id = stack_id;
	event.timestamp = bpf_ktime_get_ns();

	DEBUG(
		0,
		"Page fault at address: %lx, ip: %lx, error code: %lx",
		event.address,
		event.ip,
		event.error_code
	);

	ret = bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	if (ret < 0)
	{
		bpf_err("bpf_ringbuf_output failed: %ld", ret);
		return 0;
	}

	return 0;
}

SEC("tracepoint/exceptions/page_fault_user")
int page_fault_user(struct tp_page_fault_t *ctx)
{
	long ret = 0;
	struct page_fault_t event = {};
	int key = 0;
	int stack_id = 0;
	pid_t filter_pid = 0;
	pid_t *p_filter_pid = 0;
	pid_t pid;
	u64 pid_tgid = bpf_get_current_pid_tgid();
	pid = pid_tgid >> 32; // Get PID
	p_filter_pid = bpf_map_lookup_elem(&filter, &key);
	if (!p_filter_pid)
	{
		bpf_err("bpf_map_lookup_elem failed for filter: %ld", pid_tgid);
	}
	else
	{
		filter_pid = *p_filter_pid;
	}
	if (filter_pid && filter_pid != pid)
	{
		DEBUG(0, "Skipping page fault for PID: %d", pid);
		return 0; // Skip if not matching filter PID
	}

	event.address = ctx->address;
	event.ip = ctx->ip;
	event.error_code = ctx->error_code;
	event.pid = pid;				   // Get PID
	event.tid = pid_tgid & 0xFFFFFFFF; // Get TID
	ret = bpf_get_current_comm(event.comm, sizeof(event.comm));
	if (ret)
	{
		bpf_err("bpf_get_current_comm failed: %ld", ret);
	}
	stack_id =
		bpf_get_stackid(ctx, &stack_traces, skip_frame | BPF_F_USER_STACK);
	if (stack_id < 0)
	{
		bpf_err("bpf_get_stackid failed: %d", stack_id);
		return 0; // Skip if stack trace retrieval failed
	}
	event.stack_id = stack_id;
	event.timestamp = bpf_ktime_get_ns();

	DEBUG(
		0,
		"User page fault at address: %lx, ip: %lx, error code: %lx",
		event.address,
		event.ip,
		event.error_code
	);

	ret = bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	if (ret < 0)
	{
		bpf_err("bpf_ringbuf_output failed: %ld", ret);
		return 0;
	}

	return 0;
}
#elif defined(__aarch64__)
#define PSR_MODE_MASK	0xf
#define PSR_MODE_EL0t	0x0

static bool fault_user_mode(struct pt_regs *regs)
{
	return (BPF_CORE_READ(regs, pstate) & PSR_MODE_MASK) == PSR_MODE_EL0t;
}

SEC("fentry/do_page_fault")
int BPF_PROG(page_fault_kernel, unsigned long far, unsigned long esr,
	     struct pt_regs *regs)
{
	struct page_fault_t event = {};

	if (fault_user_mode(regs))
	{
		return 0; /* kernel-mode faults only (-k) */
	}
	event.address = far;                 /* faulting address */
	event.ip = BPF_CORE_READ(regs, pc);  /* faulting pc, com.h KSTK_EIP 惯例 */
	event.error_code = esr;
	return fill_page_fault_event(ctx, &event, false);
}

SEC("fentry/do_page_fault")
int BPF_PROG(page_fault_user, unsigned long far, unsigned long esr,
	     struct pt_regs *regs)
{
	struct page_fault_t event = {};

	if (!fault_user_mode(regs))
	{
		return 0; /* user-mode faults only (-u) */
	}
	event.address = far;
	event.ip = BPF_CORE_READ(regs, pc);
	event.error_code = esr;
	return fill_page_fault_event(ctx, &event, true);
}
#elif defined(__loongarch__)
#define CSR_PRMD_PPLV_MASK	0x3
#define CSR_PLV_USER		3

static bool fault_user_mode(struct pt_regs *regs)
{
	return (BPF_CORE_READ(regs, csr_prmd) & CSR_PRMD_PPLV_MASK) == CSR_PLV_USER;
}

SEC("kprobe/handle_mm_fault")
int page_fault_kernel(struct pt_regs *ctx)
{
	unsigned long address = PT_REGS_PARM2(ctx);
	struct pt_regs *regs = (struct pt_regs *)PT_REGS_PARM4(ctx);
	struct page_fault_t event = {};

	if (fault_user_mode(regs))
	{
		return 0; /* kernel-mode faults only (-k) */
	}
	event.address = address;
	event.ip = BPF_CORE_READ(regs, csr_era);  /* 缺页现场 PC */
	event.error_code = PT_REGS_PARM3(ctx);    /* FAULT_FLAG_* */
	return fill_page_fault_event(ctx, &event, false);
}

SEC("kprobe/handle_mm_fault")
int page_fault_user(struct pt_regs *ctx)
{
	unsigned long address = PT_REGS_PARM2(ctx);
	struct pt_regs *regs = (struct pt_regs *)PT_REGS_PARM4(ctx);
	struct page_fault_t event = {};

	if (!fault_user_mode(regs))
	{
		return 0; /* user-mode faults only (-u) */
	}
	event.address = address;
	event.ip = BPF_CORE_READ(regs, csr_era);
	event.error_code = PT_REGS_PARM3(ctx);
	return fill_page_fault_event(ctx, &event, true);
}
#endif