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

#if defined(__x86_64__)
#define fault_user_mode(regs) (false)
#elif defined(__aarch64__)
#define PSR_MODE_MASK	0xf
#define PSR_MODE_EL0t	0x0
#define fault_user_mode(regs) \
	((BPF_CORE_READ(regs, pstate) & PSR_MODE_MASK) == PSR_MODE_EL0t)
#elif defined(__loongarch__)
#define CSR_PRMD_PPLV_MASK	0x3
#define CSR_PLV_USER		3
#define fault_user_mode(regs) \
	((BPF_CORE_READ(regs, csr_prmd) & CSR_PRMD_PPLV_MASK) == CSR_PLV_USER)
#endif

static __always_inline int report_page_fault(void *ctx, struct pt_regs *regs,
					     unsigned long address, unsigned long ip,
					     unsigned long error_code, bool user_fault)
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

	event.address = address;
	event.ip = ip;
	event.error_code = error_code;
	event.pid = pid;				   // Get PID
	event.tid = pid_tgid & 0xFFFFFFFF; // Get TID
	ret = bpf_get_current_comm(event.comm, sizeof(event.comm));
	if (ret)
	{
		bpf_err("bpf_get_current_comm failed: %ld", ret);
	}
	stack_id = bpf_get_stackid(ctx, &stack_traces, skip_frame | (user_fault ? BPF_F_USER_STACK : 0));
	if (stack_id < 0)
	{
		bpf_err("bpf_get_stackid failed: %d", stack_id);
		return 0; // Skip if stack trace retrieval failed
	}
	event.stack_id = stack_id;
	event.timestamp = bpf_ktime_get_ns();

	if (regs && user_fault != fault_user_mode(regs))
	{
		return 0;
	}
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
#if defined(__x86_64__)
SEC("tracepoint/exceptions/page_fault_kernel")
int page_fault_kernel(struct tp_page_fault_t *ctx)
{
	return report_page_fault(ctx, NULL, ctx->address, ctx->ip,
				 ctx->error_code, false);
}

SEC("tracepoint/exceptions/page_fault_user")
int page_fault_user(struct tp_page_fault_t *ctx)
{
	return report_page_fault(ctx, NULL, ctx->address, ctx->ip,
				 ctx->error_code, true);
}
#elif defined(__aarch64__)
SEC("fentry/do_page_fault")
int BPF_PROG(page_fault_kernel, unsigned long far, unsigned long esr,
	     struct pt_regs *regs)
{
	return report_page_fault(ctx, regs, far, BPF_CORE_READ(regs, pc),
				 esr, false);
}

SEC("fentry/do_page_fault")
int BPF_PROG(page_fault_user, unsigned long far, unsigned long esr,
	     struct pt_regs *regs)
{
	return report_page_fault(ctx, regs, far, BPF_CORE_READ(regs, pc),
				 esr, true);
}
#elif defined(__loongarch__)
SEC("kprobe/handle_mm_fault")
int page_fault_kernel(struct pt_regs *ctx)
{
	struct pt_regs *regs = (struct pt_regs *)PT_REGS_PARM4(ctx);

	if (!regs)
	{
		return 0; /* GUP path passes NULL regs; not a hardware fault */
	}
	return report_page_fault(ctx, regs, PT_REGS_PARM2(ctx),
				 BPF_CORE_READ(regs, csr_era),
				 PT_REGS_PARM3(ctx), false);
}

SEC("kprobe/handle_mm_fault")
int page_fault_user(struct pt_regs *ctx)
{
	struct pt_regs *regs = (struct pt_regs *)PT_REGS_PARM4(ctx);

	if (!regs)
	{
		return 0; /* GUP path passes NULL regs; not a hardware fault */
	}
	return report_page_fault(ctx, regs, PT_REGS_PARM2(ctx),
				 BPF_CORE_READ(regs, csr_era),
				 PT_REGS_PARM3(ctx), true);
}
#endif
