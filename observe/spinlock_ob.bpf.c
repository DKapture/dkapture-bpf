// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
//
// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "spinlock_ob.h"

const volatile pid_t target_tgid = 0;
const volatile pid_t target_pid = 0;
void *const volatile target_lock = NULL;
const volatile int per_thread = 0;

struct
{
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(max_entries, MAX_ENTRIES);
	__uint(key_size, sizeof(u32));
	__uint(value_size, PERF_MAX_STACK_DEPTH * sizeof(u64));
} stacks SEC(".maps");

struct task_lock
{
	u32 tgid;
	u32 pid;
	u64 lock_ptr;
};

struct lockholder
{
	s32 stack_id;
	u32 tgid;
	u32 pid;
	u64 try_at;
	u64 acq_at;
	u64 rel_at;
	u64 lock_ptr;
};

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct task_lock);
	__type(value, struct lockholder);
} lockholders SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, s32);
	__type(value, struct lock_stat);
} stat_map SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);
	__type(value, void *);
} locks SEC(".maps");

static bool tracing_task(u64 pid_tgid)
{
	u32 tgid = pid_tgid >> 32;
	u32 pid = pid_tgid;

	if (target_tgid && target_tgid != tgid)
	{
		return false;
	}
	if (target_pid && target_pid != pid)
	{
		return false;
	}
	return true;
}

static void spinlock_contended(void *ctx, void *lock)
{
	u64 pid_tgid;
	struct lockholder li[1] = {0};
	struct task_lock tl = {};

	if (target_lock && target_lock != lock)
	{
		return;
	}
	pid_tgid = bpf_get_current_pid_tgid();
	if (!tracing_task(pid_tgid))
	{
		return;
	}

	li->tgid = pid_tgid >> 32;
	li->pid = pid_tgid;
	li->lock_ptr = (u64)lock;
	li->stack_id = bpf_get_stackid(ctx, &stacks, 4 | BPF_F_FAST_STACK_CMP);

	if (li->stack_id < 0)
	{
		return;
	}
	li->try_at = bpf_ktime_get_ns();

	tl.tgid = pid_tgid >> 32;
	tl.pid = pid_tgid;
	tl.lock_ptr = (u64)lock;
	bpf_map_update_elem(&lockholders, &tl, li, BPF_ANY);
}

static void spinlock_aborted(void *lock)
{
	u64 pid_tgid;
	struct task_lock tl = {};

	if (target_lock && target_lock != lock)
	{
		return;
	}
	pid_tgid = bpf_get_current_pid_tgid();
	if (!tracing_task(pid_tgid))
	{
		return;
	}
	tl.tgid = pid_tgid >> 32;
	tl.pid = pid_tgid;
	tl.lock_ptr = (u64)lock;
	bpf_map_delete_elem(&lockholders, &tl);
}

static void spinlock_acquired(void *lock)
{
	u64 pid_tgid;
	struct lockholder *li;
	struct task_lock tl = {};

	if (target_lock && target_lock != lock)
	{
		return;
	}
	pid_tgid = bpf_get_current_pid_tgid();
	if (!tracing_task(pid_tgid))
	{
		return;
	}

	tl.tgid = pid_tgid >> 32;
	tl.pid = pid_tgid;
	tl.lock_ptr = (u64)lock;
	li = bpf_map_lookup_elem(&lockholders, &tl);
	if (!li)
	{
		return;
	}

	li->acq_at = bpf_ktime_get_ns();
}

static void account(struct lockholder *li)
{
	struct lock_stat *ls;
	u64 delta;
	u32 key = li->stack_id;

	if (per_thread)
	{
		key = li->pid;
	}

	ls = bpf_map_lookup_elem(&stat_map, &key);
	if (!ls)
	{
		struct lock_stat fresh = {0};

		bpf_map_update_elem(&stat_map, &key, &fresh, BPF_ANY);
		ls = bpf_map_lookup_elem(&stat_map, &key);
		if (!ls)
		{
			return;
		}

		if (per_thread)
		{
			bpf_get_current_comm(ls->acq_max_comm, TASK_COMM_LEN);
		}
	}

	delta = li->acq_at - li->try_at;
	__sync_fetch_and_add(&ls->acq_count, 1);
	__sync_fetch_and_add(&ls->acq_total_time, delta);
	if (delta > READ_ONCE(ls->acq_max_time))
	{
		WRITE_ONCE(ls->acq_max_time, delta);
		WRITE_ONCE(ls->acq_max_id, (li->tgid << 32) | li->pid);
		WRITE_ONCE(ls->acq_max_lock_ptr, li->lock_ptr);
		if (!per_thread)
		{
			bpf_get_current_comm(ls->acq_max_comm, TASK_COMM_LEN);
		}
	}

	delta = li->rel_at - li->acq_at;
	__sync_fetch_and_add(&ls->hld_count, 1);
	__sync_fetch_and_add(&ls->hld_total_time, delta);
	if (delta > READ_ONCE(ls->hld_max_time))
	{
		WRITE_ONCE(ls->hld_max_time, delta);
		WRITE_ONCE(ls->hld_max_id, (li->tgid << 32) | li->pid);
		WRITE_ONCE(ls->hld_max_lock_ptr, li->lock_ptr);
		if (!per_thread)
		{
			bpf_get_current_comm(ls->hld_max_comm, TASK_COMM_LEN);
		}
	}
}

static void spinlock_released(void *lock)
{
	u64 pid_tgid;
	struct lockholder *li;
	struct task_lock tl = {};

	if (target_lock && target_lock != lock)
	{
		return;
	}
	pid_tgid = bpf_get_current_pid_tgid();
	if (!tracing_task(pid_tgid))
	{
		return;
	}
	tl.tgid = pid_tgid >> 32;
	tl.pid = pid_tgid;
	tl.lock_ptr = (u64)lock;
	li = bpf_map_lookup_elem(&lockholders, &tl);
	if (!li)
	{
		return;
	}

	li->rel_at = bpf_ktime_get_ns();
	account(li);
}

SEC("fentry/_raw_spin_lock")
int BPF_PROG(fentry_raw_spin_lock, raw_spinlock_t *lock)
{
	bpf_printk("_raw_spin_lock enter\n");

	spinlock_contended(ctx, lock);
	return 0;
}

SEC("fexit/_raw_spin_lock")
int BPF_PROG(fexit_raw_spin_lock, raw_spinlock_t *lock, long ret)
{
	bpf_printk("_raw_spin_lock exit\n");
	spinlock_acquired(lock);
	return 0;
}

SEC("fentry/_raw_spin_unlock")
int BPF_PROG(fentry_raw_spin_unlock, raw_spinlock_t *lock)
{
	bpf_printk("_raw_spin_unlock enter\n");
	spinlock_released(lock);
	return 0;
}

SEC("kprobe/_raw_spin_lock")
int BPF_KPROBE(kprobe_raw_spin_lock, raw_spinlock_t *lock)
{
	u32 tid = (u32)bpf_get_current_pid_tgid();

	bpf_map_update_elem(&locks, &tid, &lock, BPF_ANY);
	spinlock_contended(ctx, lock);
	return 0;
}

SEC("kretprobe/_raw_spin_lock")
int BPF_KRETPROBE(kretprobe_raw_spin_lock, long ret)
{
	u32 tid = (u32)bpf_get_current_pid_tgid();
	void **lock;

	lock = bpf_map_lookup_elem(&locks, &tid);
	if (!lock)
	{
		return 0;
	}

	bpf_map_delete_elem(&locks, &tid);
	spinlock_acquired(*lock);
	return 0;
}

SEC("kprobe/_raw_spin_unlock")
int BPF_KPROBE(kprobe_raw_spin_unlock, raw_spinlock_t *lock)
{
	spinlock_released(lock);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
