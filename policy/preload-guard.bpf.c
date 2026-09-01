// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
//
// SPDX-License-Identifier: GPL-2.0

/**
 * @file preload-guard.bpf.c
 * @brief LD_PRELOAD 环境变量监测与管控 eBPF 内核态程序
 */

#include "vmlinux.h"
#include <asm/errno.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

#define PROT_EXEC 0x4
#define MAP_PRIVATE 0x02
#define LD_PRELOAD_LEN 11
#define PRELOAD_VAL_LEN 64
#define ENV_ENTRY_LEN 128
#define MAX_ENV_ENTRIES 512	/* 允许的环境变量项数上限：扫描窗口与阈值；超过即拦截 */

struct Target
{
	u32 dev;
	u64 ino;
};

struct ProcKey
{
	u32 tgid;
};

struct AuditEvent
{
	u32 type;
	pid_t pid;
	u32 uid;
	char comm[16];
	char preload_val[PRELOAD_VAL_LEN];
	struct Target so_target;
};

struct Config
{
	u32 enforce;
	u32 reserved[7];
};

struct PendingPreload
{
	char preload_val[PRELOAD_VAL_LEN];
	u32 too_many;
};

struct
{
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct ProcKey);
	__type(value, u32);
	__uint(max_entries, 16384);
} pid_preload_map SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct ProcKey);
	__type(value, struct PendingPreload);
	__uint(max_entries, 16384);
} pending_preload_map SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct Target);
	__type(value, u8);
	__uint(max_entries, 400000);
} allowed_so SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, u8);
	__uint(max_entries, 65536);
} allowed_uid SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1024 * 1024);
} logs SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct Config);
	__uint(max_entries, 1);
} pg_config SEC(".maps");

static __always_inline bool env_has_ld_preload_prefix(const char *buf)
{
	return buf[0] == 'L' && buf[1] == 'D' &&
	       buf[2] == '_' && buf[3] == 'P' &&
	       buf[4] == 'R' && buf[5] == 'E' &&
	       buf[6] == 'L' && buf[7] == 'O' &&
	       buf[8] == 'A' && buf[9] == 'D' &&
	       buf[10] == '=';
}

static __always_inline void extract_preload_value(char *preload_buf,
						  const char *env_buf)
{
	u32 i;

#pragma unroll
	for (i = 0; i < PRELOAD_VAL_LEN - 1; i++)
	{
		char c = env_buf[LD_PRELOAD_LEN + i];
		if (c == 0 || c == ':')
		{
			preload_buf[i] = 0;
			return;
		}
		preload_buf[i] = c;
	}

	preload_buf[PRELOAD_VAL_LEN - 1] = 0;
}

static __always_inline long scan_envp_for_ld_preload(const char *const *envp,
						     char *preload_buf)
{
	u32 i;

	if (!envp)
		return 0;

	for (i = 0; i <= MAX_ENV_ENTRIES; i++)	/* 多读一项以判定 envp 是否已结束 */
	{
		const char *env = NULL;
		char env_buf[ENV_ENTRY_LEN] = {};
		long ret;

		ret = bpf_probe_read_user(&env, sizeof(env), &envp[i]);
		if (ret)
			return 0;
		if (!env)
			break;

		ret = bpf_probe_read_user_str(env_buf, sizeof(env_buf), env);
		if (ret <= LD_PRELOAD_LEN)
			continue;
		if (!env_has_ld_preload_prefix(env_buf))
			continue;

		extract_preload_value(preload_buf, env_buf);
		return 1;
	}

	if (i == MAX_ENV_ENTRIES + 1)
		return -1;	/* 未遇到 NULL 终止符：环境变量项数超过阈值 */

	return 0;
}

static __always_inline int handle_exec_enter(const char *const *envp)
{
	struct ProcKey key = {
		.tgid = bpf_get_current_pid_tgid() >> 32,
	};
	struct PendingPreload pending = {};
	long ret;

	ret = scan_envp_for_ld_preload(envp, pending.preload_val);
	if (ret == -1)
	{
		pending.too_many = 1;
		bpf_map_update_elem(&pending_preload_map, &key, &pending, BPF_ANY);
		return 0;
	}

	if (ret <= 0)
	{
		bpf_map_delete_elem(&pending_preload_map, &key);
		return 0;
	}

	bpf_map_update_elem(&pending_preload_map, &key, &pending, BPF_ANY);
	return 0;
}

static __always_inline bool is_whitelisted(struct Target *target, u32 uid)
{
	u8 *allow_uid;
	u8 *allow_so;

	allow_uid = bpf_map_lookup_elem(&allowed_uid, &uid);
	if (allow_uid)
		return true;

	allow_so = bpf_map_lookup_elem(&allowed_so, target);
	return allow_so != NULL;
}

static __always_inline void audit_log(u32 type, pid_t pid, u32 uid,
				      const char *preload_val,
				      struct Target *so_target)
{
	struct AuditEvent *ev;

	ev = bpf_ringbuf_reserve(&logs, sizeof(*ev), 0);
	if (!ev)
		return;

	ev->type = type;
	ev->pid = pid;
	ev->uid = uid;
	bpf_get_current_comm(&ev->comm, sizeof(ev->comm));

	if (preload_val)
	{
#pragma unroll
		for (int i = 0; i < PRELOAD_VAL_LEN; i++)
		{
			ev->preload_val[i] = preload_val[i];
			if (preload_val[i] == 0)
				break;
		}
	}
	else
	{
		ev->preload_val[0] = 0;
	}

	if (so_target)
		ev->so_target = *so_target;
	else
		__builtin_memset(&ev->so_target, 0, sizeof(ev->so_target));

	bpf_ringbuf_submit(ev, 0);
}

SEC("tracepoint/syscalls/sys_enter_execve")
int preload_execve_enter(struct trace_event_raw_sys_enter *ctx)
{
	return handle_exec_enter((const char *const *)ctx->args[2]);
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int preload_execveat_enter(struct trace_event_raw_sys_enter *ctx)
{
	return handle_exec_enter((const char *const *)ctx->args[3]);
}

SEC("kprobe/begin_new_exec")
int BPF_KPROBE(preload_detect, struct linux_binprm *bprm)
{
	struct ProcKey key = {};
	struct PendingPreload *pending;
	u32 flag = 1;

	(void)bprm;
	key.tgid = bpf_get_current_pid_tgid() >> 32;
	pending = bpf_map_lookup_elem(&pending_preload_map, &key);

	if (!pending)
	{
		bpf_map_delete_elem(&pid_preload_map, &key);
		return 0;
	}

	bpf_map_update_elem(&pid_preload_map, &key, &flag, BPF_ANY);
	if (pending->too_many)
		audit_log(2, key.tgid, bpf_get_current_uid_gid() & 0xffffffff,
			  NULL, NULL);
	else
		audit_log(0, key.tgid, bpf_get_current_uid_gid() & 0xffffffff,
			  pending->preload_val, NULL);
	bpf_map_delete_elem(&pending_preload_map, &key);
	return 0;
}

SEC("lsm/mmap_file")
int BPF_PROG(preload_mmap_guard, struct file *file,
	     unsigned long reqprot, unsigned long prot,
	     unsigned long flags, int ret)
{
	struct inode *inode;
	struct super_block *sb;
	struct Target target = {};
	struct ProcKey key = {};
	struct Config *cfg;
	u32 *flag;
	u32 uid;
	u32 zero = 0;

	(void)reqprot;
	if (ret)
		return ret;
	if (!(prot & PROT_EXEC))
		return 0;
	if (!file)
		return 0;
	if (!(flags & MAP_PRIVATE))
		return 0;

	cfg = bpf_map_lookup_elem(&pg_config, &zero);
	if (!cfg || !cfg->enforce)
		return 0;

	key.tgid = bpf_get_current_pid_tgid() >> 32;
	flag = bpf_map_lookup_elem(&pid_preload_map, &key);
	if (!flag)
		return 0;

	uid = bpf_get_current_uid_gid() & 0xffffffff;

	inode = BPF_CORE_READ(file, f_inode);
	if (!inode)
		return 0;

	sb = BPF_CORE_READ(inode, i_sb);
	target.dev = BPF_CORE_READ(sb, s_dev);
	target.ino = BPF_CORE_READ(inode, i_ino);

	if (is_whitelisted(&target, uid))
		return 0;

	audit_log(1, key.tgid, uid, NULL, &target);
	return -EPERM;
}

SEC("tp/sched/sched_process_exit")
int preload_exit_cleanup(void *ctx)
{
	struct ProcKey key = {
		.tgid = bpf_get_current_pid_tgid() >> 32,
	};

	(void)ctx;
	bpf_map_delete_elem(&pid_preload_map, &key);
	bpf_map_delete_elem(&pending_preload_map, &key);
	return 0;
}
