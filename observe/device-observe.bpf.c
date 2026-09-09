// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
//
// SPDX-License-Identifier: GPL-2.0

/**
 * device-observe.bpf.c - Monitor camera and microphone device access
 *
 * Hooks:
 *   sys_enter_openat  - match /dev/video* (V4L2) and /dev/snd/pcmC*D*c (ALSA capture)
 *   sys_exit_openat   - get fd, emit DEV_EVT_OPEN event, register in fd_table
 *   sys_enter_ioctl   - detect STREAM_ON / STREAM_OFF via V4L2/ALSA ioctl cmds
 *   sys_enter_close   - emit DEV_EVT_CLOSE event, cleanup fd_table
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "device-observe.h"

/* ---- rodata: user-space writable filter config ---- */
const volatile bool filter_camera = true;
const volatile bool filter_microphone = true;
const volatile int target_pid = 0;

/* ---- Tracepoint context structs (match kernel layout) ---- */

/* syscalls/sys_enter_openat(int dfd, const char *filename, int flags, umode_t mode) */
struct OpenatEnterCtx
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	int __syscall_nr;
	int __align;
	unsigned long dfd;
	const char *filename;
	unsigned long flags;
	unsigned long mode;
};

/* syscalls/sys_exit_openat -> long ret (the fd or negative error) */
struct OpenatExitCtx
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	int __syscall_nr;
	int __align;
	long ret;
};

/* syscalls/sys_enter_ioctl(unsigned int fd, unsigned long cmd, unsigned long arg) */
struct IoctlEnterCtx
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	int __syscall_nr;
	int __align;
	unsigned long fd;
	unsigned long cmd;
	unsigned long arg;
};

/* syscalls/sys_enter_close(unsigned int fd) */
struct CloseEnterCtx
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	int __syscall_nr;
	int __align;
	unsigned long fd;
};

/* ---- Maps ---- */

/* Pass device info from openat enter -> exit, keyed by pid_tgid */
struct open_info
{
	u32 device_type;
	char path[DEV_OBS_PATH_MAX];
};

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, struct open_info);
	__uint(max_entries, 10240);
} open_pending SEC(".maps");

/* Track known device fds: (tgid << 32 | fd) -> device_type */
struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, u32);
	__uint(max_entries, 10240);
} fd_table SEC(".maps");

/* Ring buffer for events */
struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

/* ---- Helpers ---- */

/**
 * Check if path starts with /dev/video (V4L2 camera device)
 */
static __always_inline bool is_camera_path(const char *path)
{
	/* /dev/video = 10 chars */
	if (path[0] != '/')  return false;
	if (path[1] != 'd' || path[2] != 'e' || path[3] != 'v') return false;
	if (path[4] != '/')  return false;
	if (path[5] != 'v' || path[6] != 'i' || path[7] != 'd'
	    || path[8] != 'e' || path[9] != 'o')
		return false;
	return true;
}

/**
 * Check if path matches /dev/snd/pcmC*D*c (ALSA capture = microphone)
 * The trailing 'c' means capture, 'p' means playback.
 */
static __always_inline bool is_mic_path(const char *path)
{
	/* /dev/snd/pcmC = 14 chars */
	if (path[0]  != '/') return false;
	if (path[1]  != 'd' || path[2]  != 'e' || path[3]  != 'v') return false;
	if (path[4]  != '/') return false;
	if (path[5]  != 's' || path[6]  != 'n' || path[7]  != 'd') return false;
	if (path[8]  != '/') return false;
	if (path[9]  != 'p' || path[10] != 'c' || path[11] != 'm'
	    || path[12] != 'C')
		return false;

	/* Walk forward to find the last char before NUL;
	   if it is 'c' this is a capture (mic) device. */
	#pragma unroll
	for (int i = 13; i < DEV_OBS_PATH_MAX - 1; i++)
	{
		char c = path[i];
		if (c == '\0')
			return false; /* string ended without trailing 'c' */
		if (c == 'c' && path[i + 1] == '\0')
			return true;
	}
	return false;
}

/**
 * Emit a device_event into the ring buffer.
 */
static __always_inline void emit_event(u32 device_type, u32 event_type,
							   int fd, u32 ioctl_cmd,
							   const char *path)
{
	struct devobs_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
	if (!ev)
		return;

	ev->timestamp_ns = bpf_ktime_get_ns();
	ev->pid  = (u32)(bpf_get_current_pid_tgid() >> 32);
	ev->tid  = (u32)bpf_get_current_pid_tgid();
	ev->uid  = (u32)bpf_get_current_uid_gid();
	ev->device_type = device_type;
	ev->event_type  = event_type;
	ev->fd   = fd;
	ev->ioctl_cmd  = ioctl_cmd;
	bpf_get_current_comm(&ev->comm, sizeof(ev->comm));

	if (path)
	{
		/* bounded copy */
		#pragma unroll
		for (int i = 0; i < DEV_OBS_PATH_MAX; i++)
		{
			ev->device_path[i] = path[i];
			if (path[i] == '\0')
				break;
		}
	}

	bpf_ringbuf_submit(ev, 0);
}

/* ---- Tracepoint programs ---- */

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_enter_openat(struct OpenatEnterCtx *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = pid_tgid >> 32;

	if (target_pid && tgid != target_pid)
		return 0;

	/* Read filename from userspace */
	char buf[DEV_OBS_PATH_MAX];
	long len = bpf_probe_read_user_str(buf, sizeof(buf), ctx->filename);
	if (len <= 0)
		return 0;

	u32 dev_type = 0;
	if (filter_camera && is_camera_path(buf))
		dev_type = DEV_TYPE_CAMERA;
	else if (filter_microphone && is_mic_path(buf))
		dev_type = DEV_TYPE_MICROPHONE;

	if (!dev_type)
		return 0;

	struct open_info info = {};
	info.device_type = dev_type;
	#pragma unroll
	for (int i = 0; i < DEV_OBS_PATH_MAX; i++)
	{
		info.path[i] = buf[i];
		if (buf[i] == '\0')
			break;
	}

	bpf_map_update_elem(&open_pending, &pid_tgid, &info, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int trace_exit_openat(struct OpenatExitCtx *ctx)
{
	long ret = ctx->ret;
	if (ret < 0)
		return 0; /* open failed */

	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = pid_tgid >> 32;
	int fd = (int)ret;

	struct open_info *info = bpf_map_lookup_elem(&open_pending, &pid_tgid);
	if (!info)
		return 0;

	/* Emit OPEN event */
	emit_event(info->device_type, DEV_EVT_OPEN, fd, 0, info->path);

	/* Register fd in fd_table for ioctl/close tracking */
	u64 fd_key = ((u64)tgid << 32) | (u32)fd;
	bpf_map_update_elem(&fd_table, &fd_key, &info->device_type, BPF_ANY);

	bpf_map_delete_elem(&open_pending, &pid_tgid);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_ioctl")
int trace_enter_ioctl(struct IoctlEnterCtx *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = pid_tgid >> 32;
	int fd = (int)ctx->fd;
	u32 cmd = (u32)ctx->cmd;

	u64 fd_key = ((u64)tgid << 32) | (u32)fd;
	u32 *dev_type = bpf_map_lookup_elem(&fd_table, &fd_key);
	if (!dev_type)
		return 0;

	u32 event_type = 0;

	if (*dev_type == DEV_TYPE_CAMERA)
	{
		if (cmd == V4L2_STREAM_ON)
			event_type = DEV_EVT_STREAM_ON;
		else if (cmd == V4L2_STREAM_OFF)
			event_type = DEV_EVT_STREAM_OFF;
	}
	else if (*dev_type == DEV_TYPE_MICROPHONE)
	{
		if (cmd == ALSA_PCM_START)
			event_type = DEV_EVT_STREAM_ON;
		else if (cmd == ALSA_PCM_DROP)
			event_type = DEV_EVT_STREAM_OFF;
	}

	if (event_type)
		emit_event(*dev_type, event_type, fd, cmd, NULL);

	return 0;
}

SEC("tracepoint/syscalls/sys_enter_close")
int trace_enter_close(struct CloseEnterCtx *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = pid_tgid >> 32;
	int fd = (int)ctx->fd;

	u64 fd_key = ((u64)tgid << 32) | (u32)fd;
	u32 *dev_type = bpf_map_lookup_elem(&fd_table, &fd_key);
	if (!dev_type)
		return 0;

	emit_event(*dev_type, DEV_EVT_CLOSE, fd, 0, NULL);

	bpf_map_delete_elem(&fd_table, &fd_key);
	return 0;
}

char _license[] SEC("license") = "GPL";
