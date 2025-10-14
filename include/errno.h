// SPDX-License-Identifier: GPL-2.0

#ifndef _ERRNO_H_
#define _ERRNO_H_

// 系统调用被信号中断，需要重新启动
#define ERESTARTSYS 512
// 系统调用被信号中断但没有被处理，需要重新启动
#define ERESTARTNOINTR 513
// 系统调用被信号中断且没有处理程序，需要重新启动
#define ERESTARTNOHAND 514
// ioctl命令无效
#define ENOIOCTLCMD 515
// 系统调用被信号中断，使用restart_block重新启动
#define ERESTART_RESTARTBLOCK 516
// 设备驱动程序延迟探测，稍后重试
#define EPROBE_DEFER 517
// 打开的句柄已过期
#define EOPENSTALE 518
// 参数无效
#define ENOPARAM 519
// 错误的句柄
#define EBADHANDLE 521
// 不同步的错误
#define ENOTSYNC 522
// 错误的cookie
#define EBADCOOKIE 523
// 不支持的操作
#define ENOTSUPP 524
// 太小的错误（缓冲区或参数太小）
#define ETOOSMALL 525
// 服务器故障
#define ESERVERFAULT 526
// 错误的类型
#define EBADTYPE 527
// 点唱机错误（远程存储设备忙）
#define EJUKEBOX 528
// 异步I/O控制块已排队
#define EIOCBQUEUED 529
// 回调冲突
#define ERECALLCONFLICT 530
// 没有宽限期（NFS相关错误）
#define ENOGRACE 531

#endif /* _ERRNO_H_ */