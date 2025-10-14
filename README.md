# DKapture-bpf

DKapture-bpf是[libdkapture](https://github.com/DKapture/libdkapture)的一个子仓库，用于单独存放和管理BPF程序。

## License

本项目采用多重许可证（Multiple Licenses）策略，不同部分使用不同的开源许可证：

- **主体源代码**（如 `.bpf.c` 等实现文件）采用 **GNU 通用公共许可证第二版（GPL-2.0）**，详见 [`LICENSE-GPL-2.0`](LICENSE-GPL-2.0)。
- **部分导出的头文件**（如 `export/` 目录下的公共接口头文件）采用 **GNU 宽通用公共许可证第二版（LGPL-2.1）**，详见 [`LICENSE-LGPL-2.1`](LICENSE-LGPL-2.1)。

每个源文件的开头均通过 `SPDX-License-Identifier` 明确标注了其适用的具体许可证。请根据你所使用的文件类型遵守相应的许可条款。

# BPF程序功能

## 信息采集

1. 网络信息采集：每进程套接字使用信息，套接字元组信息，每进程网络流量统计。
2. 文件系统信息采集：文件vfs事件跟踪，文件描述符IO内容跟踪，挂载事件监听。
3. 进程信息采集：procfs节点信息访问优化，提供高性能的进程信息访问接口，相对procfs节点接口提升超过1个数量级。
4. IO信息采集：每设备IO流量，每进程IO流量。
5. 系统调用信息采集。
6. 调度信息采集：进程切换跟踪，进程唤醒，运行队列等信息采集。
7. 中断信息采集：缺页中断，软中断，tasklet，及部分硬中断。
8. 内存信息采集：内核内存泄漏。

## 行为拦截

1. 网络包过滤：支持按网络4元组信息对网络数据包进行过滤。
2. 文件管控：支持监控和限制系统用户对文件的访问、删除。

# 目录结构

- build: 动态生成，存放项目构建过程中生成的文件。
- include: 存放编译时使用的源代码头文件。
- filter: 存放作为过滤器的 eBPF 源代码。
- observe: 存放作为观察器的 eBPF 源代码。
- policy: 存放策略相关代码。
- script: 存放用于提高工作效率的脚本。

# 编译

## 环境要求

- 系统: Deepin 23, Deepin 25, UOS 25 专业版
- 内核：6.6.0以上，且编译选项开启BPF、BTF相关配置：
  ```conf
  CONFIG_DEBUG_INFO_BTF=y
  CONFIG_BPF=y
  CONFIG_HAVE_EBPF_JIT=y
  CONFIG_BPF_SYSCALL=y
  CONFIG_BPF_JIT=y
  CONFIG_BPF_LSM=y
  CONFIG_CGROUP_BPF=y
  CONFIG_NETFILTER_BPF_LINK=y
  CONFIG_BPF_EVENTS=y
  ```
- 架构：x86_64、ARM64、Loong64、sw64。
- 编译工具：`sudo apt install build-essential clang llvm libbpf-dev bpftool`

## 构建流程

### 完整构建

```bash
# 克隆项目
git clone https://github.com/DKapture/dkapture-bpf
cd dkapture-bpf

# 完整构建所有模块
make all
```

### 分模块构建

```bash
# 构建内核头文件（必需的第一步）
make include

# 构建观察工具模块
make observe

# 构建过滤器模块
make filter

# 构建策略模块
make policy
```

### 构建特定bpf程序

```bash
make observe/bio-stat
make observe/lsock
make observe/trace-file

make filter/net-filter
make filter/rm-forbid

make policy/frtp
```

## 构建产物

### 可执行文件

构建完成后，以下目录包含对应BPF程序的字节码（.o文件）：

- `build/observe/` - 系统观察工具
- `build/filter/` - 网络和文件过滤器
- `build/policy/` - 访问控制策略工具

## 清理构建

```bash
# 清楚所有非生存头文件构建产物
make clean

# 清理所有构建产物
make distclean

# 清理特定模块
make observe/clean
make filter/clean
```
