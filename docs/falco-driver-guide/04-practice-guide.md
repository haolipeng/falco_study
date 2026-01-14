# 第四阶段：实践指导

> 动手实践：编译、调试、扩展 Falco 驱动

## 4.1 编译和加载 Falco 驱动

### 环境准备

#### 系统要求

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    linux-headers-$(uname -r) \
    cmake \
    git \
    pkg-config \
    clang \
    llvm

# RHEL/CentOS
sudo yum install -y \
    kernel-devel-$(uname -r) \
    gcc \
    cmake \
    git \
    clang \
    llvm
```

#### 获取源代码

```bash
# 克隆 Falco libs（包含驱动）
git clone https://github.com/falcosecurity/libs.git
cd libs

# 查看版本
git tag | grep -E '^[0-9]' | tail -5
git checkout 0.18.0  # 选择稳定版本
```

---

### 编译内核模块驱动（Kmod）

```bash
cd driver

# 方法1：使用 CMake（推荐）
mkdir build && cd build
cmake -DDRIVER_NAME=falco \
      -DDRIVER_DEVICE_NAME=falco \
      -DCREATE_TEST_TARGETS=OFF \
      ../
make driver

# 方法2：直接使用内核构建系统
cd driver
make -C /lib/modules/$(uname -r)/build M=$PWD modules

# 查看生成的模块
ls -lh falco.ko
file falco.ko
modinfo falco.ko
```

**输出示例：**
```
falco.ko: ELF 64-bit LSB relocatable, x86-64, version 1
filename:       /path/to/falco.ko
license:        Dual MIT/GPL
description:    Falco system call capture driver
author:         the Falco authors
srcversion:     ABC123DEF456
depends:
name:           falco
vermagic:       6.8.0-64-generic SMP preempt
```

### 加载内核模块

```bash
# 加载模块
sudo insmod falco.ko

# 验证加载成功
lsmod | grep falco
dmesg | tail -20  # 查看内核日志

# 查看设备文件
ls -l /dev/falco*

# 输出：
# crw-rw-rw- 1 root root 246, 0 Jan 14 10:00 /dev/falco0
# crw-rw-rw- 1 root root 246, 1 Jan 14 10:00 /dev/falco1
# ... (每个 CPU 一个)
```

### 卸载模块

```bash
# 卸载
sudo rmmod falco

# 验证
lsmod | grep falco  # 应该没有输出
```

---

### 编译 Legacy BPF 驱动

```bash
cd driver/bpf

# 设置 CFLAGS
export CFLAGS="-O2 -g -Wall"

# 编译
make

# 查看生成的 BPF 对象文件
ls -lh probe.o
llvm-objdump -S probe.o | less  # 查看反汇编
```

### 加载 BPF 程序

```bash
# 使用 libscap 的 BPF 加载器（在 Falco 中自动完成）
# 手动加载示例（需要编写加载代码）

# 查看加载的 BPF 程序
sudo bpftool prog list | grep falco

# 查看 BPF Map
sudo bpftool map list | grep falco
```

---

### 编译 Modern BPF 驱动

```bash
cd driver/modern_bpf

# 确保有 clang >= 11
clang --version

# 编译
mkdir build && cd build
cmake -DUSE_BUNDLED_DEPS=ON ..
make

# 查看生成的文件
ls -lh *.bpf.o
```

### 使用 DKMS（推荐生产环境）

DKMS 可以在内核升级时自动重新编译模块：

```bash
# 安装 DKMS
sudo apt-get install dkms  # Ubuntu
sudo yum install dkms      # RHEL

# 准备 DKMS 配置
cd driver
sudo mkdir /usr/src/falco-0.18.0
sudo cp -r * /usr/src/falco-0.18.0/

# 创建 dkms.conf
cat << EOF | sudo tee /usr/src/falco-0.18.0/dkms.conf
PACKAGE_NAME="falco"
PACKAGE_VERSION="0.18.0"
BUILT_MODULE_NAME[0]="falco"
DEST_MODULE_LOCATION[0]="/kernel/extra"
AUTOINSTALL="yes"
EOF

# 添加到 DKMS
sudo dkms add -m falco -v 0.18.0

# 构建
sudo dkms build -m falco -v 0.18.0

# 安装
sudo dkms install -m falco -v 0.18.0

# 自动加载
echo "falco" | sudo tee -a /etc/modules-load.d/falco.conf
```

---

## 4.2 调试驱动代码

### 内核模块调试

#### 方法 1：printk 调试

```c
// 在 driver/main.c 中添加
#define DEBUG_SYSCALL

TRACEPOINT_PROBE(syscall_exit_probe,
                 struct pt_regs *regs, long ret) {
    long id = syscall_get_nr(current, regs);

#ifdef DEBUG_SYSCALL
    // 只打印 open 系统调用
    if (id == __NR_open) {
        printk(KERN_INFO "falco: open syscall, pid=%d, ret=%ld\n",
               current->tgid, ret);
    }
#endif

    // ... 正常处理
}
```

**查看输出：**
```bash
# 实时查看
sudo dmesg -w

# 或者
sudo tail -f /var/log/kern.log
```

#### 方法 2：动态调试（Dynamic Debug）

```bash
# 启用驱动的所有 pr_debug 输出
echo 'module falco +p' | sudo tee /sys/kernel/debug/dynamic_debug/control

# 启用特定文件
echo 'file driver/main.c +p' | sudo tee /sys/kernel/debug/dynamic_debug/control

# 查看设置
cat /sys/kernel/debug/dynamic_debug/control | grep falco
```

#### 方法 3：ftrace 追踪

```bash
# 启用 function tracer
echo function > /sys/kernel/debug/tracing/current_tracer

# 过滤 falco 函数
echo 'ppm_*' > /sys/kernel/debug/tracing/set_ftrace_filter

# 查看追踪
cat /sys/kernel/debug/tracing/trace
```

#### 方法 4：kgdb/kdb（高级）

```bash
# 配置内核参数（需要重启）
# 编辑 /etc/default/grub：
GRUB_CMDLINE_LINUX="... kgdboc=ttyS0,115200 kgdbwait"

# 更新 grub
sudo update-grub
sudo reboot

# 使用 gdb 连接
gdb vmlinux
(gdb) target remote /dev/ttyS0
(gdb) break syscall_exit_probe
(gdb) continue
```

---

### BPF 程序调试

#### 方法 1：bpf_printk

```c
// 在 driver/bpf/probe.c 中
BPF_PROBE("raw_syscalls/", sys_exit, sys_exit_args) {
    long id = bpf_syscall_get_nr(ctx);

    // 调试输出
    if (id == __NR_open) {
        bpf_printk("BPF: open syscall, id=%ld\n", id);
    }

    // ... 正常处理
    return 0;
}
```

**查看输出：**
```bash
# 查看 trace_pipe（最常用）
sudo cat /sys/kernel/debug/tracing/trace_pipe

# 输出示例：
# bash-1234  [000] .... 12345.678901: 0: BPF: open syscall, id=2
```

#### 方法 2：bpftool 检查

```bash
# 列出所有 BPF 程序
sudo bpftool prog show

# 查看特定程序详情
sudo bpftool prog show id 123
sudo bpftool prog dump xlated id 123  # 查看翻译后的字节码
sudo bpftool prog dump jited id 123   # 查看 JIT 编译后的汇编

# 列出所有 Map
sudo bpftool map show

# 查看 Map 内容
sudo bpftool map dump id 456

# 查看程序统计
sudo bpftool prog show --json | jq '.[] | {id, name, run_cnt, run_time_ns}'
```

#### 方法 3：bpftrace（交互式调试）

```bash
# 安装 bpftrace
sudo apt-get install bpftrace

# 追踪所有 BPF 程序调用
sudo bpftrace -e 'tracepoint:raw_syscalls:sys_exit { @[comm] = count(); }'

# 追踪特定系统调用
sudo bpftrace -e 'tracepoint:syscalls:sys_enter_openat { printf("%s -> %s\n", comm, str(args->filename)); }'
```

#### 方法 4：BPF 验证器日志

```bash
# 编译时生成详细日志
make EXTRA_CFLAGS="-DDEBUG"

# 加载时查看验证器输出
sudo bpftool prog load probe.o /sys/fs/bpf/falco_probe 2>&1 | less

# 输出示例：
# Verifier analysis:
# 0: (bf) r6 = r1
# 1: (b7) r1 = 0
# 2: (63) *(u32 *)(r10 -4) = r1
# ...
```

---

### 常用调试脚本

#### 监控环形缓冲区状态

```bash
#!/bin/bash
# monitor_ringbuf.sh

while true; do
    echo "=== Ring Buffer Stats $(date) ==="
    for dev in /dev/falco*; do
        cpu=${dev##*falco}
        echo "CPU $cpu:"
        # 读取统计信息（需要用户态工具）
        # 或者通过 /proc/falco/stats
    done
    sleep 1
done
```

#### 压力测试

```bash
#!/bin/bash
# stress_test.sh

# 生成大量系统调用
stress-ng --open 4 --timeout 60s &
stress-ng --socket 4 --timeout 60s &

# 监控丢包率
watch -n 1 'dmesg | grep "n_drops"'
```

---

## 4.3 添加自定义系统调用监控

### 示例：监控 `reboot` 系统调用

#### 步骤 1：定义事件类型

```c
// 编辑 driver/ppm_events_public.h

typedef enum {
    // ... 现有事件
    PPME_SYSCALL_REBOOT_X = 498,  // 新增
    PPM_EVENT_MAX = 499,
} ppm_event_code;
```

#### 步骤 2：添加系统调用映射

```c
// 编辑 driver/event_table.c

const struct syscall_evt_pair g_syscall_table[SYSCALL_TABLE_SIZE] = {
    // ... 现有映射

    [__NR_reboot] = {
        .enter_event_type = PPME_GENERIC_E,
        .exit_event_type = PPME_SYSCALL_REBOOT_X,
        .flags = UF_NEVER_DROP,  // 关键事件，永不丢弃
    },
};
```

#### 步骤 3：实现 Filler 函数

```c
// 编辑 driver/ppm_fillers.c

int f_sys_reboot_x(struct event_filler_arguments *args) {
    unsigned long val;
    int res;
    int64_t retval;

    // 1. 写入返回值
    retval = (int64_t)syscall_get_return_value(current, args->regs);
    res = val_to_ring(args, retval, 0, false, 0);
    CHECK_RES(res);

    // 2. 写入 magic1（参数 0）
    syscall_get_arguments_deprecated(args, 0, 1, &val);
    res = val_to_ring(args, val, 0, false, 0);
    CHECK_RES(res);

    // 3. 写入 magic2（参数 1）
    syscall_get_arguments_deprecated(args, 1, 1, &val);
    res = val_to_ring(args, val, 0, false, 0);
    CHECK_RES(res);

    // 4. 写入 cmd（参数 2）
    syscall_get_arguments_deprecated(args, 2, 1, &val);
    res = val_to_ring(args, val, 0, false, 0);
    CHECK_RES(res);

    // 5. 写入 arg（参数 3，可能是指针）
    syscall_get_arguments_deprecated(args, 3, 1, &val);
    res = val_to_ring(args, val, 0, true, 0);  // true = 从用户空间拷贝
    CHECK_RES(res);

    return add_sentinel(args);
}
```

#### 步骤 4：注册 Filler

```c
// 编辑 driver/fillers_table.c

const struct ppm_event_entry g_ppm_events[PPM_EVENT_MAX] = {
    // ... 现有条目

    [PPME_SYSCALL_REBOOT_X] = {
        .filler_callback = f_sys_reboot_x,
        .filler_id = PPME_SYSCALL_REBOOT_X,
    },
};
```

#### 步骤 5：重新编译和测试

```bash
# 卸载旧模块
sudo rmmod falco

# 重新编译
make

# 加载新模块
sudo insmod falco.ko

# 测试（不要真的重启！）
# 创建测试程序 test_reboot.c：
cat << 'EOF' > test_reboot.c
#include <sys/reboot.h>
#include <unistd.h>
#include <stdio.h>

int main() {
    // 只调用但不真正重启（需要 root）
    int ret = reboot(0xfee1dead);  // 无效 magic，会失败
    printf("reboot returned: %d\n", ret);
    return 0;
}
EOF

gcc -o test_reboot test_reboot.c
sudo ./test_reboot

# 在 Falco 中应该能看到事件
```

---

## 4.4 修改事件数据结构

### 示例：为 open 事件添加 inode 号

#### 修改 Filler

```c
// 在 f_sys_open_x 中添加
int f_sys_open_x(struct event_filler_arguments *args) {
    int64_t retval;
    unsigned long val;
    int res;
    int fd;

    // ... 现有参数

    // 添加 inode 号
    fd = (int)retval;
    if (fd >= 0) {
        struct file *file = fget(fd);
        if (file) {
            unsigned long ino = file->f_inode->i_ino;
            res = val_to_ring(args, ino, 0, false, 0);
            CHECK_RES(res);
            fput(file);
        } else {
            res = val_to_ring(args, 0, 0, false, 0);
            CHECK_RES(res);
        }
    } else {
        res = val_to_ring(args, 0, 0, false, 0);
        CHECK_RES(res);
    }

    return add_sentinel(args);
}
```

### 协议版本兼容性

修改事件结构需要增加协议版本：

```c
// 编辑 driver/ppm_version.h

#define PPM_API_CURRENT_VERSION_MAJOR 9  // 增加主版本号
#define PPM_API_CURRENT_VERSION_MINOR 0
#define PPM_API_CURRENT_VERSION_PATCH 0
```

---

## 4.5 性能分析与优化

### 测试性能开销

```bash
#!/bin/bash
# benchmark.sh

# 基准测试（无驱动）
echo "=== Baseline (no driver) ==="
sudo rmmod falco 2>/dev/null
sysbench cpu --cpu-max-prime=20000 run | grep "total time"
sysbench fileio --file-test-mode=seqwr --file-total-size=1G prepare
sysbench fileio --file-test-mode=seqwr --file-total-size=1G run | grep "total time"
sysbench fileio --file-test-mode=seqwr --file-total-size=1G cleanup

# 加载驱动测试
echo "=== With driver ==="
sudo insmod falco.ko
sysbench cpu --cpu-max-prime=20000 run | grep "total time"
sysbench fileio --file-test-mode=seqwr --file-total-size=1G prepare
sysbench fileio --file-test-mode=seqwr --file-total-size=1G run | grep "total time"
sysbench fileio --file-test-mode=seqwr --file-total-size=1G cleanup

# 计算开销百分比
```

### 使用 perf 分析

```bash
# 记录性能数据
sudo perf record -g -a -- sleep 30

# 分析
sudo perf report

# 查找热点函数
sudo perf top -g
```

### 查看丢包统计

```bash
# 通过 /proc 接口（如果实现）
cat /proc/falco/stats

# 或者通过 dmesg
dmesg | grep -E "n_drops|n_evts"

# 输出示例：
# falco: CPU 0: n_evts=1234567 n_drops_buffer=123 n_drops_pf=0
```

---

## 常见问题排查

### Q: 模块加载失败："Operation not permitted"

**A:** 可能原因：
1. Secure Boot 启用，禁用或签名模块
2. SELinux/AppArmor 阻止，临时禁用测试

```bash
# 禁用 Secure Boot（BIOS 设置）
# 或签名模块：
sudo /usr/src/linux-headers-$(uname -r)/scripts/sign-file \
    sha256 MOK.priv MOK.der falco.ko
```

### Q: BPF 加载失败："Invalid argument"

**A:** 查看详细错误：

```bash
# 增加内核日志级别
sudo sysctl -w kernel.printk="7 4 1 7"

# 重新加载
sudo dmesg -C  # 清空日志
# 加载 BPF 程序
sudo dmesg     # 查看验证器错误
```

### Q: 事件丢失严重

**A:** 优化建议：

```bash
# 1. 增大缓冲区（重新编译时）
# 编辑 driver/ppm.h:
#define DEFAULT_DRIVER_BUFFER_BYTES_DIM (16 * 1024 * 1024)  // 16MB

# 2. 过滤不关心的事件（用户态）
# 3. 降低系统负载
# 4. 使用 Modern BPF（性能更好）
```

---

## 下一步

👉 [第五章：高级主题](./05-advanced-topics.md) - 探索多架构支持、容器集成、安全性等高级话题

---

**实战项目建议：**

1. **添加自定义监控**：监控特定应用的系统调用（如 ssh、sudo）
2. **性能对比测试**：对比三种驱动模式的性能
3. **容器环境测试**：在 Docker/Kubernetes 中测试驱动
4. **扩展事件字段**：添加更多上下文信息（如 cgroup、namespace）
