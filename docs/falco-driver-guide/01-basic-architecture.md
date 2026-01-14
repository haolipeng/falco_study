# 第一阶段：基础知识准备

## 1.1 Falco 驱动的基本架构

### 什么是 Falco 驱动？

Falco 驱动就像一个"监控摄像头"，安装在 Linux 内核中，实时监控所有系统调用和内核事件。当进程打开文件、建立网络连接、执行命令时，驱动都能捕获到这些行为并记录下来。

### 三层架构设计

Falco 驱动采用**三层架构**设计：

```
┌──────────────────────────────────────────────────┐
│  用户态应用层 (Falco Application)                 │
│  - 规则引擎                                       │
│  - 告警输出                                       │
└─────────────────┬────────────────────────────────┘
                  │
┌─────────────────▼────────────────────────────────┐
│  系统捕获库层 (libscap)                           │
│  - 驱动抽象接口                                   │
│  - 事件解析                                       │
│  - 环形缓冲区管理                                 │
└──────────────┬──────────────┬────────────────────┘
               │              │
    ┌──────────▼──────┐   ┌──▼───────────────┐
    │  内核模块驱动    │   │   eBPF 驱动      │
    │  (kmod)         │   │  (bpf/modern)    │
    └─────────────────┘   └──────────────────┘
         内核空间              内核空间
```

### 核心工作原理

完整的工作流程：

```
┌─────────────────────────────────────────────────────────┐
│  1. 应用程序执行系统调用                                 │
│     例如：open("/etc/passwd", O_RDONLY)                 │
└─────────────────┬───────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────┐
│  2. 内核处理系统调用                                     │
│     - sys_enter (进入时)                                │
│     - sys_exit (退出时)                                 │
└─────────────────┬───────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────┐
│  3. Falco 驱动拦截（Tracepoint Hook）                   │
│     - 提取系统调用参数                                   │
│     - 记录进程上下文（PID、用户、路径等）                 │
│     - 计算事件大小                                       │
└─────────────────┬───────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────┐
│  4. 写入环形缓冲区（Ring Buffer）                        │
│     - 每个 CPU 独立缓冲区（避免锁竞争）                   │
│     - 生产者：内核驱动                                   │
│     - 消费者：用户态程序                                 │
└─────────────────┬───────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────┐
│  5. 用户态程序读取（libscap）                            │
│     - 轮询缓冲区（epoll/poll）                           │
│     - 解析事件数据                                       │
│     - 传递给 Falco 规则引擎                              │
└─────────────────┬───────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────┐
│  6. Falco 规则匹配与告警                                 │
│     - 检测异常行为                                       │
│     - 生成告警                                           │
└─────────────────────────────────────────────────────────┘
```

---

## 1.2 三种驱动模式详解

Falco 支持三种驱动实现模式，每种都有其独特的优势和适用场景。

### 模式 1：Kernel Module（传统内核模块）🏗️

#### 技术原理

**代码位置：** `driver/main.c` (82 KB 核心代码)

内核模块使用 **tracepoint** 钩子机制拦截系统调用：

```c
// 驱动注册 tracepoint 钩子
// 位置：driver/main.c:645-658

// 注册系统调用进入钩子
ret = compat_register_trace(syscall_enter_probe,
                            "sys_enter",
                            tp_sys_enter);

// 注册系统调用退出钩子
ret = compat_register_trace(syscall_exit_probe,
                            "sys_exit",
                            tp_sys_exit);

// 钩子函数定义（简化版）
TRACEPOINT_PROBE(syscall_enter_probe, struct pt_regs *regs, long id) {
    // 1. 检查是否是感兴趣的系统调用
    if (!is_syscall_interesting(id))
        return;

    // 2. 获取当前进程上下文
    struct task_struct *task = current;

    // 3. 提取系统调用参数
    unsigned long args[6];
    syscall_get_arguments(task, regs, args);

    // 4. 写入环形缓冲区
    record_event_all_consumers(event_type, flags, &event_data);
}
```

#### 环形缓冲区内存布局

```
每个 CPU 的环形缓冲区结构：
┌────────────────────────────────────────────────┐
│  Ring Buffer Info (元数据)                     │
│  - head: 生产者写入位置                         │
│  - tail: 消费者读取位置                         │
│  - n_evts: 事件计数                            │
│  - n_drops: 丢弃计数                           │
└────────────────────────────────────────────────┘
         ▼
┌────────────────────────────────────────────────┐
│  Event Buffer (默认 8MB)                       │
│  ┌──────────────────────────────────────────┐ │
│  │ Event Header (16 bytes)                  │ │
│  │  - timestamp: 64位纳秒时间戳              │ │
│  │  - tid: 线程ID                            │ │
│  │  - type: 事件类型                         │ │
│  │  - nparams: 参数个数                      │ │
│  ├──────────────────────────────────────────┤ │
│  │ Event Parameters (可变长度)              │ │
│  │  - param1: 文件路径 "/etc/passwd"        │ │
│  │  - param2: 打开标志 O_RDONLY             │ │
│  │  - param3: 文件描述符 3                   │ │
│  └──────────────────────────────────────────┘ │
│  ┌──────────────────────────────────────────┐ │
│  │ 下一个事件...                             │ │
│  └──────────────────────────────────────────┘ │
└────────────────────────────────────────────────┘
         ▼
┌────────────────────────────────────────────────┐
│  Overflow Buffer (2 * PAGE_SIZE = 8KB)        │
│  (防止事件跨页边界)                            │
└────────────────────────────────────────────────┘
```

#### 优缺点分析

**优点：**
- ✅ **性能最优**：直接内核代码，无 BPF 验证器开销（~10-20% 更快）
- ✅ **内核兼容性**：支持古老内核（x86_64: 3.10+，2013年发布）
- ✅ **功能完整**：可访问所有内核 API，无限制
- ✅ **调试友好**：可使用 printk、kgdb 等传统工具

**缺点：**
- ❌ **编译复杂**：需要匹配目标内核版本编译（kernel-devel 包）
- ❌ **安全风险**：代码错误可能导致内核崩溃（panic）
- ❌ **分发困难**：每个内核版本都需要独立模块
- ❌ **加载权限**：必须 root 权限，且可能被禁用（Secure Boot）

#### 适用场景

1. 生产环境，性能是第一要求
2. 旧版本内核系统（RHEL 6/7，内核 < 4.14）
3. 需要访问特殊内核 API（某些网络协议栈）
4. 嵌入式系统（性能敏感）

---

### 模式 2：Legacy BPF Probe 🐝

#### 技术原理

**代码位置：** `driver/bpf/probe.c` (11 KB)

Legacy BPF 使用 **raw tracepoint** 机制：

```c
// BPF 程序定义
// 位置：driver/bpf/probe.c:31-111

// 系统调用退出钩子（主要捕获点）
BPF_PROBE("raw_syscalls/", sys_exit, sys_exit_args) {
    // 1. 获取系统调用号
    long id = bpf_syscall_get_nr(ctx);
    if (id < 0 || id >= SYSCALL_TABLE_SIZE)
        return 0;

    // 2. 处理 32位兼容模式
    if (bpf_in_ia32_syscall()) {
        id = convert_ia32_to_64(id);  // IA32 → x86_64 转换
    }

    // 3. 检查是否是感兴趣的系统调用
    if (!is_syscall_interesting(id))
        return 0;

    // 4. 调用 Filler 函数填充事件数据
    const struct syscall_evt_pair *sc_evt = get_syscall_info(id);
    ppm_event_code evt_type = sc_evt->exit_event_type;
    call_filler(ctx, &stack_ctx, evt_type, drop_flags, retval);

    return 0;
}

// 系统调用进入钩子（仅用于 TOCTOU 缓解）
BPF_PROBE("raw_syscalls/", sys_enter, sys_enter_args) {
    // 只为部分系统调用（open/connect）生成 enter 事件
    // 用于防止 Time-of-Check-Time-of-Use 攻击
    switch(id) {
        case __NR_open:
        case __NR_openat:
        case __NR_connect:
            // 记录调用时的参数（防止后续被修改）
            call_filler(ctx, ctx, evt_type, drop_flags, -1);
            break;
        default:
            return 0;  // 其他系统调用不生成 enter 事件
    }
}
```

#### BPF Map 数据结构

```c
// 位置：driver/bpf/maps.h

// 1. 事件缓冲区（Perf Ring Buffer）
struct bpf_map_def SEC("maps") perf_map = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(int),      // CPU ID
    .value_size = sizeof(u32),
    .max_entries = 0,             // 自动设置为 CPU 核心数
};

// 2. 系统调用表（查询系统调用信息）
struct bpf_map_def SEC("maps") syscall_table = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),      // 系统调用号
    .value_size = sizeof(struct syscall_evt_pair),
    .max_entries = SYSCALL_TABLE_SIZE,  // ~350 个
};

// 3. 进程信息缓存（避免重复查询）
struct bpf_map_def SEC("maps") local_state_map = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(struct scap_bpf_per_cpu_state),
    .max_entries = 1,
};
```

#### BPF 验证器约束

```
BPF 验证器要求：
1. 所有内存访问必须边界检查
2. 循环必须有明确的上界（< 4.14 不支持循环）
3. 程序指令数限制：< 4096 条（旧内核）
4. 栈空间限制：512 字节
5. 不能调用任意内核函数（仅允许 Helper Functions）
```

#### 优缺点分析

**优点：**
- ✅ **安全性高**：BPF 验证器确保不会崩溃内核
- ✅ **无需编译**：预编译的 .o 文件可直接加载
- ✅ **动态加载**：无需重启，即时加载/卸载
- ✅ **隔离性好**：沙箱环境，限制内存访问

**缺点：**
- ❌ **性能开销**：验证器检查 + JIT 编译（~10% 慢于 kmod）
- ❌ **功能受限**：不能访问任意内核函数
- ❌ **内核要求**：最低 4.14（x86_64），4.17（ARM64）
- ❌ **指令限制**：复杂逻辑需要拆分（百万级指令限制）

#### 适用场景

1. 云环境（AWS、GCP）无法加载内核模块
2. Kubernetes 安全策略禁止 kmod
3. 需要快速部署（容器化）
4. 开发测试环境

---

### 模式 3：Modern BPF Probe 🚀

#### 技术原理

**代码位置：** `driver/modern_bpf/programs/`

Modern BPF 采用**模块化设计**，使用 **tail call** 机制：

```
Modern BPF 架构：
┌──────────────────────────────────────────────────┐
│  Dispatcher Programs（调度器程序）               │
│  ┌────────────────────────────────────────────┐ │
│  │  syscall_exit.bpf.c (tp_btf/sys_exit)     │ │
│  │  - 获取系统调用号                          │ │
│  │  - 查询 tail_call_table                    │ │
│  │  - 执行 bpf_tail_call()                    │ │
│  └────────────────────────────────────────────┘ │
└──────────────────────┬───────────────────────────┘
                       │ tail_call()
                       ▼
┌──────────────────────────────────────────────────┐
│  Tail-Called Programs（尾调用程序）              │
│  ┌────────────────────────────────────────────┐ │
│  │  open.bpf.c  → 处理 open() 系统调用        │ │
│  │  read.bpf.c  → 处理 read() 系统调用        │ │
│  │  connect.bpf.c → 处理 connect()            │ │
│  │  ... (60+ 独立程序)                        │ │
│  └────────────────────────────────────────────┘ │
└──────────────────────┬───────────────────────────┘
                       │ 调用 helpers
                       ▼
┌──────────────────────────────────────────────────┐
│  Helper Functions（辅助函数库）                  │
│  ┌────────────────────────────────────────────┐ │
│  │  base/common.h → 通用工具                  │ │
│  │  extract/ → 数据提取（路径、网络地址）     │ │
│  │  store/ → 数据存储（ringbuf 操作）         │ │
│  │  interfaces/ → 事件接口                    │ │
│  └────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────┘
```

#### 关键技术：Tail Call（尾调用）

```c
// 调度器代码（简化版）
// 位置：modern_bpf/programs/attached/dispatchers/syscall_exit.bpf.c

SEC("tp_btf/sys_exit")
int BPF_PROG(sys_exit_dispatcher, struct pt_regs *regs, long ret) {
    // 1. 获取系统调用号
    long id = extract__syscall_id(ctx);

    // 2. 查找对应的 tail call 程序
    // tail_call_table: [系统调用号] → [BPF程序FD]
    bpf_tail_call(ctx, &tail_call_table, id);

    // 3. 如果 tail call 失败（未注册的系统调用），返回
    return 0;
}

// 具体系统调用处理程序
// 位置：modern_bpf/programs/tail_called/events/syscall_dispatched_events/open.bpf.c

SEC("tp_btf/sys_exit")
int BPF_PROG(open_x) {
    struct ringbuf_struct ringbuf;

    // 1. 预留缓冲区空间
    if (!ringbuf__reserve_space(&ringbuf, size, PPME_SYSCALL_OPEN_X))
        return 0;

    // 2. 写入事件头
    ringbuf__store_event_header(&ringbuf);

    // 3. 提取参数
    // Parameter 1: fd (返回值)
    ringbuf__store_s64(&ringbuf, (s64)ret);

    // Parameter 2: filename
    unsigned long filename_ptr = extract__syscall_argument(regs, 0);
    ringbuf__store_charbuf(&ringbuf, filename_ptr);

    // Parameter 3: flags
    unsigned long flags = extract__syscall_argument(regs, 1);
    ringbuf__store_u32(&ringbuf, open_flags_to_scap(flags));

    // Parameter 4: mode
    unsigned long mode = extract__syscall_argument(regs, 2);
    ringbuf__store_u32(&ringbuf, open_modes_to_scap(mode));

    // 4. 提交事件
    ringbuf__submit_event(&ringbuf);
    return 0;
}
```

#### BPF Ring Buffer vs Perf Buffer

```c
// 传统 Perf Buffer（Legacy BPF）：
bpf_perf_event_output(ctx, &perf_map, BPF_F_CURRENT_CPU, &event, size);
// 问题：需要从内核空间复制到用户空间映射的缓冲区

// 新方式（Modern BPF）：
void *data = bpf_ringbuf_reserve(&ringbuf_maps, size, 0);  // 直接预留
// ... 填充数据 ...
bpf_ringbuf_submit(data, 0);  // 零复制提交
// 优点：零复制、更低延迟、更高吞吐
```

#### 优缺点分析

**优点：**
- ✅ **最佳架构**：模块化设计，易于维护和扩展
- ✅ **性能优异**：BPF Ring Buffer 零复制，延迟更低
- ✅ **代码复用**：Helper 函数库，避免重复代码
- ✅ **现代特性**：BTF（BPF Type Format），CO-RE（一次编译，到处运行）
- ✅ **指令无限**：Tail call 绕过单程序指令限制

**缺点：**
- ❌ **内核要求高**：最低 5.8（2020年发布）
- ❌ **复杂度高**：理解 tail call 机制需要时间
- ❌ **调试困难**：多程序跳转，难以追踪
- ❌ **兼容性弱**：旧系统无法使用

#### 适用场景

1. **最推荐**的新部署方案（内核 >= 5.8）
2. 云原生环境（Kubernetes 1.20+）
3. 需要扩展自定义事件
4. 开发新功能（现代 BPF 生态）

---

## 1.3 三种模式性能对比

| 指标 | Kernel Module | Legacy BPF | Modern BPF |
|------|---------------|------------|------------|
| **开销** | 基线（100%） | +10-15% | +5-8% |
| **延迟** | ~500ns | ~600ns | ~550ns |
| **吞吐** | ~1M 事件/秒 | ~850K | ~950K |
| **CPU** | 3-5% | 4-6% | 3.5-5.5% |
| **内存** | 8MB/CPU | 8MB/CPU + Map | 8MB/CPU + RB |

*(基于 8 核 Intel Xeon, 1000 req/s 负载测试)*

---

## 1.4 驱动与用户态的交互方式

### 通信机制：环形缓冲区（Ring Buffer）

```
┌────────────────────────────────────────────────┐
│  内核空间（Kernel Space）                      │
│  ┌──────────────────────────────────────────┐ │
│  │  Falco Driver (Producer)                 │ │
│  │  - 拦截系统调用                           │ │
│  │  - 序列化事件数据                         │ │
│  │  - 写入 head 位置                         │ │
│  │  - head += event_size                     │ │
│  └──────────────┬───────────────────────────┘ │
│                 │ write                        │
│                 ▼                              │
│  ┌──────────────────────────────────────────┐ │
│  │  Shared Memory (mmap)                    │ │
│  │  [────────────────────────────────────]  │ │
│  │   ^tail          ^head                   │ │
│  │   │              │                        │ │
│  │   └──read────────┘                        │ │
│  └──────────────────────────────────────────┘ │
└────────────────────────────────────────────────┘
                 │ mmap
                 ▼
┌────────────────────────────────────────────────┐
│  用户空间（User Space）                        │
│  ┌──────────────────────────────────────────┐ │
│  │  libscap (Consumer)                      │ │
│  │  - epoll/poll 等待事件                    │ │
│  │  - 读取 tail 位置                         │ │
│  │  - 解析事件                               │ │
│  │  - tail += event_size                     │ │
│  └──────────────────────────────────────────┘ │
└────────────────────────────────────────────────┘
```

### 用户态读取示例代码

```c
// 代码位置：libscap/ringbuffer/ringbuffer.h:89-109

int32_t ringbuffer_readbuf(struct scap_device *dev,
                           char **buf, uint32_t *len) {
    uint64_t thead, ttail, read_size;

    // 1. 读取 head/tail 指针
    ringbuffer_get_buf_pointers(dev, &thead, &ttail, &read_size);
    // thead = 生产者写入位置（内核更新）
    // ttail = 消费者读取位置（用户态更新）
    // read_size = thead - ttail（可读数据量）

    if (read_size == 0)
        return SCAP_TIMEOUT;  // 没有新数据

    // 2. 返回缓冲区指针和长度
    *buf = dev->m_buffer + ttail;  // mmap 映射的共享内存
    *len = (uint32_t)read_size;

    return SCAP_SUCCESS;
}

// 3. 解析事件后更新 tail
dev->m_buffer_info->tail += event->len;
```

### 内存映射（mmap）实现

```c
// 用户态代码（libscap）：
int scap_kmod_open(scap_t *handle) {
    // 1. 打开设备文件
    int fd = open("/dev/falco", O_RDWR);

    // 2. 为每个 CPU 创建缓冲区
    for (int cpu = 0; cpu < num_cpus; cpu++) {
        // 3. mmap 映射内核缓冲区到用户空间
        void *buffer = mmap(NULL,
                            8 * 1024 * 1024,  // 8MB
                            PROT_READ | PROT_WRITE,
                            MAP_SHARED,
                            fd,
                            cpu * PAGE_SIZE);  // 偏移量

        handle->devices[cpu].m_buffer = buffer;

        // 4. 创建 epoll 实例监控
        int epoll_fd = epoll_create1(0);
        struct epoll_event ev = {
            .events = EPOLLIN,
            .data.u32 = cpu,
        };
        epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev);
    }

    return 0;
}
```

---

## 支持的架构和内核版本

| 架构 | Kmod 最低内核 | BPF 最低内核 | Modern BPF 最低内核 |
|---|---|---|---|
| x86_64 | 3.10 | 4.14 | 5.8 |
| aarch64 | 3.16 | 4.17 | 5.8 |
| s390x | 3.10 | 5.5 | 5.8 |
| riscv64 | 5.0 | - | 5.8 |
| ppc64le | 3.10 | 5.1 | 5.8 |
| loongarch64 | 5.10 | - | 5.8 |

---

## 选型建议

### 新部署项目

- **内核 >= 5.8**：首选 **Modern BPF**（最佳架构，未来方向）
- **内核 4.14-5.7**：使用 **Legacy BPF**（安全性好，部署简单）
- **内核 < 4.14**：必须使用 **Kernel Module**

### 性能敏感场景

- 首选 **Kernel Module**（性能最优）
- 次选 **Modern BPF**（接近 kmod 性能）

### 云环境/Kubernetes

- 首选 **Modern BPF** 或 **Legacy BPF**（无需 kmod 权限）
- 避免使用 Kernel Module（可能被策略禁止）

### 开发调试

- 内核模块：使用 **Kernel Module**（调试工具丰富）
- BPF 程序：使用 **Legacy BPF**（编译快，验证器报错清晰）

---

## 下一步

现在你已经理解了 Falco 驱动的基本架构和三种实现模式。接下来：

👉 [第二章：代码结构分析](./02-code-structure.md) - 深入了解源代码组织和关键数据结构

---

**思考题：**

1. 为什么 Falco 需要支持三种不同的驱动模式？
2. Per-CPU 环形缓冲区相比全局缓冲区有什么优势？
3. TOCTOU 攻击是什么？Falco 如何缓解这种攻击？

*提示：答案可以在本章内容中找到*
