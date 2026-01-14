# 第三阶段：核心功能深入

> 本章详细讲解 Falco 驱动的核心功能实现机制

## 3.1 系统调用钩子实现

### 系统调用过滤机制

Falco 不会监控所有系统调用（~400+），而是根据安全价值进行选择性监控：

```c
// 代码位置：driver/event_table.c

const struct syscall_evt_pair g_syscall_table[SYSCALL_TABLE_SIZE] = {
    // 高价值：文件操作
    [__NR_open] = {
        .enter_event_type = PPME_SYSCALL_OPEN_E,
        .exit_event_type = PPME_SYSCALL_OPEN_X,
        .flags = UF_USED | UF_ALWAYS_DROP,  // UF_USED=需要enter事件
    },

    [__NR_read] = {
        .enter_event_type = PPME_GENERIC_E,
        .exit_event_type = PPME_SYSCALL_READ_X,
        .flags = UF_NEVER_DROP,  // 关键事件，永不丢弃
    },

    // 高价值：网络操作
    [__NR_connect] = {
        .enter_event_type = PPME_SOCKET_CONNECT_E,
        .exit_event_type = PPME_SOCKET_CONNECT_X,
        .flags = UF_USED,  // TOCTOU 缓解
    },

    // 低价值：高频无用
    [__NR_getpid] = {
        .enter_event_type = PPME_GENERIC_E,
        .exit_event_type = PPME_GENERIC_X,
        .flags = 0,  // 不监控
    },
};
```

### TOCTOU（Time-of-Check-Time-of-Use）攻击缓解

**问题场景：**

```
1. 恶意进程创建 /tmp/safe.txt（无害）
2. 调用 open("/tmp/safe.txt")
3. 【竞态窗口】在内核检查后：
   unlink("/tmp/safe.txt");
   symlink("/etc/shadow", "/tmp/safe.txt");
4. 内核实际打开 /etc/shadow
5. Falco 只看到退出事件，检测被绕过
```

**解决方案：为敏感系统调用生成 enter 事件**

```c
// 代码位置：driver/bpf/probe.c:31-76

BPF_PROBE("raw_syscalls/", sys_enter, sys_enter_args) {
    long id = bpf_syscall_get_nr(ctx);

    // 仅为这些系统调用生成 enter 事件
    switch(id) {
    case __NR_connect:      // 网络连接
    case __NR_open:         // 文件打开
    case __NR_openat:
    case __NR_openat2:
        break;
    default:
        return 0;  // 其他跳过
    }

    // 记录进入时的参数（防止被篡改）
    call_filler(ctx, ctx, sc_evt->enter_event_type, drop_flags, -1);
    return 0;
}
```

---

## 3.2 事件缓冲区设计

### Per-CPU 环形缓冲区

**为什么使用 Per-CPU？**
1. **无锁设计**：每个 CPU 独立写入，避免同步开销
2. **高性能**：减少缓存行竞争（Cache Line Bouncing）
3. **局部性**：事件顺序在单 CPU 内保持

**算法实现：**

```c
// 简化版环形缓冲区写入
int ring_buffer_write(struct ring_buffer *rb,
                      const void *event, uint32_t len) {
    uint32_t head = rb->head;
    uint32_t tail = READ_ONCE(rb->tail);
    uint32_t size = rb->size;

    // 1. 计算可用空间
    uint32_t available = (head >= tail)
        ? (size - head + tail)
        : (tail - head);

    // 2. 空间不足，丢弃
    if (len > available - 1) {
        atomic_inc(&rb->n_drops_buffer);
        return -ENOMEM;
    }

    // 3. 写入数据（可能环绕）
    if (head + len <= size) {
        memcpy(rb->data + head, event, len);
    } else {
        uint32_t first = size - head;
        memcpy(rb->data + head, event, first);
        memcpy(rb->data, event + first, len - first);
    }

    // 4. 内存屏障 + 更新指针
    smp_wmb();
    WRITE_ONCE(rb->head, (head + len) % size);

    return 0;
}
```

---

## 3.3 进程上下文信息收集

### 进程信息获取

```c
// 代码位置：driver/ppm_fillers.c

// 获取进程基本信息
struct task_struct *task = current;  // 当前进程

// PID/TID
pid_t pid = task->tgid;   // 进程 ID
pid_t tid = task->pid;    // 线程 ID

// UID/GID
uid_t uid = task->cred->uid.val;
gid_t gid = task->cred->gid.val;

// 进程名称
char comm[TASK_COMM_LEN];
get_task_comm(comm, task);  // 例如 "bash"

// 父进程
struct task_struct *parent = task->real_parent;
pid_t ppid = parent->tgid;
```

### 命令行参数捕获（execve 系统调用）

```c
// 简化版 execve filler
int f_sys_execve_x(struct event_filler_arguments *args) {
    struct task_struct *task = current;
    struct mm_struct *mm = task->mm;

    // 1. 获取命令行参数区域
    unsigned long arg_start = mm->arg_start;
    unsigned long arg_end = mm->arg_end;

    // 2. 从用户空间读取
    char *argv_buffer = kmalloc(arg_end - arg_start, GFP_KERNEL);
    copy_from_user(argv_buffer, (void*)arg_start, arg_end - arg_start);

    // 3. 解析参数（null 分隔）
    // "bash\0-c\0echo hello\0"

    // 4. 写入事件
    val_to_ring(args, (unsigned long)argv_buffer, 0, false, 0);

    kfree(argv_buffer);
    return PPM_SUCCESS;
}
```

### 容器信息提取

```c
// 检测是否在容器中
bool in_container(struct task_struct *task) {
    // 检查 PID namespace
    return task->nsproxy->pid_ns_for_children !=
           &init_pid_ns;
}

// 获取容器 ID（从 cgroup 路径）
// /sys/fs/cgroup/cpu/docker/<container_id>/...
char* get_container_id(struct task_struct *task) {
    // 读取 /proc/<pid>/cgroup
    // 解析 docker/ 或 kubepods/ 路径
    // 提取 64 位十六进制 ID
}
```

---

## 3.4 网络事件捕获机制

### Socket 信息提取（connect 系统调用）

```c
// 代码位置：driver/ppm_fillers.c

int f_sys_connect_x(struct event_filler_arguments *args) {
    int64_t retval = args->retval;
    int fd = args->fd;

    // 1. 从文件描述符获取 socket
    struct socket *sock = sockfd_lookup(fd, &err);
    if (!sock)
        return PPM_FAILURE_INVALID_USER_MEMORY;

    // 2. 获取目标地址
    struct sockaddr_storage address;
    int addrlen = sizeof(address);
    kernel_getpeername(sock, (struct sockaddr*)&address, &addrlen);

    // 3. 解析地址（IPv4/IPv6）
    if (address.ss_family == AF_INET) {
        struct sockaddr_in *addr = (struct sockaddr_in*)&address;
        uint32_t ip = ntohl(addr->sin_addr.s_addr);  // 192.168.1.1
        uint16_t port = ntohs(addr->sin_port);        // 80

        // 写入事件：tuple(ip, port)
        val_to_ring(args, ip, 4, false, 0);
        val_to_ring(args, port, 2, false, 0);
    } else if (address.ss_family == AF_INET6) {
        // IPv6 处理
    }

    sockfd_put(sock);
    return add_sentinel(args);
}
```

### 协议解析（HTTP 示例）

```c
// 在 read/write 系统调用中检测协议
int f_sys_read_x(struct event_filler_arguments *args) {
    char *buf = args->buffer;
    size_t count = args->args[2];  // 读取字节数

    // 简单 HTTP 检测
    if (count > 4 && memcmp(buf, "GET ", 4) == 0) {
        // 提取 URL
        char *url_start = buf + 4;
        char *url_end = strchr(url_start, ' ');
        // 写入额外参数
    }

    return PPM_SUCCESS;
}
```

---

## 3.5 文件系统操作监控

### 文件路径解析

```c
// 从文件描述符获取完整路径
char* fd_to_path(int fd) {
    struct file *file = fget(fd);
    if (!file)
        return NULL;

    // 使用 d_path 获取路径
    char *path_buf = kmalloc(PATH_MAX, GFP_KERNEL);
    char *path = d_path(&file->f_path, path_buf, PATH_MAX);

    fput(file);
    return path;  // 例如 "/home/user/file.txt"
}
```

### VFS 层监控（未实现，仅概念）

Falco 主要监控系统调用层，而非 VFS 层，但理论上可以：

```c
// 假设的 VFS hook
int falco_vfs_open(struct inode *inode, struct file *file) {
    // 记录 inode 信息
    dev_t dev = inode->i_sb->s_dev;  // 设备号
    ino_t ino = inode->i_ino;        // inode 号
    umode_t mode = inode->i_mode;    // 文件类型

    // 记录事件
    return 0;
}
```

---

## 性能优化技巧

### 1. 事件采样

```c
// 高频事件采样（例如：只记录 1/100）
static atomic_t sample_counter = ATOMIC_INIT(0);

int should_sample_event(int sample_rate) {
    int count = atomic_inc_return(&sample_counter);
    return (count % sample_rate) == 0;
}

// 在 filler 中使用
if (!should_sample_event(100))
    return PPM_SKIP_EVENT;
```

### 2. 字符串截断

```c
// 限制字符串长度避免大量拷贝
#define MAX_PATH_LEN 256

int val_to_ring_truncated(struct event_filler_arguments *args,
                          unsigned long val, uint32_t max_len) {
    char *str = (char*)val;
    uint32_t len = strnlen_user(str, max_len);
    if (len > max_len)
        len = max_len;

    return val_to_ring(args, val, len, true, 0);
}
```

### 3. 延迟丢弃

```c
// 先检查事件是否会被用户态过滤
if (is_boring_pid(task->tgid))
    return PPM_SKIP_EVENT;

// 再进行昂贵的数据收集
char *path = fd_to_path(fd);  // 昂贵操作
```

---

## 调试技巧

### 内核模块调试

```c
// 使用 printk
#define DEBUG_PRINT(fmt, ...) \
    printk(KERN_INFO "falco: " fmt, ##__VA_ARGS__)

DEBUG_PRINT("syscall %ld, pid=%d\n", id, task->tgid);
```

### BPF 程序调试

```bash
# 查看 BPF 程序
bpftool prog list

# 查看 BPF Map
bpftool map list
bpftool map dump id 123

# 查看程序输出（bpf_printk）
cat /sys/kernel/debug/tracing/trace_pipe
```

---

## 常见问题

### Q1: 为什么有些系统调用看不到事件？

**A:** 可能原因：
1. 系统调用未在 `g_syscall_table` 中注册
2. 被 `is_syscall_interesting()` 过滤
3. 缓冲区满被丢弃（检查 `n_drops_buffer`）

### Q2: 如何添加新的系统调用监控？

**A:** 三步骤：
1. 在 `event_table.c` 添加映射
2. 在 `ppm_fillers.c` 实现 filler
3. 重新编译驱动

### Q3: 性能开销有多大？

**A:** 取决于负载：
- 低负载：< 3% CPU
- 中负载：3-8% CPU
- 高负载：8-15% CPU

---

## 下一步

👉 [第四章：实践指导](./04-practice-guide.md) - 动手编译、调试和扩展 Falco 驱动

---

**实验建议：**

1. **修改事件过滤**：
   ```bash
   # 修改 event_table.c，添加 getpid 监控
   [__NR_getpid] = {
       .exit_event_type = PPME_SYSCALL_GETPID_X,
       .flags = UF_NEVER_DROP,
   };
   ```

2. **添加自定义参数**：
   在 filler 中添加额外的调试信息

3. **性能测试**：
   使用 `stress-ng` 压力测试，观察 `n_drops_buffer`
