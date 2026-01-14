# 第五阶段：高级主题

> 深入探讨多架构支持、容器集成、安全性等高级话题

## 5.1 多架构支持

### 支持的架构

| 架构 | Kmod 最低内核 | BPF 最低内核 | Modern BPF | 备注 |
|------|---------------|-------------|-----------|------|
| **x86_64** | 3.10 | 4.14 | 5.8 | 最成熟 |
| **aarch64** (ARM64) | 3.16 | 4.17 | 5.8 | 树莓派、AWS Graviton |
| **s390x** | 3.10 | 5.5 | 5.8 | IBM 大型机 |
| **ppc64le** | 3.10 | 5.1 | 5.8 | PowerPC 小端 |
| **riscv64** | 5.0 | - | 5.8 | RISC-V |
| **loongarch64** | 5.10 | - | 5.8 | 龙芯 |

### 系统调用号差异处理

不同架构的系统调用号不同：

```c
// 代码位置：driver/syscall_compat_x86_64.h

#ifdef __x86_64__
#define __NR_open    2
#define __NR_read    0
#define __NR_write   1
#endif

// 代码位置：driver/syscall_compat_aarch64.h

#ifdef __aarch64__
#define __NR_openat  56   // ARM64 没有 open，只有 openat
#define __NR_read    63
#define __NR_write   64
#endif
```

### 32位兼容模式（IA32 on x86_64）

```c
// 代码位置：driver/syscall_ia32_64_map.c

// 32位系统调用号 → 64位系统调用号映射
const int g_ia32_64_map[] = {
    [0] = __NR_read,           // IA32 read = 3 → x86_64 read = 0
    [1] = __NR_write,          // IA32 write = 4 → x86_64 write = 1
    [2] = __NR_open,           // IA32 open = 5 → x86_64 open = 2
    // ... 400+ 映射
};

// 运行时转换
long convert_ia32_to_64(long ia32_nr) {
    if (ia32_nr >= 0 && ia32_nr < ARRAY_SIZE(g_ia32_64_map))
        return g_ia32_64_map[ia32_nr];
    return -1;  // 不支持的系统调用
}
```

### 参数提取差异

```c
// x86_64: 参数在寄存器 rdi, rsi, rdx, r10, r8, r9
// ARM64: 参数在寄存器 x0-x5

// 统一接口
static inline void syscall_get_arguments(struct task_struct *task,
                                          struct pt_regs *regs,
                                          unsigned long *args) {
#ifdef __x86_64__
    args[0] = regs->di;
    args[1] = regs->si;
    args[2] = regs->dx;
    args[3] = regs->r10;
    args[4] = regs->r8;
    args[5] = regs->r9;
#elif defined(__aarch64__)
    args[0] = regs->regs[0];
    args[1] = regs->regs[1];
    args[2] = regs->regs[2];
    args[3] = regs->regs[3];
    args[4] = regs->regs[4];
    args[5] = regs->regs[5];
#endif
}
```

---

## 5.2 容器和 Kubernetes 集成

### 容器检测

```c
// 检测进程是否在容器中
bool in_container(struct task_struct *task) {
    struct nsproxy *ns = task->nsproxy;

    // 检查 PID namespace
    if (ns && ns->pid_ns_for_children != &init_pid_ns)
        return true;

    // 检查 cgroup
    // /proc/<pid>/cgroup 包含 docker/kubepods
    return false;
}
```

### 容器 ID 提取

```c
// 从 cgroup 路径提取容器 ID
// 示例路径：
// /sys/fs/cgroup/cpu/docker/3a5b.../...
// /sys/fs/cgroup/cpu/kubepods/pod.../3a5b...

char* get_container_id(struct task_struct *task) {
    struct cgroup *cgrp = task_cgroup(task, cpu_cgrp_id);
    char *path = cgroup_path(cgrp);

    // 解析路径
    char *docker_prefix = strstr(path, "/docker/");
    if (docker_prefix) {
        char *id_start = docker_prefix + 8;  // 跳过 "/docker/"
        // 提取 64 位十六进制 ID
        return strndup(id_start, 64);
    }

    // Kubernetes Pod
    char *kubepods_prefix = strstr(path, "/kubepods/");
    if (kubepods_prefix) {
        // 格式：/kubepods/besteffort/pod<uuid>/<container_id>
        // 提取 container_id 部分
    }

    return NULL;
}
```

### Kubernetes 元数据

Falco 通过 Kubernetes API 获取额外元数据：

- Pod Name
- Namespace
- Labels
- Annotations

```go
// 用户态代码（Go）
// 通过容器 ID 查询 Pod 信息

func GetPodInfo(containerID string) (*PodInfo, error) {
    // 1. 查询 CRI（containerd/docker）
    container := cri.InspectContainer(containerID)

    // 2. 从容器 labels 获取 Pod UID
    podUID := container.Config.Labels["io.kubernetes.pod.uid"]

    // 3. 查询 Kubernetes API
    pod := k8sClient.CoreV1().Pods(namespace).Get(podName)

    return &PodInfo{
        Name:      pod.Name,
        Namespace: pod.Namespace,
        Labels:    pod.Labels,
    }, nil
}
```

---

## 5.3 安全性考虑

### 权限管理

```bash
# Falco 驱动需要的最小权限

# 1. Kernel Module：需要 CAP_SYS_MODULE
sudo setcap cap_sys_module=ep /usr/bin/falco-driver-loader

# 2. BPF：需要 CAP_BPF + CAP_PERFMON（内核 5.8+）
# 或者 CAP_SYS_ADMIN（旧内核）
sudo setcap cap_bpf,cap_perfmon=ep /usr/bin/falco

# 3. 设备文件访问：/dev/falco*
sudo chown root:falco /dev/falco*
sudo chmod 0640 /dev/falco*
```

### 数据隐私保护

```c
// 敏感数据脱敏

int f_sys_write_x(struct event_filler_arguments *args) {
    char *buffer = args->buffer;
    size_t count = args->args[2];

    // 检测密码字段
    if (strstr(buffer, "password=") != NULL ||
        strstr(buffer, "secret=") != NULL) {
        // 替换为 "<redacted>"
        memset(buffer, 'X', count);
    }

    return val_to_ring(args, buffer, count, true, 0);
}
```

### 对抗检测和绕过

**常见绕过技术：**

1. **直接系统调用（syscall 指令）**：绕过 libc
   - Falco 在内核层拦截，无法绕过

2. **LD_PRELOAD 劫持**：替换 libc 函数
   - Falco 在内核层拦截，无法绕过

3. **Rootkit 检测驱动**：尝试卸载 Falco
   - 保护方案：只读挂载、SELinux 策略

4. **时间竞争（TOCTOU）**：
   - Falco 通过 enter 事件缓解（见 1.2）

**对抗措施：**

```bash
# 1. 防止驱动被卸载
echo "falco" >> /etc/modules-load.d/security.conf

# 2. 保护驱动文件
sudo chattr +i /lib/modules/$(uname -r)/extra/falco.ko

# 3. 监控驱动状态
#!/bin/bash
while true; do
    if ! lsmod | grep -q falco; then
        echo "ALERT: Falco driver unloaded!" | logger
        # 重新加载或触发告警
    fi
    sleep 10
done
```

---

## 5.4 与其他技术对比

### vs. Sysdig

**相似点：**
- Falco 基于 Sysdig 的 libs（libscap/libsinsp）
- 使用相同的驱动（kmod/BPF）
- 事件格式相同

**区别：**
- Sysdig：系统诊断工具（类似 strace/tcpdump）
- Falco：运行时安全检测（专注告警）

### vs. Auditd

| 特性 | Falco | Auditd |
|------|-------|--------|
| **实现** | Tracepoint | Netlink (audit 子系统) |
| **性能** | 高（环形缓冲区） | 中（用户态队列） |
| **事件丰富度** | 丰富（进程上下文） | 基础（系统调用参数） |
| **规则语言** | 灵活（YAML + 表达式） | 复杂（auditctl） |
| **容器支持** | 原生支持 | 需额外配置 |
| **用途** | 运行时安全 | 审计合规 |

**选择建议：**
- 安全检测：Falco
- 审计合规：Auditd
- 可同时使用

### vs. Tetragon

| 特性 | Falco | Tetragon |
|------|-------|----------|
| **技术** | Tracepoint (kmod/BPF) | eBPF (kprobe/tracepoint) |
| **内核要求** | 3.10+ (kmod), 4.14+ (BPF) | 5.4+ |
| **架构** | 成熟稳定 | 新兴（Cilium 团队） |
| **事件类型** | 系统调用为主 | 系统调用 + 网络 + 内核函数 |
| **策略** | 规则匹配 | eBPF 策略 |
| **性能** | 优秀 | 优秀 |

**选择建议：**
- 云原生新项目：考虑 Tetragon（更现代）
- 生产环境：Falco（成熟稳定）
- 复杂网络策略：Tetragon（Cilium 集成）

---

## 5.5 性能优化深入

### CPU 亲和性优化

```bash
# 将 Falco 进程绑定到特定 CPU
taskset -c 0-3 falco

# 将驱动中断绑定到特定 CPU
echo 4-7 > /proc/irq/<irq_num>/smp_affinity_list
```

### 缓冲区调优

```c
// 动态调整缓冲区大小
// 编辑 driver/ppm.h

// 高负载系统（大量事件）
#define DEFAULT_DRIVER_BUFFER_BYTES_DIM (32 * 1024 * 1024)  // 32MB

// 低负载系统（节省内存）
#define DEFAULT_DRIVER_BUFFER_BYTES_DIM (4 * 1024 * 1024)   // 4MB
```

### 事件采样策略

```c
// 代码位置：driver/ppm_fillers.c

// 采样高频事件（例如：read/write）
static atomic_t read_sample_counter = ATOMIC_INIT(0);

int f_sys_read_x(struct event_filler_arguments *args) {
    // 只记录 1/10 的 read 事件
    int count = atomic_inc_return(&read_sample_counter);
    if (count % 10 != 0)
        return PPM_SKIP_EVENT;

    // 正常处理
    // ...
}
```

### 用户态优化

```c
// libscap 优化：批量读取事件

int scap_next_batch(scap_t *handle, scap_evt **events, int max_events) {
    int n_events = 0;

    for (int cpu = 0; cpu < handle->n_cpus; cpu++) {
        char *buf;
        uint32_t len;

        if (ringbuffer_readbuf(&handle->devices[cpu], &buf, &len) == SCAP_SUCCESS) {
            // 批量解析事件
            while (len > 0 && n_events < max_events) {
                scap_evt *evt = (scap_evt*)buf;
                events[n_events++] = evt;
                buf += evt->len;
                len -= evt->len;
            }
        }
    }

    return n_events;
}
```

---

## 5.6 扩展阅读

### eBPF 深入学习

**推荐书籍：**
1. "BPF Performance Tools" by Brendan Gregg
2. "Learning eBPF" by Liz Rice
3. "Linux Observability with BPF" by David Calavera

**在线资源：**
- [eBPF.io](https://ebpf.io/) - 官方文档
- [Cilium eBPF 教程](https://github.com/cilium/ebpf)
- [BPF CO-RE 参考](https://nakryiko.com/posts/bpf-portability-and-co-re/)

### 内核开发资源

**推荐书籍：**
1. "Linux Device Drivers" (3rd Edition)
2. "Linux Kernel Development" by Robert Love
3. "Understanding the Linux Kernel" by Bovet & Cesati

**源码阅读：**
```bash
# 克隆内核源码
git clone https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
cd linux

# 阅读 tracepoint 实现
less kernel/tracepoint.c
less include/linux/tracepoint.h

# 阅读 perf events
less kernel/events/core.c
```

---

## 5.7 实战项目推荐

### 项目 1：自定义安全检测器

基于 Falco 驱动，实现特定应用的安全监控：

```c
// 监控 SSH 登录
int f_sys_execve_x(struct event_filler_arguments *args) {
    char *filename = get_filename(args);

    if (strcmp(filename, "/usr/sbin/sshd") == 0) {
        // 提取 SSH 连接信息
        char *remote_ip = get_remote_ip(current);
        char *username = get_username(current);

        // 写入自定义事件
        val_to_ring(args, remote_ip, 0, true, 0);
        val_to_ring(args, username, 0, true, 0);
    }

    return add_sentinel(args);
}
```

### 项目 2：性能分析工具

使用 Falco 驱动实现类似 `strace` 的工具：

```c
// 统计系统调用延迟
struct syscall_stats {
    uint64_t count;
    uint64_t total_ns;
    uint64_t min_ns;
    uint64_t max_ns;
};

static struct syscall_stats stats[SYSCALL_TABLE_SIZE];

// 在 sys_enter 记录开始时间
// 在 sys_exit 计算延迟并更新统计
```

### 项目 3：容器运行时监控

集成 Kubernetes，实现 Pod 级别的安全监控：

```yaml
# Kubernetes DaemonSet 部署
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: falco-security
spec:
  template:
    spec:
      hostPID: true
      hostNetwork: true
      containers:
      - name: falco
        image: falcosecurity/falco:latest
        securityContext:
          privileged: true
        volumeMounts:
        - name: dev
          mountPath: /host/dev
        - name: proc
          mountPath: /host/proc
```

---

## 下一步

👉 [第六章：学习资源](./06-resources.md) - 官方文档、社区资源、工具推荐

---

**思考题：**

1. 为什么不同架构需要不同的系统调用映射？
2. 如何防止恶意进程检测并卸载 Falco 驱动？
3. 在高负载系统中，如何平衡性能和事件完整性？
