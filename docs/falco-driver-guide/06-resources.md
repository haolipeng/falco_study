# 第六章：学习资源

> 官方文档、社区资源、工具和进阶学习路径

## 6.1 官方资源

### Falco 项目

#### 官方网站和文档
- **Falco 官网**: https://falco.org/
- **官方文档**: https://falco.org/docs/
- **驱动文档**: https://falco.org/docs/event-sources/drivers/

#### GitHub 仓库
- **Falco 主仓库**: https://github.com/falcosecurity/falco
- **Libs (驱动)**: https://github.com/falcosecurity/libs
  - 驱动代码位于 `driver/` 目录
  - libscap/libsinsp 位于 `userspace/` 目录
- **规则库**: https://github.com/falcosecurity/rules

#### 社区和支持
- **Slack**: https://kubernetes.slack.com/messages/falco
- **GitHub Discussions**: https://github.com/falcosecurity/falco/discussions
- **邮件列表**: https://lists.cncf.io/g/cncf-falco-dev

### CNCF 资源
Falco 是 CNCF 毕业项目：
- **CNCF Falco 页面**: https://www.cncf.io/projects/falco/
- **项目成熟度**: Graduated (最高级别)
- **采用情况**: https://github.com/falcosecurity/falco/blob/master/ADOPTERS.md

---

## 6.2 Linux 内核开发学习

### 推荐书籍

#### 初级
1. **"Linux Device Drivers" (3rd Edition)**
   - 作者: Alessandro Rubini, Jonathan Corbet, Greg Kroah-Hartman
   - 适合: 内核驱动入门
   - 免费在线版: https://lwn.net/Kernel/LDD3/

2. **"Linux Kernel Development" (3rd Edition)**
   - 作者: Robert Love
   - 适合: 内核核心概念
   - 涵盖: 进程管理、内存管理、系统调用

#### 中级
3. **"Understanding the Linux Kernel" (3rd Edition)**
   - 作者: Daniel P. Bovet, Marco Cesati
   - 适合: 深入理解内核机制
   - 内容: 详细的内核源码分析

4. **"Linux Kernel Programming" (2nd Edition, 2024)**
   - 作者: Kaiwan N Billimoria
   - 适合: 现代内核开发
   - 包含: 5.x/6.x 内核新特性

#### 高级
5. **"Professional Linux Kernel Architecture"**
   - 作者: Wolfgang Mauerer
   - 适合: 架构级理解
   - 深度: 非常详细

### 在线课程

1. **Linux Kernel Teaching** (Free)
   - 网站: https://linux-kernel-labs.github.io/
   - 内容: 动手实验、作业、示例代码

2. **Bootlin Training Materials** (Free)
   - 网站: https://bootlin.com/docs/
   - 课程: Linux 驱动开发、嵌入式 Linux

3. **The Linux Foundation Courses**
   - "Linux Kernel Internals and Development" (LFD420)
   - "Developing Linux Device Drivers" (LFD430)
   - 费用: ~$2000-3000

### 内核文档

```bash
# 克隆内核源码
git clone https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
cd linux

# 阅读文档
less Documentation/process/submitting-patches.rst
less Documentation/driver-api/index.rst
less Documentation/trace/tracepoints.rst

# 在线阅读
# https://www.kernel.org/doc/html/latest/
```

---

## 6.3 eBPF 学习资源

### 推荐书籍

1. **"Learning eBPF" (2023)**
   - 作者: Liz Rice
   - 出版: O'Reilly
   - 适合: eBPF 入门到进阶
   - 评分: ⭐⭐⭐⭐⭐

2. **"BPF Performance Tools" (2019)**
   - 作者: Brendan Gregg
   - 出版: Addison-Wesley
   - 适合: 性能分析专家
   - 内容: 100+ BPF 工具

3. **"Linux Observability with BPF" (2019)**
   - 作者: David Calavera, Lorenzo Fontana
   - 出版: O'Reilly
   - 适合: 可观测性领域

### 官方文档

- **eBPF.io**: https://ebpf.io/
  - What is eBPF
  - 教程和指南
  - 项目展示

- **内核 BPF 文档**: https://docs.kernel.org/bpf/
  - BPF 指令集
  - Verifier 规则
  - Helper 函数参考

- **Cilium eBPF 库**: https://github.com/cilium/ebpf
  - Go 语言 eBPF 库
  - 丰富的示例

### 在线教程

1. **BPF CO-RE 系列** by Andrii Nakryiko
   - Part 1: https://nakryiko.com/posts/bpf-portability-and-co-re/
   - Part 2: https://nakryiko.com/posts/bcc-to-libbpf-howto-guide/
   - 必读！BPF 可移植性核心

2. **eBPF Summit 演讲**
   - YouTube: https://www.youtube.com/c/eBPFSummit
   - 年度技术大会录像

3. **BPF Performance Tools Blog**
   - Brendan Gregg: https://www.brendangregg.com/blog/
   - 性能分析案例

---

## 6.4 工具和库

### 开发工具

#### BPF 工具链
```bash
# Ubuntu/Debian
sudo apt-get install \
    clang \
    llvm \
    libbpf-dev \
    bpftool \
    linux-tools-generic

# RHEL/CentOS
sudo yum install \
    clang \
    llvm \
    libbpf-devel \
    bpftool
```

#### 调试工具
```bash
# BCC 工具集（Python BPF 前端）
sudo apt-get install bpfcc-tools

# 常用工具
sudo opensnoop-bpfcc     # 监控 open 系统调用
sudo execsnoop-bpfcc     # 监控进程创建
sudo tcpconnect-bpfcc    # 监控 TCP 连接

# bpftrace（高级脚本工具）
sudo apt-get install bpftrace

# 示例：统计系统调用
sudo bpftrace -e 'tracepoint:raw_syscalls:sys_enter { @[comm] = count(); }'
```

#### 性能分析
```bash
# perf（Linux 性能分析工具）
sudo apt-get install linux-tools-generic

# 记录事件
sudo perf record -g -a -- sleep 30
sudo perf report

# 实时监控
sudo perf top -g

# Flamegraph 火焰图
git clone https://github.com/brendangregg/FlameGraph
sudo perf script | ./FlameGraph/stackcollapse-perf.pl | \
    ./FlameGraph/flamegraph.pl > flamegraph.svg
```

### 开发库

#### libbpf（推荐）
```c
// 现代 BPF 程序开发库
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

// 使用 skeleton 加载 BPF 程序
#include "my_program.skel.h"

struct my_program_bpf *skel = my_program_bpf__open_and_load();
my_program_bpf__attach(skel);
```

#### BCC（Python/C++）
```python
from bcc import BPF

# BPF 程序（C 代码字符串）
bpf_text = """
int hello(void *ctx) {
    bpf_trace_printk("Hello, World!\\n");
    return 0;
}
"""

b = BPF(text=bpf_text)
b.attach_kprobe(event="sys_clone", fn_name="hello")
```

---

## 6.5 示例代码和实战项目

### Falco 官方示例

```bash
# 克隆示例仓库
git clone https://github.com/falcosecurity/libs.git
cd libs

# 驱动示例
cd driver
less main.c              # 内核模块示例
less bpf/probe.c         # BPF 程序示例
less modern_bpf/         # Modern BPF 示例

# 用户态示例
cd ../userspace
less libscap/examples/   # libscap 使用示例
```

### 社区项目

1. **Tracee** by Aqua Security
   - 仓库: https://github.com/aquasecurity/tracee
   - 功能: eBPF 运行时安全检测
   - 类似 Falco，但更专注容器

2. **Tetragon** by Cilium
   - 仓库: https://github.com/cilium/tetragon
   - 功能: eBPF 安全可观测性
   - 与 Cilium 深度集成

3. **Inspektor Gadget** by Kinvolk
   - 仓库: https://github.com/inspektor-gadget/inspektor-gadget
   - 功能: Kubernetes 调试工具集
   - 基于 BCC/libbpf

### 练习项目建议

#### 初级项目
1. **简单系统调用监控器**
   - 监控 `open`/`read`/`write`
   - 统计调用次数和延迟
   - 输出到 `/proc` 文件

2. **进程树追踪器**
   - 监控 `fork`/`exec`
   - 构建进程树
   - 检测异常进程链

#### 中级项目
3. **文件访问审计器**
   - 监控敏感文件访问（`/etc/passwd`, `/etc/shadow`）
   - 记录访问者 PID、UID、时间
   - 生成审计日志

4. **网络连接追踪器**
   - 监控 `connect`/`accept`/`bind`
   - 关联进程和 socket
   - 可视化网络拓扑

#### 高级项目
5. **容器逃逸检测器**
   - 检测容器内的特权操作
   - 监控 namespace 切换
   - 检测 `mount` 异常

6. **性能分析框架**
   - 实现类似 `strace` 的工具
   - 统计系统调用耗时
   - 生成火焰图

---

## 6.6 技术博客和文章

### 必读博客

1. **Brendan Gregg's Blog**
   - URL: https://www.brendangregg.com/
   - 主题: 性能分析、eBPF、火焰图
   - 必读文章:
     - "Linux Performance Analysis in 60 seconds"
     - "eBPF: One Small Step"

2. **Cilium Blog**
   - URL: https://cilium.io/blog/
   - 主题: eBPF、网络、安全
   - 推荐:
     - "eBPF - The Future of Networking & Security"
     - "BPF Performance Tools"

3. **LWN.net (Linux Weekly News)**
   - URL: https://lwn.net/
   - 内核开发新闻和深度文章
   - 订阅: $7/月（支持开源新闻）

### 中文资源

1. **《深入理解 Linux 内核》中文翻译**
   - 在线阅读: https://0xax.gitbooks.io/linux-insides/

2. **eBPF 中文社区**
   - 网站: https://ebpf.top/
   - 翻译官方文档和教程

3. **CloudNative 社区**
   - 网站: https://cloudnative.to/
   - Falco、eBPF 相关文章

---

## 6.7 会议和活动

### 国际会议

1. **eBPF Summit** (年度，9月)
   - 专注 eBPF 技术
   - 免费虚拟参会
   - 录像: https://ebpf.io/summit/

2. **Linux Plumbers Conference** (年度，9月)
   - 内核开发者大会
   - 包含 BPF、Tracing 专题

3. **KubeCon + CloudNativeCon** (年度，春/秋)
   - CNCF 旗舰会议
   - Falco 专题演讲

### 国内活动

1. **KCD China (Kubernetes Community Days)**
   - 多个城市举办
   - 云原生技术分享

2. **OpenInfra Days**
   - 开源基础设施大会
   - 包含内核、容器相关议题

---

## 6.8 认证和职业发展

### 相关认证

1. **CKS (Certified Kubernetes Security Specialist)**
   - 包含 Falco 相关内容
   - 费用: $395
   - 链接: https://training.linuxfoundation.org/certification/cks/

2. **Linux Foundation Certifications**
   - LFCS (Linux Foundation Certified Sysadmin)
   - LFCE (Linux Foundation Certified Engineer)

### 职业路径

#### 运行时安全工程师
- 技能: Falco、eBPF、内核安全
- 公司: Aqua, Sysdig, DataDog

#### 内核开发工程师
- 技能: 驱动开发、性能优化
- 公司: Red Hat, Canonical, Intel

#### 云原生安全专家
- 技能: Kubernetes、容器安全、Falco
- 公司: 各大云厂商

---

## 6.9 实用脚本和配置

### Vim 配置（内核开发）

```vim
" ~/.vimrc - 内核开发配置

" 缩进设置（内核风格：Tab = 8 空格）
set tabstop=8
set shiftwidth=8
set noexpandtab

" 代码高亮
syntax on
filetype plugin indent on

" 内核代码标记
autocmd BufRead,BufNewFile *.c,*.h set cindent
autocmd BufRead,BufNewFile *.c,*.h set cinoptions=:0,l1,t0,g0,(0

" cscope 支持
if has("cscope")
    set csprg=/usr/bin/cscope
    set csto=0
    set cst
    set nocsverb
    cs add cscope.out
    set csverb
endif
```

### Git 配置（提交内核补丁）

```bash
# ~/.gitconfig

[user]
    name = Your Name
    email = your.email@example.com

[sendemail]
    smtpserver = smtp.gmail.com
    smtpserverport = 587
    smtpencryption = tls
    smtpuser = your.email@gmail.com

[format]
    signoff = true
```

### 构建脚本

```bash
#!/bin/bash
# build_all_drivers.sh - 构建所有三种驱动

set -e

echo "=== Building Kernel Module ==="
cd driver
make clean
make
sudo insmod falco.ko || true
lsmod | grep falco

echo "=== Building Legacy BPF ==="
cd bpf
make clean
make
file probe.o

echo "=== Building Modern BPF ==="
cd ../modern_bpf
mkdir -p build && cd build
cmake ..
make
ls -lh *.bpf.o

echo "=== All drivers built successfully ==="
```

---

## 6.10 获取帮助

### 提问技巧

遵循 **"How to Ask Questions The Smart Way"**：

1. **做好准备**：先搜索、阅读文档
2. **清晰描述**：内核版本、驱动类型、错误信息
3. **提供上下文**：完整的错误日志、`dmesg` 输出
4. **展示尝试**：说明已经尝试过的解决方案

### 社区支持

- **GitHub Issues**: 报告 bug 和功能请求
- **Slack**: 实时讨论和快速问答
- **Stack Overflow**: 标签 `falco`, `ebpf`, `linux-kernel`

### 商业支持

- **Sysdig**: Falco 原始开发者，提供商业支持
- **Red Hat**: OpenShift 中的 Falco 支持

---

## 6.11 保持更新

### 订阅邮件列表

```bash
# Falco 开发邮件列表
https://lists.cncf.io/g/cncf-falco-dev

# 内核邮件列表（高级）
https://lore.kernel.org/lkml/
```

### RSS 订阅

- Falco 博客: https://falco.org/blog/index.xml
- CNCF 博客: https://www.cncf.io/blog/feed/
- LWN.net: https://lwn.net/headlines/rss

### 社交媒体

- Twitter/X: @falco_org, @ciliumproject, @brendangregg
- LinkedIn: Falco 官方页面

---

## 结语

恭喜你完成了 Falco Driver 学习指南的全部内容！

### 学习回顾

你现在已经掌握了：

✅ Falco 驱动的三种实现模式
✅ 代码结构和核心数据结构
✅ 系统调用拦截和事件捕获机制
✅ 编译、调试和扩展驱动
✅ 多架构支持和容器集成
✅ 性能优化和安全性考虑

### 下一步建议

1. **动手实践**：编译并运行 Falco 驱动
2. **阅读源码**：深入研究感兴趣的部分
3. **参与社区**：在 Slack/GitHub 提问和分享
4. **贡献代码**：修复 bug 或添加新特性
5. **应用到项目**：将技术应用到实际工作中

### 持续学习

记住：

> "代码是最好的文档" - 遇到疑问时，直接阅读源码往往比文档更准确

> "实践出真知" - 动手编写代码，调试错误，才能真正理解

祝你在 Linux 内核驱动和 eBPF 的学习之路上越走越远！🚀

---

**反馈和贡献**

如果你发现文档中的错误或有改进建议，欢迎：
- 提交 Issue
- 发起 Pull Request
- 在社区分享你的学习经验

---

**Happy Hacking! 🐧**
