# Falco Driver 完整学习指南

欢迎来到 Falco Driver 完整学习指南！本指南将帮助你从零开始掌握 Falco 驱动开发，包括 Linux 内核模块和 eBPF 技术。

## 📚 关于本指南

本学习指南专为**内核驱动开发新手**设计，假设你：
- 有基础的 C/C++ 编程经验
- 了解 Linux 基本操作
- 对内核驱动开发是新手
- 对 eBPF 了解有限

## 📖 目录

### [00. 总览和导航](./00-overview.md)
- 学习路径和文档结构
- 快速开始指南
- 学习建议

### [01. 基础架构](./01-basic-architecture.md)
学习 Falco 驱动的基本概念和架构设计：
- **1.1** Falco 驱动的基本架构
- **1.2** 三种驱动模式详解
  - Kernel Module（传统内核模块）
  - Legacy BPF Probe
  - Modern BPF Probe
- **1.3** 三种模式性能对比
- **1.4** 驱动与用户态的交互方式

### [02. 代码结构分析](./02-code-structure.md)
深入了解 Falco 驱动的代码组织：
- **2.1** 主要源码目录详解
- **2.2** 关键数据结构详解
  - 事件头（Event Header）
  - 环形缓冲区上下文
  - 事件填充器参数
- **2.3** 事件捕获的完整流程
- **2.4** 系统调用拦截的实现机制对比

### [03. 核心功能深入](./03-core-features.md)
掌握 Falco 驱动的核心功能实现：
- **3.1** 系统调用钩子实现
- **3.2** 事件缓冲区设计
- **3.3** 进程上下文信息收集
- **3.4** 网络事件捕获机制
- **3.5** 文件系统操作监控

### [04. 实践指导](./04-practice-guide.md)
动手实践和调试技巧：
- **4.1** 编译和加载 Falco 驱动
- **4.2** 调试驱动代码
- **4.3** 添加自定义系统调用监控
- **4.4** 修改事件数据结构
- **4.5** 性能分析与优化

### [05. 高级主题](./05-advanced-topics.md)
深入探讨高级技术和架构设计：
- **5.1** 多架构支持
- **5.2** 容器和 Kubernetes 集成
- **5.3** 安全性考虑
- **5.4** 与其他技术对比
- **5.5** 性能优化深入
- **5.6** 扩展阅读

### [06. 学习资源](./06-resources.md)
相关学习资源和社区支持：
- **6.1** 官方资源
- **6.2** Linux 内核开发学习
- **6.3** eBPF 学习资源
- **6.4** 工具和库
- **6.5** 示例代码和实战项目
- **6.6** 技术博客和文章
- **6.7** 会议和活动
- **6.8** 认证和职业发展

## 🚀 快速开始

### 推荐学习路径

#### 第 1 周：基础理解
- **第 1-2 天**：阅读 [01-basic-architecture.md](./01-basic-architecture.md)
  - 理解三种驱动模式的区别
  - 掌握核心工作原理
- **第 3-4 天**：阅读 [02-code-structure.md](./02-code-structure.md)
  - 熟悉代码组织结构
  - 理解关键数据结构
- **第 5-7 天**：阅读 [03-core-features.md](./03-core-features.md)
  - 学习系统调用拦截
  - 了解事件捕获流程

#### 第 2 周：动手实践
- **第 8-10 天**：跟随 [04-practice-guide.md](./04-practice-guide.md)
  - 搭建开发环境
  - 编译和加载驱动
  - 学习调试技巧
- **第 11-14 天**：实践项目
  - 添加自定义监控
  - 修改事件结构
  - 性能测试

#### 第 3 周及以后：深入进阶
- 阅读 [05-advanced-topics.md](./05-advanced-topics.md)
- 研究 [06-resources.md](./06-resources.md) 推荐的书籍和资源
- 参与开源社区贡献

## 💡 学习建议

### 1. 理论与实践结合
```bash
# 边学习边实验
git clone https://github.com/falcosecurity/libs.git
cd libs/driver
# 阅读代码，添加 printk 调试输出
```

### 2. 使用调试工具
```bash
# 内核模块调试
sudo dmesg -w

# BPF 程序调试
sudo cat /sys/kernel/debug/tracing/trace_pipe
sudo bpftool prog show
```

### 3. 阅读源代码
- 文档是指引，源代码是真相
- 使用 `grep`、`cscope`、`ctags` 导航代码
- 从简单函数开始，逐步深入

### 4. 参与社区
- 在 Slack 提问：https://kubernetes.slack.com/messages/falco
- 查看 GitHub Issues：https://github.com/falcosecurity/falco/issues
- 关注技术博客和会议

## 📋 前置知识检查

在开始学习之前，建议你具备以下知识：

### 必须掌握
- ✅ C 语言基础（指针、结构体、函数）
- ✅ Linux 命令行操作
- ✅ Git 基本使用

### 建议了解
- 📖 操作系统概念（进程、内存、文件系统）
- 📖 系统调用基础（open、read、write）
- 📖 基本的 Makefile/CMake

### 可选加分项
- 🌟 编译过 Linux 内核
- 🌟 写过简单的内核模块
- 🌟 了解 eBPF 概念

## 🛠️ 开发环境推荐

### 操作系统
- **Ubuntu 22.04/24.04** (推荐初学者)
- **Fedora 39+** (较新的内核)
- **Debian 12+**

### 工具
```bash
# 必需
sudo apt-get install \
    build-essential \
    linux-headers-$(uname -r) \
    cmake \
    git

# 推荐
sudo apt-get install \
    clang \
    llvm \
    bpftool \
    bpfcc-tools \
    vim \
    cscope \
    ctags
```

### IDE/编辑器
- **Vim/Neovim** (配置 cscope 插件)
- **VSCode** (C/C++ 扩展)
- **CLion** (商业，功能强大)

## 📊 学习进度跟踪

使用这个 checklist 跟踪你的学习进度：

- [ ] 第一章：理解三种驱动模式
- [ ] 第一章：完成思考题
- [ ] 第二章：熟悉代码结构
- [ ] 第二章：阅读 `main.c` 和 `ppm_fillers.c`
- [ ] 第三章：理解系统调用拦截
- [ ] 第三章：理解环形缓冲区
- [ ] 第四章：成功编译内核模块
- [ ] 第四章：成功加载驱动
- [ ] 第四章：添加自定义监控
- [ ] 第五章：了解多架构支持
- [ ] 第五章：学习容器集成
- [ ] 第六章：阅读推荐书籍
- [ ] 第六章：参与社区讨论
- [ ] 完成一个实战项目

## 🎯 学习目标

完成本指南后，你将能够：

1. **理解** Falco 驱动的三种实现模式及其差异
2. **解释** 系统调用拦截和事件捕获的完整流程
3. **编译和加载** 三种类型的 Falco 驱动
4. **调试** 内核模块和 BPF 程序
5. **扩展** Falco 驱动，添加自定义监控功能
6. **优化** 驱动性能，减少系统开销
7. **集成** Falco 到容器和 Kubernetes 环境
8. **贡献** 代码到 Falco 开源项目

## 🤝 贡献指南

发现文档错误或有改进建议？欢迎贡献！

### 报告问题
- 提交 Issue 描述问题
- 包含章节号和具体内容

### 改进文档
1. Fork 仓库
2. 创建分支：`git checkout -b improve-doc`
3. 修改文档
4. 提交 PR

### 分享经验
- 在社区分享你的学习笔记
- 编写博客文章
- 录制教学视频

## 📞 获取帮助

遇到问题？这里有多种方式获取帮助：

### 社区支持
- **Slack**: https://kubernetes.slack.com/messages/falco
- **GitHub Discussions**: https://github.com/falcosecurity/falco/discussions
- **Stack Overflow**: 标签 `falco`, `ebpf`, `linux-kernel`

### 提问技巧
1. 描述清楚问题（内核版本、驱动类型）
2. 提供完整的错误日志
3. 说明已经尝试的解决方案
4. 附上相关代码片段

## 📜 许可证

本学习指南采用 **CC BY-SA 4.0** 许可证。

- ✅ 可以自由分享和修改
- ✅ 必须署名原作者
- ✅ 必须使用相同许可证分享修改版本

## 🌟 致谢

本指南参考了以下资源：
- Falco 官方文档
- Linux 内核文档
- eBPF.io 教程
- 社区贡献者的博客和文章

特别感谢：
- Falco 社区
- Sysdig 团队
- CNCF

## 📊 文档状态

- **版本**: v1.0
- **最后更新**: 2026-01-14
- **基于 Falco 版本**: 0.39.0+
- **内核版本覆盖**: 3.10 - 6.x

## 🚀 开始学习

准备好了吗？让我们开始吧！

👉 [点击这里开始第一章：基础架构](./01-basic-architecture.md)

---

**祝你学习愉快！Happy Hacking! 🐧**

如有任何问题，随时在社区提问。我们期待看到你的进步和贡献！
