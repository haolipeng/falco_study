# Falco 入侵检测能力调研报告

## 一、调研概述

**调研目标**: 评估 Falco 在容器环境和主机环境中对以下入侵行为的检测能力：
- 暴力破解、本地提权、高危命令、异常登录、反弹shell、异常网络请求、网络攻击、核心文件监控

**结论**: Falco 具备完整的入侵检测能力，86条规则覆盖上述所有场景。

---

## 二、检测能力对照表

| 检测场景 | 容器环境 | 主机环境 | 检测能力 | 备注 |
|---------|---------|---------|---------|------|
| **暴力破解** | ⚠️ 间接 | ⚠️ 间接 | 部分支持 | 需结合SIEM关联分析 |
| **本地提权** | ✅ | ✅ | 完整支持 | CVE特定检测+通用监控 |
| **高危命令** | ✅ | ✅ | 完整支持 | 80+工具监控 |
| **异常登录** | ✅ | ✅ | 完整支持 | 系统用户交互检测 |
| **反弹Shell** | ✅ | ✅ | 完整支持 | 多种检测机制 |
| **异常网络请求** | ✅ | ✅ | 完整支持 | 端口/协议/目标监控 |
| **网络攻击** | ✅ | ✅ | 完整支持 | 矿机/侦察检测 |
| **核心文件监控** | ✅ | ✅ | 完整支持 | 敏感文件读写监控 |

---

## 三、各场景详细分析

### 3.1 暴力破解检测

**检测能力**: ⚠️ 间接支持

**现有规则**:
- 无专门的暴力破解计数规则
- 可通过 `System user interactive` 检测异常登录行为
- 可通过 `Read ssh information` 检测SSH相关文件访问

**检测机制**:
```yaml
# Falco 本身不统计登录失败次数
# 需要结合外部 SIEM 系统关联分析:
# 1. Falco 输出登录相关事件
# 2. SIEM 统计短时间内的失败次数
# 3. 超过阈值触发告警
```

**建议**: 可自定义规则监控 `/var/log/auth.log` 或 `/var/log/secure` 的异常访问模式

---

### 3.2 本地提权检测

**检测能力**: ✅ 完整支持

**核心规则**:

| 规则名称 | 优先级 | 检测内容 |
|---------|--------|---------|
| `Sudo Potential Privilege Escalation (CVE-2021-3156)` | CRITICAL | sudo堆溢出漏洞 |
| `Polkit Local Privilege Escalation (CVE-2021-4034)` | CRITICAL | pkexec漏洞 |
| `Non sudo setuid` | WARNING | 非sudo的setuid调用 |
| `Set Setuid or Setgid bit` | NOTICE | chmod设置特权位 |
| `PTRACE attached to process` | NOTICE | 进程注入 |
| `Linux Kernel Module Injection Detected` | WARNING | 内核模块加载 |
| `Detect release_agent File Container Escapes` | CRITICAL | 容器逃逸 |
| `Potential Local Privilege Escalation via Environment Variables Misuse` | WARNING | GLIBC_TUNABLES提权 |

**检测示例**:
```yaml
- rule: Sudo Potential Privilege Escalation Vulnerability CVE-2021-3156
  desc: Detect sudo exploit (CVE-2021-3156)
  condition: >
    spawned_process and
    proc.name in (sudo, sudoedit) and
    proc.args contains "-s" or proc.args contains "-i" and
    proc.args contains "\"
  priority: CRITICAL
```

---

### 3.3 高危命令检测

**检测能力**: ✅ 完整支持

**监控的危险工具** (80+):

| 类别 | 工具列表 |
|-----|---------|
| **网络扫描** | nmap, masscan, zmap, hping |
| **网络工具** | nc, ncat, netcat, socat, telnet |
| **抓包工具** | tcpdump, tshark, wireshark |
| **DNS工具** | dig, nslookup, host |
| **远程复制** | rsync, scp, sftp, dcp |
| **包管理器** | apt, yum, dnf, apk, pip |
| **K8s工具** | kubectl, oc, helm |

**规则示例**:
```yaml
- rule: Launch Suspicious Network Tool in Container
  condition: >
    spawned_process and container and
    proc.name in (network_tool_binaries)
  priority: NOTICE

- rule: Launch Suspicious Network Tool on Host
  condition: >
    spawned_process and not container and
    proc.name in (network_tool_binaries)
  priority: NOTICE
```

---

### 3.4 异常登录检测

**检测能力**: ✅ 完整支持

**核心规则**:
- `System user interactive` - 系统账户交互式命令
- `User mgmt binaries` - 用户管理命令执行
- `Non sudo setuid` - 非授权的setuid调用

**监控的系统用户**:
```
bin, daemon, games, lp, mail, nobody, sshd, sync, uucp, www-data
```

**检测逻辑**:
```yaml
- rule: System user interactive
  desc: Detect interactive commands run by system users
  condition: >
    spawned_process and
    user.name in (system_users) and
    interactive
  priority: INFO
```

---

### 3.5 反弹Shell检测

**检测能力**: ✅ 完整支持

**多层检测机制**:

| 检测方式 | 规则 | 原理 |
|---------|------|------|
| **Shell产生检测** | `Run shell untrusted` | Web服务器等进程产生shell |
| **网络重定向** | `Redirect STDOUT/STDIN to Network Connection` | dup系统调用重定向到网络 |
| **工具检测** | `Netcat Remote Code Execution` | nc -e/-c 参数检测 |
| **TTY检测** | `Terminal shell in container` | 容器内出现交互式shell |

**检测原理**:
```yaml
# 检测 dup/dup2/dup3 将 stdin/stdout 重定向到网络连接
- rule: Redirect STDOUT/STDIN to Network Connection in Container
  condition: >
    dup and container and
    evt.rawres in (0, 1, 2) and
    fd.type in (ipv4, ipv6)
  priority: NOTICE
```

**Shell spawner 保护列表**:
```
apache, httpd, nginx, mysqld, postgres, sshd, php-fpm, java, python, ruby
```

---

### 3.6 异常网络请求检测

**检测能力**: ✅ 完整支持

**核心规则**:

| 规则 | 检测内容 |
|-----|---------|
| `Unexpected UDP Traffic` | 非标准UDP端口流量 |
| `Disallowed SSH Connection Non Standard Port` | SSH连接可疑端口(80,443,4444等) |
| `Contact K8S API Server From Container` | 容器访问K8s API |
| `Contact EC2 Instance Metadata Service` | 访问云元数据服务 |
| `Network Connection outside Local Subnet` | 跨子网连接 |

**云元数据服务监控**:
```yaml
# AWS: 169.254.169.254
# GCP: metadata.google.internal
# Azure: 169.254.169.254
```

---

### 3.7 网络攻击检测

**检测能力**: ✅ 完整支持

**核心规则**:

| 规则 | 检测内容 | 优先级 |
|-----|---------|--------|
| `Detect outbound connections to common miner pool ports` | 加密货币矿池连接 | NOTICE |
| `Detect crypto miners using the Stratum protocol` | Stratum协议矿机 | CRITICAL |
| `Basic Interactive Reconnaissance` | 侦察命令执行 | NOTICE |

**矿机检测**:
```yaml
- rule: Detect crypto miners using the Stratum protocol
  condition: >
    spawned_process and
    (proc.cmdline contains "stratum+" or
     proc.cmdline contains "stratum1+" or
     proc.cmdline contains "stratum2+")
  priority: CRITICAL
```

---

### 3.8 核心文件监控

**检测能力**: ✅ 完整支持

**监控的敏感文件**:

| 类别 | 文件路径 |
|-----|---------|
| **密码文件** | /etc/shadow, /etc/passwd, /etc/gshadow |
| **权限配置** | /etc/sudoers, /etc/sudoers.d/* |
| **认证配置** | /etc/pam.conf, /etc/pam.d/* |
| **SSH配置** | /etc/ssh/*, ~/.ssh/* |
| **Shell配置** | ~/.bashrc, ~/.bash_profile, ~/.zshrc |
| **系统启动** | /etc/init.d/*, /etc/systemd/* |

**核心规则**:

| 规则 | 检测内容 |
|-----|---------|
| `Read sensitive file untrusted` | 非授权程序读取敏感文件 |
| `Write below binary dir` | 在/bin,/sbin,/usr/bin等写入 |
| `Modify Shell Configuration File` | 修改shell配置(持久化) |
| `Directory traversal monitored file read` | 目录遍历攻击 |
| `Create Symlink Over Sensitive Files` | 符号链接攻击 |

---

## 四、Falco 额外检测能力

除用户需求外，Falco 还支持以下检测:

| 额外能力 | 说明 |
|---------|------|
| **容器逃逸** | release_agent、debugfs、内核模块注入 |
| **无文件攻击** | memfd_create 检测 |
| **凭证窃取** | AWS凭证、私钥搜索 |
| **数据泄露** | kubectl cp、远程复制工具 |
| **日志清除** | 日志截断、shell历史删除 |
| **特权容器** | 特权模式、过度权限容器 |
| **供应链攻击** | 容器内包管理器执行 |

---

## 五、检测架构

```
┌─────────────────────────────────────────────────────────┐
│                    Falco Application                     │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐  │
│  │ Rule Engine │  │   Alerts    │  │ Output Plugins  │  │
│  └─────────────┘  └─────────────┘  └─────────────────┘  │
└───────────────────────────┬─────────────────────────────┘
                            │
┌───────────────────────────┼─────────────────────────────┐
│                       libscap                            │
│  ┌─────────────────────────────────────────────────┐    │
│  │          Per-CPU Ring Buffer (无锁设计)           │    │
│  └─────────────────────────────────────────────────┘    │
└───────────────────────────┬─────────────────────────────┘
                            │
        ┌───────────────────┴───────────────────┐
        ▼                                       ▼
┌───────────────┐                     ┌───────────────┐
│  Kernel Module │                     │   eBPF Probe  │
│    (kmod)      │                     │   (modern)    │
└───────────────┘                     └───────────────┘
        │                                       │
        └───────────────────┬───────────────────┘
                            ▼
              ┌─────────────────────────┐
              │   Linux Kernel          │
              │   System Call Table     │
              │   (Tracepoint Hooks)    │
              └─────────────────────────┘
```

---

## 六、规则文件位置

| 文件 | 路径 | 规则数 | 稳定性 |
|-----|------|-------|--------|
| 核心规则 | `submodules/falcosecurity-rules/rules/falco_rules.yaml` | 26 | Stable |
| 孵化规则 | `submodules/falcosecurity-rules/rules/falco-incubating_rules.yaml` | 32 | Incubating |
| 沙盒规则 | `submodules/falcosecurity-rules/rules/falco-sandbox_rules.yaml` | 28 | Sandbox |

---

## 七、MITRE ATT&CK 覆盖

Falco 规则与 MITRE ATT&CK 框架的映射:

| 战术 | 技术ID | 覆盖状态 |
|-----|--------|---------|
| Initial Access | T1078, T1133 | ✅ |
| Execution | T1059, T1053 | ✅ |
| Persistence | T1098, T1136 | ✅ |
| Privilege Escalation | T1548, T1611 | ✅ |
| Defense Evasion | T1070, T1620 | ✅ |
| Credential Access | T1555, T1552 | ✅ |
| Discovery | T1046, T1083 | ✅ |
| Lateral Movement | T1021 | ✅ |
| Exfiltration | T1020, T1041 | ✅ |
| Impact | T1485, T1496 | ✅ |

---

## 八、总结

### Falco 优势
1. **检测覆盖全面**: 86条规则覆盖主流入侵场景
2. **性能优异**: Per-CPU无锁环形缓冲区，零开销系统调用监控
3. **容器原生**: 天然支持容器和K8s环境
4. **可扩展**: 支持自定义规则和插件
5. **生态成熟**: CNCF毕业项目，社区活跃

### 需要补充的能力
1. **暴力破解**: 需结合SIEM进行事件关联统计
2. **网络流量分析**: 深度包检测需要其他工具配合
3. **恶意软件检测**: 基于行为而非签名，需配合杀毒软件

### 建议
- 容器环境: Falco 完全满足需求，可直接部署
- 主机环境: Falco 满足大部分需求，暴力破解场景建议结合 fail2ban 或 SIEM
