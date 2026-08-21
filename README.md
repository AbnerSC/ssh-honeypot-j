<div style="text-align: center;">
  <img src="docs/logo.svg" alt="NetGazer Logo" width="160"/>
</div>


# NetGazer 网络凝视者
一款 **中交互** 多协议蜜罐，静默凝视每一次针对服务器的暴力破解与入侵行为。


基于 **Apache MINA SSHD** 实现 SSH 协议，原生 Socket 实现 Telnet 协议，
内置伪装的 Ubuntu 22.04 虚拟文件系统与伪 Shell，
支持 SSH / Telnet / MySQL / PostgreSQL / Redis 多协议诱捕，
并内置 Web 可视化控制台与攻击归属地分析。

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
- **攻击日志**：JSONL 格式（`logs/honeypot.jsonl`）与 SQLite（`db/database.db`）双写，
  记录来源 IP、登录凭证、每条命令、恶意下载 URL、会话时长，可直接对接 ELK / jq 分析
- **Web 可视化控制台**：内置浏览器端管理界面（同进程部署，随 fat-jar 一起打包），
  提供攻击日志统计图表、明细查询与系统用户管理，详见下文
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

# 数据库蜜罐：连接时立即返回默认的认证失败信息并断开连接，不做任何协议交互
mysql:
  enabled: true      # 是否启用 MySQL 蜜罐（模拟 8.4，连接即返回 Access denied 1045/28000）
  port: 3306         # MySQL 监听端口

postgresql:
  enabled: true      # 是否启用 PostgreSQL 蜜罐（模拟 17，连接即返回 FATAL 28P01 认证失败）
  port: 5432         # PostgreSQL 监听端口

redis:
  enabled: true      # 是否启用 Redis 蜜罐（模拟 7，连接即返回 WRONGPASS）
  port: 6379         # Redis 监听端口

log:
  file: logs/honeypot.jsonl   # 攻击日志文件路径
  db: db/database.db        # SQLite 数据库文件（与 JSONL 双写同一份数据，供 Web 可视化）
  ipdb_v4: db/ip2region_v4.xdb  # IP 归属地离线库文件（ip2region xdb 格式 ipv4），解析来源 IP 为“国家 省份 城市”；
  ipdb_v6: db/ip2region_v6.xdb  # IP 归属地离线库文件（ip2region xdb 格式 ipv6），解析来源 IP 为“国家 省份 城市”；
  # 可选覆盖项：文件缺失时自动回退使用 jar 内置库（已随包打包），均缺失时归属地留空，不影响其他功能

# Web 可视化控制台：攻击日志统计与明细查询、系统用户管理（与蜜罐同进程部署）
# 首次启动自动创建默认管理员 admin/admin123，登录后强制修改密码
web:
  enabled: true            # 是否启用 Web 控制台
  port: 8080               # Web 监听端口
  sessionTimeoutMinutes: 30  # 管理端登录会话超时（分钟）
```

配置文件不存在时使用内置默认值（SSH:2222、Telnet:2323、日志 logs/honeypot.jsonl、Web:8080）。

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

> 注意先把真实 sshd 移到别的端口，避免把自己锁在门外。

## Web 可视化控制台

与蜜罐同进程部署，前端页面与接口随 fat-jar 一起打包，无需额外服务。启动后访问
`http://<主机IP>:8080/` 即可。

**功能：**

- **攻击日志统计**：总览指标（会话数、登录尝试、命令数、攻击 IP 数）、近 N 天趋势、
  协议分布、Top 攻击 IP / 用户名 / 口令（ECharts 图表）
- **明细查询**：会话、登录尝试、命令、恶意下载、IP 锁定五类事件的分页查询，
  支持按来源 IP / 用户名 / 协议 / 关键字 / 时间范围过滤
- **系统用户管理**：管理员可创建 / 禁用 / 删除账号、重置口令

**登录与安全：**

- 首次启动自动创建默认管理员 `admin/admin123`，登录后强制修改密码
- 口令以 PBKDF2-HMAC-SHA256 加盐哈希存储；登录态由服务端 Session（HttpOnly Cookie）承载
- 连续 5 次登录失败锁定来源 IP 15 分钟；会话默认 30 分钟超时
- 双角色：`admin`（全部权限）与 `viewer`（仅查看日志统计与明细）

> 建议：8080 端口仅对运维网段开放，不要将管理控制台直接暴露到公网。

## Docker 部署

镜像基于 JDK 25 运行时构建，开箱即用。

### 使用docker镜像（推荐）

创建 `docker-compose.yml`，将日志目录挂载到宿主机，并映射 SSH(2222) 与 Telnet(2323) 端口：

```yaml
services:
  ssh-honeypot-j:
    image: babyfly/ssh-honeypot-j:latest
    # 阿里云：crpi-gbejqvtf2wfon7bh.cn-chengdu.personal.cr.aliyuncs.com/scdm/ssh-honeypot-j:dev
    container_name: ssh-honeypot-j
    restart: always
    volumes:
      - ${PWD}/logs:/app/logs  # 挂载宿主机日志目录
      - ${PWD}/db:/app/db      # 挂载宿主机数据库目录
    environment:
      - TZ=Asia/Shanghai       # 时区，北京时间
    ports:
      - 22:2222                # SSH端口
      - 23:2323                # Telnet端口
      - 3306:3306              # MySQL数据库端口
      - 5432:5432              # Postgre数据库端口
      - 6379:6379              # Redis数据库端口
      - 127.0.0.1:11800:8080   # Web控制台端口，建议使用nginx代理为https
    mem_limit: 512m            # 内存限制，被持续攻击大约需要290MB
    healthcheck:
      test: ["CMD", "curl", "-f", "http://127.0.0.1:8080"]
      interval: 10s
      timeout: 3s
      retries: 3
      start_period: 20s
```

启动：

```bash
mkdir logs db
docker compose up -d
```

- `${PWD}/logs` 为宿主机日志目录，攻击日志实时写入 `./logs/honeypot.jsonl`
- `${PWD}/db` 持久化 SQLite 数据库（攻击日志与系统用户），重建容器不丢数据。还可以自己更新IP库，文件名：ip2region_v4.xdb、ip2region_v6.xdb，下载地址：https://github.com/lionsoul2014/ip2region
- `mem_limit: 512m` 限制容器内存，避免海量会话拖垮宿主机
- 蜜罐服务端口（3306/5432/6379）同样在容器内监听，需要诱捕数据库端口时自行追加映射
- 如需自定义配置，可将 `config.yaml` 一并挂载，如：`${PWD}/config.yaml:/app/config.yaml`

  ```yaml
  volumes:
    - ${PWD}/logs:/app/logs
    - ${PWD}/db:/app/db
    - ${PWD}/config.yaml:/app/config.yaml
  ```
  
登录：
```angular2html
地址：http://127.0.0.1:8080
账号：admin
密码：admin123
```

## 测试

```bash
ssh -p 2222 root@127.0.0.1
telnet 127.0.0.1 2323
ssh -p 2222 root@127.0.0.1 "uname -a; cat /etc/passwd"
```

## 日志格式

- 每行一个 JSON 事件
- 同步保存到数据库（WAL 模式，攻击事件在 JSONL 之外同步写入 `db/database.db`）

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
- [ ] 操作审计日志增加中文说明

## 版本历史

### release-v1.1.4（2026-08-21）

> 本期聚焦安全性

**改进**
- 更换 Docker 基础镜像，提升安全性

---

### release-v1.1.3（2026-08-20）

> 本期聚焦部署与易用性提升

**新增**
- 添加 Docker 镜像自动发布功能

---

### release-v1.1.2（2026-08-18）

> 本期聚焦系统稳定性

**改进**
- 优化IP归属地数据库加载方式，提升系统性能
- 修复已知问题，提升系统稳定性

**新增**
- **系统logo**：新增系统logo，提升界面 professionalism

---

### release-v1.1.1（2026-08-17）

**新增**
- **攻击来源归属地**：查询和统计增加攻击归属地信息，方便通过地区拦截攻击者

---

### release-v1.1.0（2026-08-17）

> 本期聚焦可观测性：攻击数据结构化落库，并提供内置 Web 可视化管理控制台。

**新增**
- **SQLite 双写存储**：攻击事件在 JSONL 之外同步写入 `db/database.db`（WAL 模式，
  蜜罐写入与 Web 查询互不阻塞），涵盖会话 / 登录尝试 / 命令 / 下载 / IP 锁定五类事件。
- **Web 可视化控制台**：内嵌 Javalin（Jetty），前端静态页与 ECharts 随 fat-jar 一起打包，
  离线可用；提供统计总览、趋势/协议/Top 榜单图表、五类事件明细分页过滤查询。
- **系统用户管理**：admin / viewer 双角色，支持创建、禁用、删除账号与重置口令。
- **登录安全**：PBKDF2-HMAC-SHA256 加盐哈希、服务端 Session（HttpOnly Cookie）、
  首次登录强制改密、登录失败 IP 锁定、会话固定攻击防护。

---

### release-v1.0.3（2026-08-14）

> 本期聚焦账号隔离与权限真实度，是对 1.0.2 的能力增强版本。

**新增 / 改进**
- **用户主目录隔离**：为每个登录用户生成独立的默认 `/home/<user>` 目录，攻击者在各自主目录中操作，互不干扰。
- **目录权限检查**：`cd` 命令增加权限校验，用户默认目录拒绝其他用户访问，越权访问被拒绝，行为更贴近真实 Linux 系统。
- **IP 锁定策略增强**：IP 锁定增加"计数窗口时长"配置，暴力破解计数在指定时间窗口内累计，窗口外自动回落，降低误锁正常流量。
- **密码本完善**：支持单个用户配置多个密码（列表形式），命中任一密码即视为登录成功，弱口令覆盖更全。

---

### release-v1.0.2（2026-08-13）

> 引入容器化交付，蜜罐可一键 Docker 部署。

**新增**
- **Docker 镜像发布**：新增 `docker-maven-plugin`，支持 `mvn deploy` 构建本地镜像并推送到 Nexus 仓库。
- 发布镜像默认附加 `latest` 标签，便于拉取最新稳定版。

**安全 / 稳定性**
- 修复客户端直接断开网络（非 `exit` 正常退出）时攻击日志无法记录的问题。

**依赖**
- sshd-core `2.19.0`、slf4j `2.0.18`、snakeyaml `2.6`、docker-maven-plugin `0.49.0`。

---

### release-v1.0.1（2026-08-12）

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

### release-v1.0.0（2026-08-11）

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
