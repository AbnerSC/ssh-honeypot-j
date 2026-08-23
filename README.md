<div style="text-align: center;">
  <img src="docs/logo.svg" alt="NetGazer Logo" width="160"/>
</div>

# NetGazer 网络凝视者
一款 **中交互** 多协议蜜罐，静默凝视每一次针对服务器的暴力破解与入侵行为。

## GitHub
https://github.com/AbnerSC/ssh-honeypot-j.git

[![GitHub Stars](https://img.shields.io/github/stars/AbnerSC/ssh-honeypot-j?style=flat&label=Stars)](https://github.com/AbnerSC/ssh-honeypot-j/stargazers)
[![Docker Pulls](https://img.shields.io/docker/pulls/babyfly/ssh-honeypot-j?label=Docker%20Pulls)](https://hub.docker.com/r/babyfly/ssh-honeypot-j)

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

## 技术栈

| 类别 | 技术 | 版本 | 用途 |
| --- | --- | --- | --- |
| 语言 / 运行时 | Java | 25 | 开发语言，启用紧凑对象头（JEP 519）等运行时优化 |
| SSH 协议 | Apache MINA SSHD | 2.19.0 | 实现 SSH 服务端与协议交互 |
| Telnet 协议 | 原生 Socket | - | 实现 Telnet 协议与 IAC 终端协商 |
| Web 控制台 | Javalin（Jetty 12） | 7.2.3 | 轻量嵌入式 Web 框架，承载管理 API 与静态前端 |
| 前端图表 | ECharts（WebJar） | 6.1.0 | 攻击统计图表，随 fat-jar 打包离线可用 |
| JSON | Gson | 2.14.0 | 接口 JSON 序列化 / 反序列化 |
| 配置解析 | SnakeYAML | 2.6 | 解析 `config.yaml` 配置文件 |
| 存储 | SQLite（sqlite-jdbc） | 3.53.2.1 | 攻击事件与系统用户结构化存储（WAL 模式） |
| IP 归属地 | ip2region | 3.3.7 | 离线 xdb 库解析来源 IP 归属地（IPv4 / IPv6 双库） |
| 日志 | SLF4J + JDK14 | 2.0.18 | 运行日志门面与输出 |
| 构建打包 | Maven Shade Plugin | 3.5.3 | 生成含全部依赖的可执行 fat-jar |
| 容器化 | Docker / docker-maven-plugin | 0.49.0 | 基于 `eclipse-temurin:25-jdk-noble` 构建镜像，`mvn deploy` 推送 |
| CI/CD | GitHub Actions | - | 多架构镜像自动构建与发布 |

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
    # 阿里云：crpi-gbejqvtf2wfon7bh.cn-chengdu.personal.cr.aliyuncs.com/scdm/ssh-honeypot-j:latest
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
    mem_limit: 300m            # 内存限制，被持续攻击大约需要240MB
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
- [X] 操作审计日志增加中文说明

## 版本历史

### release-v1.1.5（2026-08-22）
- 优化性能，降低内存使用
- 审计日志增加操作描述
- 补充项目文档

### release-v1.1.4（2026-08-21）
- 更换 Docker 基础镜像，提升安全性

### release-v1.1.3（2026-08-20）
- 新增 Docker 镜像自动发布

### release-v1.1.2（2026-08-18）
- 优化 IP 归属地数据库加载方式，提升性能
- 新增系统 logo
- 修复已知问题

### release-v1.1.1（2026-08-17）
- 攻击查询与统计新增归属地信息，支持按地区拦截攻击

### release-v1.1.0（2026-08-17）
- 攻击事件结构化落库 SQLite（WAL 双写，覆盖五类事件）
- 内置 Web 可视化控制台（统计总览、图表、明细分页查询）
- 系统用户管理（admin / viewer 双角色）
- 登录安全加固：加盐哈希、强制改密、失败锁定 IP、会话固定防护

### release-v1.0.3（2026-08-14）
- 用户主目录隔离，各账号独立 `/home/<user>`
- `cd` 增加权限校验，越权访问被拒绝
- IP 锁定增加计数窗口时长配置，降低误锁
- 支持单用户多密码，命中任一即登录成功

### release-v1.0.2（2026-08-13）
- 引入 `docker-maven-plugin`，支持 `mvn deploy` 构建并推送镜像到 Nexus
- 镜像默认附加 `latest` 标签
- 修复客户端直接断开网络时攻击日志丢失的问题

### release-v1.0.1（2026-08-12）
- 新增 `config.yaml` 配置文件，可自定义端口、日志路径、账号密码本
- 新增账号密码本，登录失败达阈值锁定来源 IP
- Shell 命令随机延时，扩充命令支持，输出更贴近真实系统
- 升级至 JDK 25，启用紧凑对象头等运行时优化

### release-v1.0.0（2026-08-11）
- 首个可用版本：SSH / Telnet 蜜罐、伪 Shell、内存虚拟文件系统、JSONL 攻击日志、exec 通道记录
