package org.open.scdm.honeypot.env;

/**
 * 蜜罐虚拟服务器环境画像：集中定义硬件、网络、系统与软件版本等"硬事实"。
 * <p>
 * CommandProcessor 的本地命令输出与 AiClient 的 systemPrompt 都引用这里的常量，
 * 保证攻击者用任意命令交叉验证（lscpu/free/ifconfig/dpkg -l/node -v ...）时口径一致，
 * 不会因本地伪造输出与大模型仿真输出矛盾而识破蜜罐。
 * <p>
 * 人设：一台全栈开发者的 Ubuntu 22.04 服务器，前后端/云原生开发工具链齐备；
 * 渗透测试与流量分析类工具（nmap/hydra/sqlmap/tcpdump 等）未安装，
 * 大模型对这些工具如实回 command not found，与蜜罐降级语义一致。
 */
public final class FakeEnv {
    private FakeEnv() {}

    /* ---------------- 系统与内核 ---------------- */
    public static final String OS_DESC = "Ubuntu 22.04.3 LTS";
    public static final String OS_RELEASE = "22.04";
    public static final String OS_CODENAME = "jammy";
    public static final String KERNEL = "5.15.0-91-generic";
    public static final String KERNEL_BUILD = "#101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023";
    public static final String ARCH = "x86_64";
    public static final String BASH_VERSION = "5.1.16(1)-release";

    /* ---------------- 硬件 ---------------- */
    public static final String CPU_MODEL = "Intel(R) Xeon(R) Platinum 8375C CPU @ 2.90GHz";
    public static final int CPU_COUNT = 4;
    public static final String MEM_TOTAL_H = "7.8Gi";
    public static final String SWAP_TOTAL_H = "2.0Gi";
    public static final String UPTIME = "47 days,  3:12";
    /** 根分区：80G 磁盘，已用 42% */
    public static final String DISK_ROOT_DEV = "/dev/sda1";
    public static final String DISK_ROOT_SIZE = "80G";
    /** 数据盘：100G 磁盘，挂载 /data，已用 19% */
    public static final String DISK_DATA_DEV = "/dev/sdb1";
    public static final String DISK_DATA_SIZE = "100G";

    /* ---------------- 网络 ---------------- */
    public static final String ETH0_IP = "10.23.76.15";
    public static final String ETH0_NETMASK = "255.255.255.0";
    public static final String ETH0_BROADCAST = "10.23.76.255";
    public static final String ETH0_MAC = "00:15:5d:00:1a:2b";
    /** 网关：与 eth0 同网段（10.23.76.0/24），arp/route/traceroute 口径一致 */
    public static final String GATEWAY = "10.23.76.1";
    public static final String DNS = "10.0.0.2";
    /** 所有外部域名统一解析到的地址（dig/nslookup/ping/wget/getent hosts 共用） */
    public static final String WAN_IP = "93.184.216.34";
    /** 监听服务（netstat/ss/lsof 与 AI 口径一致）：sshd:22、nginx:80、mysqld:3306 */
    public static final String LISTEN_PORTS = "sshd:22, nginx:80, mysqld:3306";

    /* ---------------- 软件版本（本地命令输出与 AI 提示词共用） ---------------- */
    public static final String DOCKER = "24.0.7";
    public static final String DOCKER_API = "1.43";
    public static final String DOCKER_COMPOSE = "1.29.2";
    public static final String GIT = "2.34.1";
    public static final String PYTHON = "3.10.12";
    public static final String PIP = "22.0.2+dfsg-1ubuntu0.4";
    public static final String NODE = "v20.11.0";
    public static final String NPM = "10.2.4";
    public static final String YARN = "1.22.19";
    public static final String GO = "go1.21.6";
    public static final String RUST = "1.75.0";
    public static final String CARGO = "cargo 1.75.0 (1d8b05cdd 2023-11-20)";
    public static final String RUSTC = "rustc 1.75.0 (82e1608df 2023-12-21)";
    public static final String JAVA = "17.0.9";
    public static final String MAVEN = "3.9.6";
    public static final String GRADLE = "8.5";
    public static final String PHP = "8.1.2-1ubuntu2.14";
    public static final String COMPOSER = "2.6.6";
    public static final String RUBY = "ruby 3.0.2p107 (2021-07-07 revision 0db68f0233) [x86_64-linux-gnu]";
    public static final String GEM = "3.3.5";
    public static final String PERL = "v5.34.0";
    public static final String LUA = "5.4.6";
    public static final String GCC = "11.4.0";
    public static final String MAKE = "4.3";
    public static final String CMAKE = "3.22.1";
    public static final String NGINX = "1.18.0";
    public static final String MYSQL = "8.0.35";
    public static final String OPENSSL = "3.0.2";
    public static final String OPENSSH = "8.9p1";
    public static final String REDIS = "6.0.16";
    public static final String POSTGRES = "14.10";
    public static final String SQLITE = "3.37.2";
    public static final String KUBECTL = "v1.28.4";
    public static final String APT = "2.4.11";
    public static final String BUSYBOX = "v1.35.0";
    public static final String DIG = "9.18.18-0ubuntu0.22.04.1-Ubuntu";

    /* ---------------- AI 提示词用的软件清单 ---------------- */

    /** 已安装软件清单：全栈开发者工具链，大模型对这些命令仿真成功输出 */
    public static final String INSTALLED = String.join(", ",
            "docker " + DOCKER + " (daemon running; one nginx:latest container named 'web', ID a1b2c3d4e5f6, up 3 weeks)",
            "docker-compose " + DOCKER_COMPOSE,
            "git " + GIT,
            "python3 " + PYTHON + " with pip",
            "node " + NODE + " with npm " + NPM + " and yarn " + YARN,
            "go " + GO,
            "rust " + RUST + " with cargo",
            "openjdk " + JAVA + " with maven " + MAVEN + " and gradle " + GRADLE,
            "php " + PHP + " with composer " + COMPOSER,
            "ruby 3.0.2 with gem", "perl 5.34", "lua 5.4",
            "gcc " + GCC + ", make " + MAKE + ", cmake " + CMAKE,
            "nginx " + NGINX,
            "mysql-server " + MYSQL + " (running)",
            "redis-server " + REDIS + " (service stopped)",
            "postgresql " + POSTGRES + " (service stopped)",
            "sqlite3 " + SQLITE,
            "kubectl " + KUBECTL + " (installed, but no reachable cluster: most subcommands fail with connection refused)",
            "openssh-server " + OPENSSH, "openssl " + OPENSSL, "snapd",
            "curl", "wget", "vim", "nano", "jq", "htop", "tmux", "screen",
            "strace", "ltrace", "gdb", "binutils",
            "crontab", "tar", "zip", "unzip", "gzip", "rsync", "netcat (nc)");

    /** 未安装软件清单：渗透测试与流量分析工具，大模型对它们如实回 command not found */
    public static final String NOT_INSTALLED = String.join(", ",
            "nmap", "masscan", "zmap", "hydra", "medusa", "john", "hashcat",
            "sqlmap", "nikto", "gobuster", "ffuf", "dirb", "wfuzz",
            "tcpdump", "tshark", "wireshark", "ettercap", "arpspoof",
            "metasploit", "msfconsole", "searchsploit", "netcat variants beyond nc",
            "flatpak", "helm", "terraform", "ansible");

    /**
     * 生成 systemPrompt 用的"Server facts"多行事实块。
     * 全部由上述常量拼接，与 CommandProcessor 本地命令输出天然同源一致。
     */
    public static String factsBlock() {
        return "Server facts (keep every output strictly consistent with them):\n"
                + "- OS " + OS_DESC + " (" + OS_CODENAME + "), kernel " + KERNEL + ", " + ARCH + "; up " + UPTIME + ".\n"
                + "- CPU " + CPU_COUNT + "x " + CPU_MODEL + ", " + MEM_TOTAL_H + " RAM, " + SWAP_TOTAL_H + " swap; "
                + DISK_ROOT_DEV + " " + DISK_ROOT_SIZE + " on /, " + DISK_DATA_DEV + " " + DISK_DATA_SIZE + " on /data.\n"
                + "- Network: eth0 " + ETH0_IP + "/24 (MAC " + ETH0_MAC + "), gateway " + GATEWAY + ", DNS " + DNS + "; "
                + "listening services: " + LISTEN_PORTS + "; every external hostname resolves to " + WAN_IP + ".\n"
                + "- Users: root(0), admin(1000), ubuntu(1001); sudo members: admin, ubuntu.\n"
                + "- Running processes: systemd, sshd, mysqld, nginx worker, cron.\n"
                + "- Installed (this is a full-stack developer's server, all common dev toolchains present): "
                + INSTALLED + ".\n"
                + "- NOT installed: " + NOT_INSTALLED + ".\n";
    }
}
