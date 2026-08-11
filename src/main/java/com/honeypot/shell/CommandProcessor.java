package com.honeypot.shell;

import com.honeypot.fs.VNode;
import com.honeypot.log.AttackLogger;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Random;

/**
 * 伪 Shell 命令解释器。
 * 接收攻击者输入的一行命令，返回以假乱真的输出；所有危险行为仅记录不执行。
 */
public class CommandProcessor {
    private static final Random RANDOM = new Random();
    private final AttackLogger logger;

    /** exit/logout 时返回的标记 */
    public static final String EXIT_SIGNAL = "\u0000__EXIT__";

    public CommandProcessor(AttackLogger logger) {
        this.logger = logger;
    }

    /**
     * 执行一行输入（可能包含 ;、&&、| 等组合），返回输出文本。
     */
    public String execute(SessionState st, String line) {
        line = line.trim();
        if (line.isEmpty()) return "";
        st.history.add(line);
        logger.command(st.sessionId, st.ip, st.username, line);

        StringBuilder out = new StringBuilder();
        // 先按 ; 和 && 拆分成命令序列（蜜罐场景下足够）
        for (String segment : line.split(";|&&")) {
            segment = segment.trim();
            if (segment.isEmpty()) continue;
            // 管道：只执行第一个命令，忽略后续（多数 bot 命令用不到管道结果）
            String first = segment.split("\\|", 2)[0].trim();
            String result = runSingle(st, first);
            if (EXIT_SIGNAL.equals(result)) return EXIT_SIGNAL;
            if (!result.isEmpty()) {
                if (result.endsWith("\u0000NONL")) {
                    out.append(result, 0, result.length() - "\u0000NONL".length()); // echo -n：不补换行
                } else {
                    out.append(result);
                    if (!result.endsWith("\n")) out.append('\n');
                }
            }
        }
        return out.toString();
    }

    private String runSingle(SessionState st, String cmd) {
        // 处理重定向 > / >>
        String redirectFile = null;
        boolean append = false;
        if (cmd.contains(">>")) {
            String[] p = cmd.split(">>", 2);
            cmd = p[0].trim();
            redirectFile = p[1].trim();
            append = true;
        } else if (cmd.contains(">") && !cmd.contains("2>")) {
            String[] p = cmd.split(">", 2);
            cmd = p[0].trim();
            redirectFile = p[1].trim();
        }

        List<String> tokens = tokenize(cmd);
        if (tokens.isEmpty()) return "";
        String name = tokens.getFirst();
        List<String> args = tokens.subList(1, tokens.size());

        // sudo 前缀：剥掉继续执行
        if (name.equals("sudo")) {
            if (args.isEmpty()) return "usage: sudo command ...";
            logger.command(st.sessionId, st.ip, st.username, "[sudo] " + String.join(" ", args));
            return runSingle(st, String.join(" ", args));
        }

        String output = switch (name) {
            case "exit", "logout", "quit" -> EXIT_SIGNAL;
            case "help" -> help();
            case "pwd" -> st.cwd;
            case "cd" -> cd(st, args);
            case "ls", "dir", "ll" -> ls(st, args);
            case "cat", "more", "less", "head", "tail" -> cat(st, args);
            case "echo" -> echo(args);
            case "whoami" -> st.username;
            case "id" -> id(st);
            case "groups" -> "root".equals(st.username) ? "root" : st.username + " sudo";
            case "uname" -> uname(args);
            case "hostname", "hostnamectl" -> "svr01";
            case "who", "w" -> w(st);
            case "last" -> "root     pts/0        203.0.113.44     Mon Aug 11 06:25   still logged in";
            case "uptime" -> uptime();
            case "ps" -> ps(args);
            case "top", "htop" -> top();
            case "history" -> history(st);
            case "env", "printenv", "set", "export" -> env(st);
            case "date" -> LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
            case "df" -> df();
            case "free" -> free();
            case "clear" -> "\033[H\033[2J\033[3J";
            case "touch" -> touch(st, args);
            case "mkdir" -> mkdir(st, args);
            case "rm", "rmdir" -> rm(st, args);
            case "cp", "mv" -> "";
            case "chmod", "chown", "chgrp" -> "";
            case "ln" -> "";
            case "which" -> which(args);
            case "bash", "sh", "zsh", "dash" -> "";
            case "su" -> su(st, args);
            case "passwd" -> "passwd: Authentication token manipulation error\npasswd: password unchanged";
            case "wget" -> download(st, args, false);
            case "curl" -> download(st, args, true);
            case "ifconfig" -> ifconfig();
            case "ip" -> ipCmd(args);
            case "netstat", "ss" -> netstat();
            case "ping" -> "PING " + (args.isEmpty() ? "" : args.getFirst()) + " ... \n--- 3 packets transmitted, 0 received, 100% packet loss ---";
            case "kill", "killall", "pkill" -> "";
            case "apt", "apt-get", "yum", "dnf" -> apt(args);
            case "systemctl", "service" -> "";
            case "crontab" -> crontab(args);
            case "tar", "gzip", "gunzip", "unzip", "zip" -> "";
            case "scp", "sftp", "ftp", "ssh", "telnet", "nc", "ncat" ->
                    name + ": connect to host " + (args.isEmpty() ? "" : args.getLast()) + " port 22: Connection timed out";
            case "mount" -> "/dev/sda1 on / type ext4 (rw,relatime,errors=remount-ro)";
            case "umount" -> "umount: " + (args.isEmpty() ? "" : args.getLast()) + ": not mounted.";
            case "dmesg" -> "dmesg: read kernel buffer failed: Operation not permitted";
            case "reboot", "shutdown", "halt", "poweroff", "init" -> {
                logger.command(st.sessionId, st.ip, st.username, "[危险操作] " + name);
                yield EXIT_SIGNAL; // 模拟系统重启导致连接断开
            }
            case "busybox" -> "BusyBox v1.35.0 (Ubuntu 1:1.35.0-17ubuntu1) multi-call binary.";
            case "python", "python3", "perl", "php", "ruby" -> "";
            case "gcc", "cc", "make" -> "";
            case "nproc" -> "4";
            case "lscpu" -> "Architecture: x86_64\nCPU(s): 4\nModel name: Intel(R) Xeon(R) Platinum 8375C CPU @ 2.90GHz";
            case "lsblk" -> "sda      8:0    0   80G  0 disk\n└─sda1   8:1    0   80G  0 part /";
            case "true" -> "";
            case "false" -> "";
            case "sleep" -> "";
            case "tty" -> "/dev/pts/0";
            case "stty" -> "";
            case "reset" -> "\033c";
            case "grep", "egrep", "fgrep" -> "";
            case "find" -> find(st, args);
            case "awk", "sed" -> "";
            case "vi", "vim", "nano", "emacs" -> ""; // 编辑器：直接挂起太复杂，静默返回
            case "adduser", "useradd", "usermod" -> "";
            case "deluser", "userdel" -> "";
            case "iptables", "ufw" -> "";
            case "getent" -> "";
            case "locate" -> "";
            case "man" -> "No manual entry for " + (args.isEmpty() ? "" : args.getFirst());
            case "type", "command", "hash" -> "";
            case "alias", "unalias" -> "";
            case "source", "." -> "";
            default -> defaultCmd(name);
        };

        if (EXIT_SIGNAL.equals(output)) return EXIT_SIGNAL;

        // 处理输出重定向：写入虚拟文件系统
        if (redirectFile != null && !redirectFile.isEmpty()) {
            writeRedirect(st, redirectFile, output, append);
            return "";
        }
        return output;
    }

    /* ------------------------------------------------------------------ */
    /* 命令实现                                                            */
    /* ------------------------------------------------------------------ */

    private String help() {
        return "GNU bash, version 5.1.16(1)-release (x86_64-pc-linux-gnu)\n" +
               "These shell commands are defined internally.  Type `help' to see this list.\n" +
               "cd ls cat echo pwd whoami id uname hostname ps kill clear history exit";
    }

    private String cd(SessionState st, List<String> args) {
        String target = args.isEmpty() ? ("root".equals(st.username) ? "/root" : "/home/" + st.username) : args.getFirst();
        if (target.equals("~")) target = "root".equals(st.username) ? "/root" : "/home/" + st.username;
        VNode node = st.fs.resolve(st.cwd, target);
        if (node == null) return "-bash: cd: " + args.getFirst() + ": No such file or directory";
        if (!node.directory) return "-bash: cd: " + args.getFirst() + ": Not a directory";
        st.cwd = st.fs.normalize(st.cwd, target);
        return "";
    }

    private String ls(SessionState st, List<String> args) {
        boolean longFmt = args.stream().anyMatch(a -> a.startsWith("-") && a.contains("l"));
        boolean showAll = args.stream().anyMatch(a -> a.startsWith("-") && a.contains("a"));
        String path = args.stream().filter(a -> !a.startsWith("-")).findFirst().orElse(st.cwd);
        VNode node = st.fs.resolve(st.cwd, path);
        if (node == null) return "ls: cannot access '" + path + "': No such file or directory";

        if (!node.directory) {
            return longFmt ? node.toLsLong() : node.name;
        }
        StringBuilder sb = new StringBuilder();
        if (longFmt) {
            sb.append("total ").append(node.children().size() * 4).append('\n');
            if (showAll) {
                sb.append("drwxr-xr-x  2 root     root     4096 Aug 11 06:25 .\n");
                sb.append("drwxr-xr-x 20 root     root     4096 Aug  4 10:12 ..\n");
            }
            node.children().values().forEach(c -> {
                if (showAll || !c.name.startsWith(".")) sb.append(c.toLsLong()).append('\n');
            });
            if (sb.length() > 0 && sb.charAt(sb.length() - 1) == '\n') sb.setLength(sb.length() - 1);
        } else {
            List<String> names = new ArrayList<>();
            node.children().values().forEach(c -> {
                if (showAll || !c.name.startsWith(".")) names.add(c.name);
            });
            sb.append(String.join("  ", names));
        }
        return sb.toString();
    }

    private String cat(SessionState st, List<String> args) {
        List<String> files = args.stream().filter(a -> !a.startsWith("-")).toList();
        if (files.isEmpty()) return "";
        StringBuilder sb = new StringBuilder();
        for (String f : files) {
            VNode node = st.fs.resolve(st.cwd, f);
            if (node == null) {
                sb.append("cat: ").append(f).append(": No such file or directory\n");
            } else if (node.directory) {
                sb.append("cat: ").append(f).append(": Is a directory\n");
            } else {
                sb.append(node.content());
                if (!node.content().endsWith("\n")) sb.append('\n');
            }
        }
        if (sb.length() > 0 && sb.charAt(sb.length() - 1) == '\n') sb.setLength(sb.length() - 1);
        return sb.toString();
    }

    private String echo(List<String> args) {
        boolean newline = true;
        List<String> parts = new ArrayList<>(args);
        if (!parts.isEmpty() && parts.getFirst().equals("-n")) {
            newline = false;
            parts.removeFirst();
        }
        String s = String.join(" ", parts).replace("\\n", "\n").replace("\\t", "\t");
        return newline ? s : s + "\u0000NONL";
    }

    private String id(SessionState st) {
        if ("root".equals(st.username)) return "uid=0(root) gid=0(root) groups=0(root)";
        return "uid=1000(" + st.username + ") gid=1000(" + st.username + ") groups=1000(" + st.username + "),27(sudo)";
    }

    private String uname(List<String> args) {
        String flag = args.isEmpty() ? "" : args.getFirst();
        return switch (flag) {
            case "-a" -> "Linux svr01 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux";
            case "-r" -> "5.15.0-91-generic";
            case "-m" -> "x86_64";
            case "-n" -> "svr01";
            case "-s" -> "Linux";
            case "-v" -> "#101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023";
            case "-o" -> "GNU/Linux";
            default -> "Linux";
        };
    }

    private String w(SessionState st) {
        return " " + LocalDateTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss")) +
               " up 47 days,  3:12,  1 user,  load average: 0.08, 0.03, 0.01\n" +
               "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n" +
               st.username + "   pts/0    " + st.ip + "     " +
               LocalDateTime.now().format(DateTimeFormatter.ofPattern("HH:mm")) +
               "    0.00s  0.02s  0.00s w";
    }

    private String uptime() {
        double load = RANDOM.nextDouble(0.01, 0.3);
        return " " + LocalDateTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss")) +
               " up 47 days,  3:12,  1 user,  load average: " +
               String.format("%.2f, %.2f, %.2f", load, load * 0.8, load * 0.6);
    }

    private String ps(List<String> args) {
        boolean aux = args.stream().anyMatch(a -> a.contains("a") || a.contains("x") || a.contains("e"));
        String header = aux
                ? "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND"
                : "    PID TTY          TIME CMD";
        String base = aux ? """
                root           1  0.0  0.2 167892 11824 ?        Ss   Jun24   2:14 /sbin/init
                root         412  0.0  0.1  72300  6236 ?        Ss   Jun24   0:32 /usr/sbin/sshd -D
                root         519  0.0  0.4 388920 21432 ?        Ssl  Jun24   5:47 /usr/bin/mysqld
                www-data     803  0.0  0.3 245112 16028 ?        S    Jun24   1:02 nginx: worker process
                root        1102  0.0  0.1  21788  6512 ?        Ss   Jun24   0:18 /usr/sbin/cron -f
                root       21841  0.0  0.1  13524  7944 ?        Ss   06:25   0:00 sshd: root@pts/0
                root       21850  0.0  0.0   9056  4628 pts/0    Ss   06:25   0:00 -bash
                """ : """
                21850 pts/0    00:00:00 bash
                21901 pts/0    00:00:00 ps
                """;
        return header + "\n" + base.stripTrailing();
    }

    private String top() {
        return "top - " + LocalDateTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss")) +
               " up 47 days,  3:12,  1 user,  load average: 0.08, 0.03, 0.01\n" +
               "Tasks:  97 total,   1 running,  96 sleeping,   0 stopped,   0 zombie\n" +
               "%Cpu(s):  1.3 us,  0.7 sy,  0.0 ni, 97.8 id,  0.2 wa,  0.0 hi,  0.0 si,  0.0 st";
    }

    private String history(SessionState st) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < st.history.size(); i++) {
            sb.append(String.format("%5d  %s%n", i + 1, st.history.get(i)));
        }
        return sb.toString().stripTrailing();
    }

    private String env(SessionState st) {
        return "SHELL=/bin/bash\nUSER=" + st.username + "\nHOME=" +
               ("root".equals(st.username) ? "/root" : "/home/" + st.username) +
               "\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n" +
               "HOSTNAME=svr01\nTERM=xterm\nLANG=en_US.UTF-8\nPWD=" + st.cwd;
    }

    private String df() {
        return """
                Filesystem      1K-blocks     Used Available Use% Mounted on
                /dev/sda1        82559280 32471164  45875896  42% /
                tmpfs             4080572        0   4080572   0% /dev/shm
                /dev/sdb1       103080232 18495632  79342184  19% /data""";
    }

    private String free() {
        return """
                          total        used        free      shared  buff/cache   available
                Mem:        8161148     2816532     2415688       12460     2928928     5341560
                Swap:       2097148           0     2097148""";
    }

    private String touch(SessionState st, List<String> args) {
        for (String f : args) {
            if (f.startsWith("-")) continue;
            if (!st.fs.touch(st.cwd, f, st.username)) {
                return "touch: cannot touch '" + f + "': No such file or directory";
            }
        }
        return "";
    }

    private String mkdir(SessionState st, List<String> args) {
        for (String f : args) {
            if (f.startsWith("-")) continue;
            VNode existing = st.fs.resolve(st.cwd, f);
            if (existing != null) return "mkdir: cannot create directory '" + f + "': File exists";
            if (!st.fs.mkdir(st.cwd, f, st.username)) {
                return "mkdir: cannot create directory '" + f + "': No such file or directory";
            }
        }
        return "";
    }

    private String rm(SessionState st, List<String> args) {
        List<String> files = args.stream().filter(a -> !a.startsWith("-")).toList();
        if (files.isEmpty()) return "rm: missing operand";
        for (String f : files) {
            if (f.equals("/") || f.equals("/*") || f.equals("*")) {
                logger.command(st.sessionId, st.ip, st.username, "[危险操作] rm " + String.join(" ", args));
                continue; // 假装成功，实际不动
            }
            if (!st.fs.remove(st.cwd, f)) {
                return "rm: cannot remove '" + f + "': No such file or directory";
            }
        }
        return "";
    }

    private String which(List<String> args) {
        if (args.isEmpty()) return "";
        return "/usr/bin/" + args.getFirst();
    }

    private String su(SessionState st, List<String> args) {
        String target = args.isEmpty() ? "root" : args.getFirst();
        logger.command(st.sessionId, st.ip, st.username, "[提权尝试] su " + target);
        if ("root".equals(target) && !"root".equals(st.username)) {
            st.username = "root"; // 蜜罐直接放行，记录即可
            st.cwd = "/root";
            return "";
        }
        return "";
    }

    /** wget/curl：典型恶意软件下载行为，重点记录 URL */
    private String download(SessionState st, List<String> args, boolean isCurl) {
        String url = args.stream().filter(a -> a.startsWith("http") || a.contains("."))
                .findFirst().orElse(args.isEmpty() ? "" : args.getLast());
        if (!url.isEmpty()) logger.download(st.sessionId, st.ip, st.username, url);
        if (url.isEmpty()) return isCurl ? "curl: no URL specified!" : "wget: missing URL";

        String filename = url.contains("/") ? url.substring(url.lastIndexOf('/') + 1) : "index.html";
        if (filename.isEmpty()) filename = "index.html";
        // 在虚拟文件系统里"落地"一个假文件，让攻击者看到下载成功
        st.fs.touch(st.cwd, filename, st.username);
        VNode f = st.fs.resolve(st.cwd, filename);
        if (f != null) f.content("#!/bin/bash\n# binary payload placeholder\n");

        if (isCurl) {
            return "  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current\n" +
                   "                                 Dload  Upload   Total   Spent    Left  Speed\n" +
                   "100  843k  100  843k    0     0  1287k      0 --:--:-- --:--:-- --:--:-- 1289k";
        }
        return "--" + LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")) +
               "--  " + url + "\n" +
               "Resolving " + hostOf(url) + " (" + hostOf(url) + ")... 93.184.216.34\n" +
               "Connecting to " + hostOf(url) + " (" + hostOf(url) + ")|93.184.216.34|:80... connected.\n" +
               "HTTP request sent, awaiting response... 200 OK\n" +
               "Length: 864512 (844K) [application/octet-stream]\n" +
               "Saving to: '" + filename + "'\n\n" +
               filename + "          100%[===================>] 844.25K  1.29MB/s    in 0.6s\n\n" +
               LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")) +
               " (1.29 MB/s) - '" + filename + "' saved [864512/864512]";
    }

    private String hostOf(String url) {
        String h = url.replaceFirst("^https?://", "");
        int slash = h.indexOf('/');
        return slash > 0 ? h.substring(0, slash) : h;
    }

    private String ifconfig() {
        return """
                eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
                        inet 10.0.0.15  netmask 255.255.255.0  broadcast 10.0.0.255
                        inet6 fe80::215:5dff:fe00:1a2b  prefixlen 64  scopeid 0x20<link>
                        ether 00:15:5d:00:1a:2b  txqueuelen 1000  (Ethernet)
                        RX packets 18492653  bytes 21412405712 (21.4 GB)
                        RX errors 0  dropped 0  overruns 0  frame 0
                        TX packets 15248931  bytes 8982341231 (8.9 GB)
                        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

                lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
                        inet 127.0.0.1  netmask 255.0.0.0
                        loop  txqueuelen 1000  (Local Loopback)""";
    }

    private String ipCmd(List<String> args) {
        if (args.isEmpty()) return "Usage: ip [ OPTIONS ] OBJECT { COMMAND | help }";
        String sub = args.getFirst();
        if (sub.equals("addr") || sub.equals("a")) {
            return """
                    1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
                        inet 127.0.0.1/8 scope host lo
                    2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
                        inet 10.0.0.15/24 brd 10.0.0.255 scope global eth0""";
        }
        if (sub.equals("route") || sub.equals("r")) {
            return "default via 10.0.0.1 dev eth0 proto static\n10.0.0.0/24 dev eth0 proto kernel scope link src 10.0.0.15";
        }
        return "";
    }

    private String netstat() {
        return """
                Active Internet connections (servers and established)
                Proto Recv-Q Send-Q Local Address           Foreign Address         State
                tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN
                tcp        0      0 0.0.0.0:3306            0.0.0.0:*               LISTEN
                tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN
                tcp        0    288 10.0.0.15:22            10.0.0.99:51220         ESTABLISHED
                udp        0      0 0.0.0.0:68              0.0.0.0:*""";
    }

    private String apt(List<String> args) {
        if (args.isEmpty()) return "apt 2.4.11 (amd64)";
        if (args.getFirst().equals("update")) {
            return "Hit:1 http://archive.ubuntu.com/ubuntu jammy InRelease\n" +
                   "Get:2 http://archive.ubuntu.com/ubuntu jammy-updates InRelease [119 kB]\n" +
                   "Get:3 http://security.ubuntu.com/ubuntu jammy-security InRelease [110 kB]\n" +
                   "Fetched 229 kB in 1s (205 kB/s)\nReading package lists... Done";
        }
        return "Reading package lists... Done\nBuilding dependency tree... Done\n0 upgraded, 0 newly installed, 0 to remove and 3 not upgraded.";
    }

    private String crontab(List<String> args) {
        if (args.isEmpty()) return "usage error: file name must be specified for replace";
        if (args.getFirst().equals("-l")) {
            return "17 *\t* * *\troot    cd / && run-parts --report /etc/cron.hourly\n" +
                   "25 6\t* * *\troot\ttest -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )";
        }
        return "";
    }

    private String find(SessionState st, List<String> args) {
        String base = args.isEmpty() ? st.cwd : (args.getFirst().startsWith("-") ? st.cwd : args.getFirst());
        VNode node = st.fs.resolve(st.cwd, base);
        if (node == null) return "find: '" + base + "': No such file or directory";
        StringBuilder sb = new StringBuilder();
        collectPaths(st.fs.normalize(st.cwd, base), node, sb, 0);
        return sb.toString();
    }

    private void collectPaths(String path, VNode node, StringBuilder sb, int depth) {
        sb.append(path.isEmpty() ? "/" : path).append('\n');
        if (node.directory && depth < 2) {
            node.children().values().forEach(c ->
                    collectPaths((path.isEmpty() ? "" : path) + "/" + c.name, c, sb, depth + 1));
        }
    }

    private void writeRedirect(SessionState st, String file, String content, boolean append) {
        VNode existing = st.fs.resolve(st.cwd, file);
        if (existing != null && !existing.directory) {
            existing.content(append ? existing.content() + content + "\n" : content + "\n");
        } else if (existing == null) {
            if (st.fs.touch(st.cwd, file, st.username)) {
                VNode f = st.fs.resolve(st.cwd, file);
                if (f != null) f.content(content + "\n");
            }
        }
    }

    private String defaultCmd(String name) {
        return "-bash: " + name + ": command not found";
    }

    /** 简单分词：支持单双引号 */
    private List<String> tokenize(String cmd) {
        List<String> tokens = new ArrayList<>();
        StringBuilder cur = new StringBuilder();
        char quote = 0;
        for (int i = 0; i < cmd.length(); i++) {
            char c = cmd.charAt(i);
            if (quote != 0) {
                if (c == quote) quote = 0;
                else cur.append(c);
            } else if (c == '\'' || c == '"') {
                quote = c;
            } else if (Character.isWhitespace(c)) {
                if (cur.length() > 0) {
                    tokens.add(cur.toString());
                    cur.setLength(0);
                }
            } else {
                cur.append(c);
            }
        }
        if (cur.length() > 0) tokens.add(cur.toString());
        return tokens;
    }
}
