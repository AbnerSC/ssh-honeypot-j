package org.open.scdm.honeypot.shell;

import org.open.scdm.honeypot.fs.VNode;
import org.open.scdm.honeypot.log.AttackLogger;

import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

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
            case "cat", "more", "less" -> cat(st, args);
            case "head" -> headTail(st, args, false);
            case "tail" -> headTail(st, args, true);
            case "wc" -> wc(st, args);
            case "echo" -> echo(args);
            case "whoami" -> st.username;
            case "id" -> id(st);
            case "groups" -> "root".equals(st.username) ? "root" : st.username + " sudo";
            case "uname" -> uname(args);
            case "hostname", "hostnamectl" -> hostnameCmd(args);
            case "who", "w" -> w(st);
            case "last" -> "root     pts/0        203.0.113.44     Mon Aug 11 06:25   still logged in";
            case "uptime" -> uptime();
            case "ps" -> ps(args);
            case "top", "htop" -> top();
            case "history" -> history(st);
            case "env", "printenv", "set", "export" -> env(st);
            case "date" -> dateCmd(args);
            case "df" -> df(args);
            case "free" -> free(args);
            case "vmstat" -> vmstat();
            case "iostat" -> "Linux 5.15.0-91-generic (svr01) \t08/11/26 \t_x86_64_\t(4 CPU)\n\navg-cpu:  %user   %nice %system %iowait  %steal   %idle\n           1.26    0.01    0.68    0.19    0.00   97.85";
            case "clear" -> "\033[H\033[2J\033[3J";
            case "touch" -> touch(st, args);
            case "mkdir" -> mkdir(st, args);
            case "rm", "rmdir" -> rm(st, args);
            case "cp" -> cp(st, args);
            case "mv" -> mv(st, args);
            case "chmod" -> chmod(st, args);
            case "chown", "chgrp" -> chown(st, args);
            case "ln" -> ln(st, args);
            case "stat" -> stat(st, args);
            case "du" -> du(st, args);
            case "which", "whereis" -> which(args);
            case "type" -> typeCmd(args);
            case "bash", "sh", "zsh", "dash", "ksh" -> "";
            case "su" -> su(st, args);
            case "sudo" -> ""; // 已在入口处理，兼容 sudo -i / sudo su 等递归剥离后的重复命中
            case "passwd" -> "passwd: Authentication token manipulation error\npasswd: password unchanged";
            case "chpasswd" -> "";
            case "wget" -> download(st, args, false);
            case "curl" -> download(st, args, true);
            case "ifconfig" -> ifconfig();
            case "ip" -> ipCmd(args);
            case "netstat", "ss" -> netstat();
            case "ping", "ping6" -> ping(args);
            case "traceroute", "tracepath", "mtr" -> "traceroute to " + (args.isEmpty() ? "" : firstNonFlag(args)) + " (93.184.216.34), 30 hops max\n 1  10.0.0.1 (10.0.0.1)  0.412 ms  0.389 ms  0.371 ms\n 2  * * *";
            case "dig" -> dig(args);
            case "nslookup", "host" -> nslookup(args);
            case "arp" -> "Address                  HWtype  HWaddress           Flags Mask            Iface\n10.0.0.1                 ether   00:15:5d:00:1a:01   C                     eth0";
            case "route" -> "Kernel IP routing table\nDestination     Gateway         Genmask         Flags Metric Ref    Use Iface\ndefault         _gateway        0.0.0.0         UG    100    0        0 eth0\n10.0.0.0        0.0.0.0         255.255.255.0   U     100    0        0 eth0";
            case "kill", "killall", "pkill" -> kill(args);
            case "apt", "apt-get", "aptitude" -> apt(args);
            case "yum", "dnf" -> yum(args);
            case "dpkg", "rpm" -> dpkg(args);
            case "snap", "flatpak" -> "";
            case "systemctl" -> systemctl(st, args);
            case "service" -> service(args);
            case "journalctl" -> journalctl();
            case "crontab" -> crontab(args);
            case "tar" -> tar(st, args);
            case "gzip", "gunzip", "bzip2", "xz" -> "";
            case "unzip" -> unzip(st, args);
            case "zip" -> "";
            case "rsync" -> "";
            case "ssh" -> "ssh: connect to host " + (args.isEmpty() ? "" : args.getLast()) + " port 22: Connection timed out";
            case "scp", "sftp" -> name + ": connect to host " + (args.isEmpty() ? "" : args.getLast()) + " port 22: Connection timed out";
            case "ftp", "telnet" -> name + ": connect to address " + (args.isEmpty() ? "" : firstNonFlag(args)) + ": Connection timed out";
            case "nc", "ncat", "netcat", "socat" -> ""; // nc 反弹 shell：静默挂起，仅记录命令
            case "mount" -> mount();
            case "umount" -> "umount: " + (args.isEmpty() ? "" : args.getLast()) + ": not mounted.";
            case "lsblk" -> lsblk();
            case "fdisk", "parted" -> "Disk /dev/sda: 80 GiB, 85899345920 bytes, 167772160 sectors\nDisk model: Virtio Block Dev\nUnits: sectors of 1 * 512 = 512 bytes\n\nDevice     Boot Start       End   Sectors Size Id Type\n/dev/sda1  *     2048 167772159 167770112  80G 83 Linux";
            case "lsof" -> lsof();
            case "dmesg" -> "dmesg: read kernel buffer failed: Operation not permitted";
            case "reboot", "shutdown", "halt", "poweroff" -> {
                logger.command(st.sessionId, st.ip, st.username, "[危险操作] " + name);
                yield EXIT_SIGNAL; // 模拟系统重启导致连接断开
            }
            case "init" -> initCmd(st, args);
            case "busybox" -> "BusyBox v1.35.0 (Ubuntu 1:1.35.0-17ubuntu1) multi-call binary.";
            case "python", "python3" -> python(st, args);
            case "perl", "php", "ruby", "lua", "node" -> ""; // 交互解释器：静默挂起
            case "gcc", "cc", "make", "g++", "cmake" -> "";
            case "java" -> javaCmd(args);
            case "go", "cargo", "pip", "pip3", "npm", "yarn" -> "";
            case "nproc" -> "4";
            case "lscpu" -> lscpu();
            case "lsmem" -> "RANGE                                  SIZE  STATE REMOVABLE  BLOCK\n0x0000000000000000-0x000000007fffffff   2G online       yes 0-15\n\nMemory block size:       128M\nTotal online memory:       8G\nTotal offline memory:      0B";
            case "lspci" -> "00:00.0 Host bridge: Intel Corporation 440FX - 82441FX PMC [Natoma] (rev 02)\n00:01.0 ISA bridge: Intel Corporation 82371SB PIIX3 ISA [Natoma/Triton II]\n00:02.0 VGA compatible controller: Cirrus Logic GD 5446\n00:03.0 Ethernet controller: Microsoft Corporation Hyper-V virtual NIC";
            case "lsusb" -> "";
            case "lsmod" -> "Module                  Size  Used by\nipv6                  520192  24\nnf_conntrack_netlink    49152  0\nxfrm_algo              16384  1";
            case "modprobe" -> "";
            case "true" -> "";
            case "false" -> "";
            case "sleep" -> "";
            case "test", "[" -> "";
            case "tty" -> "/dev/pts/0";
            case "stty" -> "";
            case "reset" -> "\033c";
            case "grep", "egrep", "fgrep", "zgrep" -> grep(st, args);
            case "find" -> find(st, args);
            case "xargs" -> "";
            case "sort", "uniq", "cut", "tr", "tee", "paste", "nl", "column", "expand" -> "";
            case "awk", "sed" -> "";
            case "diff" -> "";
            case "base64" -> base64Cmd(st, args);
            case "md5sum", "sha1sum", "sha256sum", "sha512sum" -> sumCmd(st, name, args);
            case "openssl" -> openssl(args);
            case "vi", "vim", "nano", "emacs", "ed" -> ""; // 编辑器：直接挂起太复杂，静默返回
            case "adduser", "useradd" -> useradd(st, args);
            case "usermod" -> "";
            case "deluser", "userdel" -> "";
            case "getent" -> getent(args);
            case "finger" -> "";
            case "iptables" -> iptables(args);
            case "ufw" -> ufw(args);
            case "firewall-cmd" -> "success";
            case "locate" -> "";
            case "man" -> "No manual entry for " + (args.isEmpty() ? "" : args.getFirst());
            case "command", "hash" -> "";
            case "alias" -> aliasCmd(args);
            case "unalias" -> "";
            case "source", "." -> "";
            case "eval", "exec", "nohup", "disown", "bg", "fg", "jobs" -> "";
            case "screen", "tmux" -> "";
            case "docker" -> docker(args);
            case "docker-compose" -> "";
            case "kubectl" -> kubectl(args);
            case "mysql", "mariadb" -> "ERROR 1045 (28000): Access denied for user '" + (args.isEmpty() ? "root" : userOfDbArgs(args)) + "'@'localhost' (using password: YES)";
            case "psql" -> "psql: error: connection to server at \"localhost\" (127.0.0.1), port 5432 failed: Connection refused";
            case "redis-cli" -> "Could not connect to Redis at 127.0.0.1:6379: Connection refused";
            case "sqlite3" -> "";
            case "lsb_release" -> lsbRelease(args);
            case "cat /etc/os-release" -> "";
            case "neofetch" -> neofetch();
            case "fortune", "cowsay", "sl" -> "";
            case "dd" -> dd(st, args);
            case "mkfs", "mkswap" -> "";
            case "fsck" -> "/dev/sda1: clean, 131245/5242880 files, 1531422/20971264 blocks";
            case "swapon" -> "NAME      TYPE      SIZE USED PRIO\n/dev/sda2 partition   2G   0B -2";
            case "swapoff" -> "";
            case "sync" -> "";
            case "yes" -> "";
            case "seq" -> seqCmd(args);
            case "watch" -> "";
            case "timeout" -> "";
            case "parallel" -> "";
            case "at" -> "at: can't open /var/run/atd.pid";
            case "visudo", "pkexec", "chroot" -> "";
            case "strace", "ltrace" -> strace(args);
            case "gdb" -> "";
            case "objdump", "strings", "readelf" -> "";
            case "ldd" -> ldd(args);
            case "file" -> fileCmd(st, args);
            case "bc", "dc", "expr" -> "";
            case "realpath", "dirname", "basename", "readlink" -> pathCmd(st, name, args);
            case "cmp" -> "";
            case "mktemp" -> mktemp(st, args);
            case "od", "xxd", "hexdump" -> "";
            case "iconv", "dos2unix", "unix2dos" -> "";
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
               "cd ls cat head tail wc echo pwd whoami id uname hostname ps kill clear history exit\n" +
               "cp mv rm mkdir touch chmod chown ln stat du df free top netstat ping wget curl crontab\n" +
               "systemctl service journalctl docker kubectl mysql base64 md5sum tar unzip find grep";
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
            if (!sb.isEmpty() && sb.charAt(sb.length() - 1) == '\n') sb.setLength(sb.length() - 1);
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
        if (!sb.isEmpty() && sb.charAt(sb.length() - 1) == '\n') sb.setLength(sb.length() - 1);
        return sb.toString();
    }

    /** head/tail：支持 -n N，默认 10 行 */
    private String headTail(SessionState st, List<String> args, boolean isTail) {
        int n = 10;
        List<String> files = new ArrayList<>();
        for (int i = 0; i < args.size(); i++) {
            String a = args.get(i);
            if (a.startsWith("-")) {
                if ((a.equals("-n") || a.equals("--lines")) && i + 1 < args.size()) {
                    try { n = Math.max(0, Integer.parseInt(args.get(++i))); } catch (NumberFormatException ignore) {}
                } else {
                    String num = a.replaceAll("^-n?", "");
                    if (!num.isEmpty() && num.matches("\\d+")) n = Integer.parseInt(num);
                }
            } else files.add(a);
        }
        if (files.isEmpty()) return "";
        String cmd = isTail ? "tail" : "head";
        StringBuilder sb = new StringBuilder();
        for (String f : files) {
            VNode node = st.fs.resolve(st.cwd, f);
            if (node == null) {
                sb.append(cmd).append(": cannot open '").append(f)
                        .append("' for reading: No such file or directory\n");
                continue;
            }
            if (node.directory) {
                sb.append(cmd).append(": cannot open '").append(f)
                        .append("' for reading: Is a directory\n");
                continue;
            }
            String[] lines = node.content().split("\n", -1);
            List<String> pick = new ArrayList<>();
            for (int i = 0; i < lines.length; i++) {
                boolean keep = isTail ? i >= lines.length - n : i < n;
                if (keep && !lines[i].isEmpty()) pick.add(lines[i]);
            }
            sb.append(String.join("\n", pick));
            if (!pick.isEmpty()) sb.append('\n');
        }
        return sb.toString().stripTrailing();
    }

    private String wc(SessionState st, List<String> args) {
        List<String> files = args.stream().filter(a -> !a.startsWith("-")).toList();
        if (files.isEmpty()) return "0 0 0";
        StringBuilder sb = new StringBuilder();
        for (String f : files) {
            VNode node = st.fs.resolve(st.cwd, f);
            if (node == null || node.directory) {
                sb.append("wc: ").append(f).append(": No such file or directory\n");
                continue;
            }
            String c = node.content();
            int lines = c.isEmpty() ? 0 : c.split("\n", -1).length - (c.endsWith("\n") ? 1 : 0);
            int words = c.isBlank() ? 0 : c.trim().split("\\s+").length;
            int chars = c.length();
            sb.append(String.format("%7d %7d %7d %s%n", lines, words, chars, f));
        }
        return sb.toString().stripTrailing();
    }

    private String stat(SessionState st, List<String> args) {
        List<String> files = args.stream().filter(a -> !a.startsWith("-")).toList();
        if (files.isEmpty()) return "stat: missing operand";
        String f = files.getFirst();
        VNode node = st.fs.resolve(st.cwd, f);
        if (node == null) return "stat: cannot statx '" + f + "': No such file or directory";
        String abs = st.fs.normalize(st.cwd, f);
        return "  File: " + f + "\n" +
               "  Size: " + node.size() + "       \tBlocks: " + (node.size() / 512 + 8) + "    IO Block: 4096   " +
               (node.directory ? "directory" : "regular file") + "\n" +
               "Access: (" + (node.directory ? "0755/drwxr-xr-x" : "0644/-rw-r--r--") + ")  Uid: (" +
               ("root".equals(node.owner) ? "0" : "1000") + "/" + node.owner + ")   Gid: (" +
               ("root".equals(node.group) ? "0" : "1000") + "/" + node.group + ")\n" +
               "Access: " + node.mtime + "\nModify: " + node.mtime + "\nChange: " + node.mtime +
               "\n Birth: " + node.mtime + "  (path=" + abs + ")";
    }

    private String du(SessionState st, List<String> args) {
        String path = args.stream().filter(a -> !a.startsWith("-")).findFirst().orElse(".");
        VNode node = st.fs.resolve(st.cwd, path);
        if (node == null) return "du: cannot access '" + path + "': No such file or directory";
        boolean h = args.stream().anyMatch(a -> a.startsWith("-") && a.contains("h"));
        StringBuilder sb = new StringBuilder();
        duWalk(st.fs.normalize(st.cwd, path), node, h, sb);
        return sb.toString().stripTrailing();
    }

    private void duWalk(String path, VNode node, boolean human, StringBuilder sb) {
        long kb = node.directory ? 4 : Math.max(1, node.size() / 1024);
        if (node.directory) {
            for (VNode c : node.children().values()) {
                duWalk((path.equals("/") ? "" : path) + "/" + c.name, c, human, sb);
                kb += 4;
            }
        }
        sb.append(human ? humanSize(kb * 1024) : String.valueOf(kb)).append('\t')
                .append(path.isEmpty() ? "/" : path).append('\n');
    }

    private String humanSize(long bytes) {
        if (bytes < 1024) return bytes + "B";
        if (bytes < 1024 * 1024) return bytes / 1024 + "K";
        if (bytes < 1024L * 1024 * 1024) return bytes / 1024 / 1024 + "M";
        return bytes / 1024 / 1024 / 1024 + "G";
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

    private String df(List<String> args) {
        boolean h = args.stream().anyMatch(a -> a.startsWith("-") && a.contains("h"));
        if (h) {
            return """
                    Filesystem      Size  Used  Avail  Use%  Mounted on
                    /dev/sda1       79G   31G   44G    42%   /
                    tmpfs           3.9G  0     3.9G   0%    /dev/shm
                    /dev/sdb1       99G   18G   76G    19%   /data
                    """;
        }
        return """
                Filesystem      1K-blocks     Used       Available  Use%   Mounted on
                /dev/sda1       82559280      32471164   45875896   42%    /
                tmpfs           4080572       0          4080572    0%     /dev/shm
                /dev/sdb1       103080232     18495632   79342184   19%    /data
                """;
    }

    private String free(List<String> args) {
        boolean h = args.stream().anyMatch(a -> a.startsWith("-") && a.contains("h"));
        if (h) {
            return """
                               total        used        free      shared   buff/cache    available
                    Mem:       7.8Gi       2.7Gi       2.3Gi        12Mi        2.8Gi        5.1Gi
                    Swap:      2.0Gi          0B       2.0Gi
                    """;
        }
        return """
                            total        used        free      shared    buff/cache   available
                Mem:      8161148     2816532     2415688       12460       2928928     5341560
                Swap:     2097148           0     2097148
                """;
    }

    private String vmstat() {
        return "procs -----------memory---------- ---swap-- -----io---- -system-- ------cpu-----\n" +
               " r  b   swpd   free   buff  cache   si   so    bi    bo   in   cs us sy id wa st\n" +
               " 1  0      0 2415688 102400 2928928    0    0    12    45  187  412  1  1 98  0  0";
    }

    private String dateCmd(List<String> args) {
        if (!args.isEmpty() && args.getFirst().startsWith("+%")) {
            String fmt = args.getFirst().substring(1)
                    .replace("Y", "yyyy").replace("m", "MM").replace("d", "dd")
                    .replace("H", "HH").replace("M", "mm").replace("S", "ss")
                    .replace("s", "'" + System.currentTimeMillis() / 1000 + "'")
                    .replace("z", "'UTC'");
            try {
                return LocalDateTime.now().format(DateTimeFormatter.ofPattern(fmt, Locale.ENGLISH));
            } catch (Exception e) {
                return LocalDateTime.now().format(DateTimeFormatter.ofPattern("EEE MMM dd HH:mm:ss 'UTC' yyyy", Locale.ENGLISH));
            }
        }
        return LocalDateTime.now().format(DateTimeFormatter.ofPattern("EEE MMM dd HH:mm:ss 'UTC' yyyy", Locale.ENGLISH));
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
        boolean parents = args.stream().anyMatch(a -> a.startsWith("-") && a.contains("p"));
        for (String f : args) {
            if (f.startsWith("-")) continue;
            VNode existing = st.fs.resolve(st.cwd, f);
            if (existing != null) {
                if (parents && existing.directory) continue; // mkdir -p 对已存在目录静默成功
                return "mkdir: cannot create directory '" + f + "': File exists";
            }
            boolean ok = parents ? mkdirs(st, f) : st.fs.mkdir(st.cwd, f, st.username);
            if (!ok) {
                return "mkdir: cannot create directory '" + f + "': No such file or directory";
            }
        }
        return "";
    }

    /** mkdir -p：逐级创建缺失的中间目录 */
    private boolean mkdirs(SessionState st, String path) {
        String abs = st.fs.normalize(st.cwd, path);
        String[] parts = abs.substring(1).split("/");
        String cur = "";
        for (String part : parts) {
            cur += "/" + part;
            VNode node = st.fs.resolve("/", cur);
            if (node == null) {
                if (!st.fs.mkdir("/", cur, st.username)) return false;
            } else if (!node.directory) {
                return false;
            }
        }
        return true;
    }

    private String rm(SessionState st, List<String> args) {
        List<String> files = args.stream().filter(a -> !a.startsWith("-")).toList();
        boolean recursive = args.stream().anyMatch(a -> a.startsWith("-") && a.contains("r"));
        if (files.isEmpty()) return "rm: missing operand";
        for (String f : files) {
            if (f.equals("/") || f.equals("/*") || f.equals("~/*") || f.equals("*")) {
                logger.command(st.sessionId, st.ip, st.username, "[危险操作] rm " + String.join(" ", args));
                continue; // 假装成功，实际不动
            }
            VNode node = st.fs.resolve(st.cwd, f);
            if (node != null && node.directory && !recursive) {
                return "rm: cannot remove '" + f + "': Is a directory";
            }
            if (!st.fs.remove(st.cwd, f)) {
                return "rm: cannot remove '" + f + "': No such file or directory";
            }
        }
        return "";
    }

    private String cp(SessionState st, List<String> args) {
        List<String> operands = args.stream().filter(a -> !a.startsWith("-")).toList();
        if (operands.size() < 2) return "cp: missing destination file operand after '" + (operands.isEmpty() ? "" : operands.getFirst()) + "'";
        String src = operands.get(operands.size() - 2), dst = operands.getLast();
        VNode srcNode = st.fs.resolve(st.cwd, src);
        if (srcNode == null) return "cp: cannot stat '" + src + "': No such file or directory";
        if (srcNode.directory && args.stream().noneMatch(a -> a.startsWith("-") && (a.contains("r") || a.contains("R") || a.contains("a")))) {
            return "cp: -r not specified; omitting directory '" + src + "'";
        }
        if (!st.fs.copy(st.cwd, src, dst)) {
            return "cp: cannot copy '" + src + "' to '" + dst + "'";
        }
        return "";
    }

    private String mv(SessionState st, List<String> args) {
        List<String> operands = args.stream().filter(a -> !a.startsWith("-")).toList();
        if (operands.size() < 2) return "mv: missing destination file operand after '" + (operands.isEmpty() ? "" : operands.getFirst()) + "'";
        String src = operands.get(operands.size() - 2), dst = operands.getLast();
        if (st.fs.resolve(st.cwd, src) == null) {
            return "mv: cannot stat '" + src + "': No such file or directory";
        }
        if (!st.fs.move(st.cwd, src, dst)) {
            return "mv: cannot move '" + src + "' to '" + dst + "'";
        }
        return "";
    }

    private String chmod(SessionState st, List<String> args) {
        List<String> operands = args.stream().filter(a -> !a.startsWith("-")).toList();
        if (operands.size() < 2) return "chmod: missing operand";
        String mode = operands.getFirst();
        if (!mode.matches("[0-7]{3,4}") && !mode.matches("[ugoa]*[-+=][rwxXst]*")) {
            return "chmod: invalid mode: '" + mode + "'";
        }
        for (int i = 1; i < operands.size(); i++) {
            if (st.fs.resolve(st.cwd, operands.get(i)) == null) {
                return "chmod: cannot access '" + operands.get(i) + "': No such file or directory";
            }
        }
        return "";
    }

    private String chown(SessionState st, List<String> args) {
        List<String> operands = args.stream().filter(a -> !a.startsWith("-")).toList();
        if (operands.size() < 2) return "chown: missing operand";
        for (int i = 1; i < operands.size(); i++) {
            if (st.fs.resolve(st.cwd, operands.get(i)) == null) {
                return "chown: cannot access '" + operands.get(i) + "': No such file or directory";
            }
        }
        return "";
    }

    private String ln(SessionState st, List<String> args) {
        List<String> operands = args.stream().filter(a -> !a.startsWith("-")).toList();
        if (operands.size() < 2) return "ln: missing file operand";
        String src = operands.getFirst();
        if (st.fs.resolve(st.cwd, src) == null) {
            return "ln: failed to create symbolic link '" + operands.getLast() + "': No such file or directory";
        }
        return "";
    }

    private String kill(List<String> args) {
        String sig = args.stream().filter(a -> a.startsWith("-")).findFirst().orElse("-9");
        List<String> pids = args.stream().filter(a -> !a.startsWith("-")).toList();
        if (pids.isEmpty()) return "kill: usage: kill [-s sigspec | -n signum | -sigspec] pid | jobspec ...";
        for (String pid : pids) {
            if (!pid.matches("\\d+")) {
                return "kill: " + pid + ": arguments must be process or job IDs";
            }
        }
        // 蜜罐内无真实进程，假装成功；记录可疑 kill 行为
        return "";
    }

    private String grep(SessionState st, List<String> args) {
        List<String> operands = args.stream().filter(a -> !a.startsWith("-")).toList();
        if (operands.isEmpty()) return "Usage: grep [OPTION]... PATTERNS [FILE]...";
        String pattern = operands.getFirst();
        if (operands.size() < 2) return ""; // 从 stdin 读，蜜罐里没有
        boolean invert = args.contains("-v") || args.contains("--invert-match");
        boolean count = args.contains("-c") || args.contains("--count");
        StringBuilder sb = new StringBuilder();
        for (int i = 1; i < operands.size(); i++) {
            String f = operands.get(i);
            VNode node = st.fs.resolve(st.cwd, f);
            if (node == null) {
                sb.append("grep: ").append(f).append(": No such file or directory\n");
                continue;
            }
            if (node.directory) {
                sb.append("grep: ").append(f).append(": Is a directory\n");
                continue;
            }
            List<String> matched = new ArrayList<>();
            for (String line : node.content().split("\n", -1)) {
                boolean hit = line.contains(pattern);
                if (hit != invert && !line.isEmpty()) matched.add(line);
            }
            if (count) {
                sb.append(operands.size() > 2 ? f + ":" : "").append(matched.size()).append('\n');
            } else {
                for (String m : matched) sb.append(operands.size() > 2 ? f + ":" : "").append(m).append('\n');
            }
        }
        return sb.toString().stripTrailing();
    }

    private static final List<String> SBIN_CMDS = List.of(
            "ifconfig", "ip", "iptables", "reboot", "shutdown", "sshd", "fdisk", "mkfs", "service", "init", "useradd", "userdel");

    private String which(List<String> args) {
        List<String> names = args.stream().filter(a -> !a.startsWith("-")).toList();
        if (names.isEmpty()) return "";
        StringBuilder sb = new StringBuilder();
        for (String n : names) {
            sb.append(SBIN_CMDS.contains(n) ? "/usr/sbin/" : "/usr/bin/").append(n).append('\n');
        }
        return sb.toString().stripTrailing();
    }

    private String typeCmd(List<String> args) {
        if (args.isEmpty()) return "";
        String n = args.getFirst();
        return n + " is /usr/bin/" + n;
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
                        inet 10.23.76.15  netmask 255.255.255.0  broadcast 10.0.0.255
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
                        inet 10.23.76.15/24 brd 10.0.0.255 scope global eth0""";
        }
        if (sub.equals("route") || sub.equals("r")) {
            return "default via 10.0.0.1 dev eth0 proto static\n10.0.0.0/24 dev eth0 proto kernel scope link src 10.23.76.15";
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
                tcp        0    288 10.23.76.15:22          10.0.0.99:51220         ESTABLISHED
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

    /* ------------------------------------------------------------------ */
    /* 新增命令实现                                                            */
    /* ------------------------------------------------------------------ */

    private String hostnameCmd(List<String> args) {
        if (args.contains("-I") || args.contains("--all-ip-addresses")) return "10.23.76.15";
        if (args.contains("-i")) return "10.23.76.15";
        if (args.contains("-f")) return "svr01.internal";
        return "svr01";
    }

    /** 取第一个非选项参数 */
    private String firstNonFlag(List<String> args) {
        return args.stream().filter(a -> !a.startsWith("-")).findFirst().orElse("");
    }

    private String ping(List<String> args) {
        String host = firstNonFlag(args);
        if (host.isEmpty()) return "ping: usage error: Destination address required";
        return "PING " + host + " (93.184.216.34) 56(84) bytes of data.\n" +
               "\n--- " + host + " ping statistics ---\n" +
               "4 packets transmitted, 0 received, 100% packet loss, time 3055ms";
    }

    private String dig(List<String> args) {
        String host = firstNonFlag(args);
        if (host.isEmpty()) return "; <<>> DiG 9.18.18-0ubuntu0.22.04.1-Ubuntu <<>>\n;; global options: +cmd";
        return "; <<>> DiG 9.18.18-0ubuntu0.22.04.1-Ubuntu <<>> " + host + "\n" +
               ";; global options: +cmd\n" +
               ";; Got answer:\n" +
               ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: " + (10000 + RANDOM.nextInt(50000)) + "\n" +
               ";; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1\n\n" +
               ";; QUESTION SECTION:\n;" + host + ".\t\t\t\tIN\tA\n\n" +
               ";; ANSWER SECTION:\n" + host + ".\t\t54\tIN\tA\t93.184.216.34\n\n" +
               ";; Query time: " + (5 + RANDOM.nextInt(40)) + " msec\n;; SERVER: 10.0.0.2#53(10.0.0.2) (UDP)\n;; WHEN: " +
               LocalDateTime.now().format(DateTimeFormatter.ofPattern("EEE MMM dd HH:mm:ss 'UTC' yyyy", Locale.ENGLISH)) +
               "\n;; MSG SIZE  rcvd: 55";
    }

    private String nslookup(List<String> args) {
        String host = firstNonFlag(args);
        if (host.isEmpty()) return "> ";
        return "Server:\t\t10.0.0.2\nAddress:\t10.0.0.2#53\n\nNon-authoritative answer:\nName:\t" + host +
               "\nAddress: 93.184.216.34";
    }

    private String yum(List<String> args) {
        if (args.isEmpty()) return "Loaded plugins: fastestmirror\nYou need to give some command";
        return "Loaded plugins: fastestmirror\nLoading mirror speeds from cached hostfile\nNo packages marked for update";
    }

    private String dpkg(List<String> args) {
        if (!args.isEmpty() && args.getFirst().equals("-l")) {
            return "Desired=Unknown/Install/Remove/Purge/Hold\n| Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend\n" +
                   "||/ Name           Version          Architecture Description\n" +
                   "+++-==============-================-============-=================================\n" +
                   "ii  bash           5.1-6ubuntu1     amd64        GNU Bourne Again SHell\n" +
                   "ii  openssh-server 1:8.9p1-3ubuntu0 amd64        secure shell (SSH) server\n" +
                   "ii  mysql-server   8.0.35-0ubuntu0. amd64        MySQL database server (metapackage)";
        }
        return "dpkg: error: need an action option";
    }

    private String systemctl(SessionState st, List<String> args) {
        if (args.isEmpty() || args.getFirst().equals("status")) {
            String unit = args.size() > 1 ? args.getLast() : "";
            if (!unit.isEmpty()) {
                return "● " + unit + "\n     Loaded: loaded (/lib/systemd/system/" + unit + "; enabled; vendor preset: enabled)\n" +
                       "     Active: active (running) since Mon 2026-06-24 06:13:02 UTC; 1 months 17 days ago\n" +
                       "   Main PID: 519 (" + unit.replace(".service", "") + ")\n" +
                       "      Tasks: 12 (limit: 4662)\n     Memory: 45.2M\n        CPU: 1min 22.4s\n" +
                       "     CGroup: /system.slice/" + unit;
            }
            return "";
        }
        String sub = args.getFirst();
        if (sub.equals("list-units") || sub.equals("list")) {
            return "  UNIT                    LOAD   ACTIVE SUB     DESCRIPTION\n" +
                   "  ssh.service             loaded active running OpenBSD Secure Shell server\n" +
                   "  mysql.service           loaded active running MySQL Community Server\n" +
                   "  nginx.service           loaded active running A high performance web server\n" +
                   "  cron.service            loaded active running Regular background program processing daemon";
        }
        if (sub.equals("is-active")) return "active";
        if (sub.equals("is-enabled")) return "enabled";
        if (sub.equals("daemon-reload") || sub.equals("start") || sub.equals("stop") ||
            sub.equals("restart") || sub.equals("enable") || sub.equals("disable")) {
            if (sub.equals("stop") || sub.equals("disable")) {
                logger.command(st.sessionId, st.ip, st.username, "[危险操作] systemctl " + String.join(" ", args));
            }
            return "";
        }
        return "";
    }

    private String service(List<String> args) {
        if (args.size() >= 2 && args.getLast().equals("status")) {
            return " * " + args.getFirst() + " is running";
        }
        return "";
    }

    private String journalctl() {
        return "-- Journal begins at Mon 2026-06-24 06:13:02 UTC, ends at " +
               LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")) + " UTC. --\n" +
               "Aug 11 06:25:01 svr01 systemd[1]: Started Session 42 of user root.\n" +
               "Aug 11 06:25:03 svr01 sshd[21841]: Accepted password for root from 203.0.113.44 port 51220 ssh2";
    }

    private String tar(SessionState st, List<String> args) {
        boolean extract = args.stream().anyMatch(a -> a.startsWith("-") && a.contains("x"));
        boolean create = args.stream().anyMatch(a -> a.startsWith("-") && a.contains("c"));
        List<String> operands = args.stream().filter(a -> !a.startsWith("-")).toList();
        if (!extract && !create)
            return "tar: You must specify one of the `-Acdtrux', `--delete' or `--test-label' options";
        if (operands.isEmpty()) return "tar: Cowardly refusing to create an empty archive";
        String archive = operands.getFirst();
        if (extract) {
            // 假装解包成功：在 cwd 造一个同名目录（去掉扩展名）
            String dirName = archive.replaceFirst("\\.(tar(\\.(gz|bz2|xz))?|tgz|zip)$", "");
            if (!dirName.isEmpty() && st.fs.resolve(st.cwd, dirName) == null) {
                st.fs.mkdir(st.cwd, dirName, st.username);
            }
            return "";
        }
        // 打包：源文件必须存在（通配符除外）
        for (int i = 1; i < operands.size(); i++) {
            String src = operands.get(i);
            if (src.contains("*") || src.equals(".")) continue;
            if (st.fs.resolve(st.cwd, src) == null) {
                return "tar: " + src + ": Cannot stat: No such file or directory\ntar: Exiting with failure status due to previous errors";
            }
        }
        // 落地一个假归档文件
        st.fs.write(st.cwd, archive, st.username, "\u001f\u008b\u0008\u0000(fake archive)");
        return "";
    }

    private String unzip(SessionState st, List<String> args) {
        String file = firstNonFlag(args);
        if (file.isEmpty()) {
            return "UnZip 6.00 of 20 April 2009, by Debian. Original by Info-ZIP.\n\nUsage: unzip [-Z] [-opts[modifiers]] file[.zip] [list] [-x xlist] [-d exdir]";
        }
        if (st.fs.resolve(st.cwd, file) == null) {
            return "unzip:  cannot find or open " + file + ", " + file + ".zip or " + file + ".ZIP.";
        }
        return "Archive:  " + file + "\n   creating: app/\n  inflating: app/main\n  inflating: app/README.md";
    }

    private String mount() {
        return "/dev/sda1 on / type ext4 (rw,relatime,errors=remount-ro)\n" +
               "proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)\n" +
               "sysfs on /sys type sysfs (rw,nosuid,nodev,noexec,relatime)\n" +
               "tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev)\n" +
               "/dev/sdb1 on /data type ext4 (rw,relatime)";
    }

    private String lsblk() {
        return "NAME    MAJ:MIN RM SIZE RO TYPE MOUNTPOINT\n" +
               "sda       8:0    0  80G  0 disk\n" +
               "└─sda1    8:1    0  80G  0 part /\n" +
               "sdb       8:16   0 100G  0 disk\n" +
               "└─sdb1    8:17   0 100G  0 part /data";
    }

    private String lsof() {
        return "COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME\n" +
               "systemd     1 root  cwd    DIR    8,1     4096    2 /\n" +
               "sshd      412 root    3u  IPv4  21841      0t0  TCP *:22 (LISTEN)\n" +
               "mysqld    519 mysql  21u  IPv4  24132      0t0  TCP *:3306 (LISTEN)\n" +
               "nginx     803 www    6u  IPv4  22901      0t0  TCP *:80 (LISTEN)\n" +
               "bash    21850 root  cwd    DIR    8,1     4096  524289 /root";
    }

    private String initCmd(SessionState st, List<String> args) {
        if (!args.isEmpty() && args.getFirst().matches("[06]")) {
            logger.command(st.sessionId, st.ip, st.username, "[危险操作] init " + args.getFirst());
            return EXIT_SIGNAL;
        }
        return "";
    }

    private String python(SessionState st, List<String> args) {
        // python -c "code"：重点记录，常见反弹shell载荷
        int ci = args.indexOf("-c");
        if (ci >= 0 && ci + 1 < args.size()) {
            logger.command(st.sessionId, st.ip, st.username, "[可疑脚本] python -c " + args.get(ci + 1));
            return "";
        }
        if (!args.isEmpty() && !args.getFirst().startsWith("-") && args.getFirst().endsWith(".py")) {
            VNode f = st.fs.resolve(st.cwd, args.getFirst());
            if (f == null) {
                return "python3: can't open file '" + args.getFirst() + "': [Errno 2] No such file or directory";
            }
            logger.command(st.sessionId, st.ip, st.username, "[可疑脚本] python " + args.getFirst());
            return "";
        }
        if (args.contains("--version") || args.contains("-V")) return "Python 3.10.12";
        return ""; // 交互模式静默挂起
    }

    private String javaCmd(List<String> args) {
        if (args.contains("-version") || args.isEmpty()) {
            return "openjdk version \"17.0.9\" 2023-10-17\nOpenJDK Runtime Environment (build 17.0.9+9-Ubuntu-122.04)\nOpenJDK 64-Bit Server VM (build 17.0.9+9-Ubuntu-122.04, mixed mode, sharing)";
        }
        return "";
    }

    private String lscpu() {
        return "Architecture:            x86_64\n" +
               "  CPU op-mode(s):        32-bit, 64-bit\n" +
               "  Address sizes:         46 bits physical, 48 bits virtual\n" +
               "  Byte Order:            Little Endian\n" +
               "CPU(s):                  4\n" +
               "  On-line CPU(s) list:   0-3\n" +
               "Vendor ID:               GenuineIntel\n" +
               "  Model name:            Intel(R) Xeon(R) Platinum 8375C CPU @ 2.90GHz\n" +
               "    CPU family:          6\n" +
               "    Model:               106\n" +
               "    Thread(s) per core:  2\n" +
               "    Core(s) per socket:  2\n" +
               "    Socket(s):           1\n" +
               "    CPU max MHz:         2900.0000\n" +
               "Virtualization features:\n" +
               "  Hypervisor vendor:     Microsoft\n" +
               "  Virtualization type:   full";
    }

    private String base64Cmd(SessionState st, List<String> args) {
        boolean decode = args.contains("-d") || args.contains("--decode");
        List<String> files = args.stream().filter(a -> !a.startsWith("-")).toList();
        if (files.isEmpty()) return ""; // stdin
        VNode node = null;
        for (String f : files) {
            node = st.fs.resolve(st.cwd, f);
            if (node == null) return "base64: " + f + ": No such file or directory";
        }
        if (decode) {
            try {
                return new String(Base64.getMimeDecoder().decode(node.content().trim()), StandardCharsets.UTF_8);
            } catch (IllegalArgumentException e) {
                return "base64: invalid input";
            }
        }
        return Base64.getEncoder().encodeToString(node.content().getBytes(StandardCharsets.UTF_8));
    }

    private String sumCmd(SessionState st, String name, List<String> args) {
        List<String> files = args.stream().filter(a -> !a.startsWith("-")).toList();
        if (files.isEmpty()) return name + ": no files to hash";
        String hashPrefix = switch (name) {
            case "md5sum" -> "d41d8cd98f00b204e9800998ecf8427e";
            case "sha1sum" -> "da39a3ee5e6b4b0d3255bfef95601890afd80709";
            case "sha256sum" -> "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
            default -> "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
        };
        StringBuilder sb = new StringBuilder();
        for (String f : files) {
            if (st.fs.resolve(st.cwd, f) == null) {
                sb.append(name).append(": ").append(f).append(": No such file or directory\n");
            } else {
                sb.append(hashPrefix).append("  ").append(f).append('\n');
            }
        }
        return sb.toString().stripTrailing();
    }

    private String openssl(List<String> args) {
        if (!args.isEmpty() && args.getFirst().equals("version")) return "OpenSSL 3.0.2 15 Mar 2022 (Library: OpenSSL 3.0.2 15 Mar 2022)";
        if (args.contains("genrsa") || args.contains("req") || args.contains("x509")) {
            return "";
        }
        return "";
    }

    private String useradd(SessionState st, List<String> args) {
        String name = firstNonFlag(args);
        if (name.isEmpty()) return "useradd: missing operand";
        logger.command(st.sessionId, st.ip, st.username, "[后门账号] useradd " + String.join(" ", args));
        return "";
    }

    private String getent(List<String> args) {
        if (args.isEmpty()) return "";
        if (args.getFirst().equals("passwd")) {
            String user = args.size() > 1 ? args.get(1) : "root";
            return user + ":x:" + ("root".equals(user) ? "0:0:root:/root:/bin/bash" : "1000:1000:" + user + ":/home/" + user + ":/bin/bash");
        }
        if (args.getFirst().equals("hosts") && args.size() > 1) {
            return "93.184.216.34     " + args.get(1);
        }
        return "";
    }

    private String iptables(List<String> args) {
        if (args.contains("-L") || args.contains("--list")) {
            return "Chain INPUT (policy ACCEPT)\ntarget     prot opt source               destination\n\n" +
                   "Chain FORWARD (policy ACCEPT)\ntarget     prot opt source               destination\n\n" +
                   "Chain OUTPUT (policy ACCEPT)\ntarget     prot opt source               destination";
        }
        return "";
    }

    private String ufw(List<String> args) {
        if (!args.isEmpty() && args.getFirst().equals("status")) {
            return "Status: active\n\nTo                         Action      From\n--                         ------      ----\n22/tcp                     ALLOW       Anywhere\n80/tcp                     ALLOW       Anywhere\n22/tcp (v6)                ALLOW       Anywhere (v6)\n80/tcp (v6)                ALLOW       Anywhere (v6)";
        }
        return "";
    }

    private String aliasCmd(List<String> args) {
        if (args.isEmpty()) {
            return "alias ll='ls -alF'\nalias la='ls -A'\nalias l='ls -CF'";
        }
        return "";
    }

    private String docker(List<String> args) {
        if (args.isEmpty()) return "Usage:  docker [OPTIONS] COMMAND";
        String sub = args.getFirst();
        if (sub.equals("ps") || sub.equals("container")) {
            return "CONTAINER ID   IMAGE          COMMAND                  CREATED        STATUS        PORTS     NAMES\n" +
                   "a1b2c3d4e5f6   nginx:latest   \"/docker-entrypoint.…\"   3 weeks ago    Up 3 weeks    80/tcp    web";
        }
        if (sub.equals("images")) {
            return "REPOSITORY   TAG       IMAGE ID       CREATED        SIZE\nnginx        latest    61395b4c586d   3 weeks ago    187MB";
        }
        if (sub.equals("version")) {
            return "Client: Docker Engine - Community\n Version:           24.0.7\n API version:       1.43\n Go version:        go1.20.10";
        }
        return "";
    }

    private String kubectl(List<String> args) {
        if (args.isEmpty()) return "kubectl controls the Kubernetes cluster manager.";
        if (args.getFirst().equals("get") && args.contains("pods")) {
            return "NAME                     READY   STATUS    RESTARTS   AGE\nweb-6d9f5b7c8-x2k4p      1/1     Running   0          12d";
        }
        return "The connection to the server localhost:8080 was refused - did you specify the right host or port?";
    }

    private String userOfDbArgs(List<String> args) {
        for (int i = 0; i < args.size() - 1; i++) {
            if (args.get(i).equals("-u") || args.get(i).equals("--user")) return args.get(i + 1);
        }
        return "root";
    }

    private String lsbRelease(List<String> args) {
        if (args.contains("-a") || args.contains("--all")) {
            return "Distributor ID:\tUbuntu\nDescription:\tUbuntu 22.04.3 LTS\nRelease:\t22.04\nCodename:\tjammy";
        }
        return "";
    }

    private String neofetch() {
        return "            .-/+oossssoo+/-.               root@svr01\n" +
               "        `:+ssssssssssssssssss+:`           ------------\n" +
               "      -+ssssssssssssssssssyyssss+-         OS: Ubuntu 22.04.3 LTS x86_64\n" +
               "     /ssssssssssssssssssdMMMNysssso.       Kernel: 5.15.0-91-generic\n" +
               "    +sssssssssshdmmNNmmyNMMMMhssssss/      Uptime: 47 days, 3 hours\n" +
               "   .osssssshdmmNNMNNNMMMMNMMMMdssssssso    Shell: bash 5.1.16\n" +
               "  ossss+MMMNMMMNMMMMMMMMMMMMMMMN+sssssss   CPU: Intel Xeon Platinum 8375C (4) @ 2.90GHz\n" +
               "  ssss/MMMMMMMMMMMMMMMMMMMMMMMMMM+ssssss   Memory: 2816MiB / 7970MiB";
    }

    private String dd(SessionState st, List<String> args) {
        logger.command(st.sessionId, st.ip, st.username, "[危险操作] dd " + String.join(" ", args));
        return "4+0 records in\n4+0 records out\n2048 bytes (2.0 kB, 2.0 KiB) copied, 0.00052 s, 3.9 MB/s";
    }

    private String seqCmd(List<String> args) {
        List<String> nums = args.stream().filter(a -> !a.startsWith("-")).toList();
        if (nums.isEmpty()) return "";
        int end;
        int start = 1;
        try {
            end = Integer.parseInt(nums.getLast());
            if (nums.size() >= 2) start = Integer.parseInt(nums.getFirst());
        } catch (NumberFormatException e) {
            return "seq: invalid floating point argument";
        }
        if (end - start > 1000) return ""; // 防滥用
        StringBuilder sb = new StringBuilder();
        for (int i = start; i <= end; i++) sb.append(i).append('\n');
        return sb.toString().stripTrailing();
    }

    private String strace(List<String> args) {
        String target = firstNonFlag(args);
        if (target.isEmpty()) return "strace: Must have at least one command";
        return "execve(\"/usr/bin/" + target + "\", [\"" + target + "\"], 0x7ffd...) = 0\n" +
               "+++ exited with 0 +++";
    }

    private String ldd(List<String> args) {
        String target = firstNonFlag(args);
        if (target.isEmpty()) return "ldd: missing file arguments";
        return "\tlinux-vdso.so.1 (0x00007ffd5b3c2000)\n" +
               "\tlibc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f2c8a400000)\n" +
               "\t/lib64/ld-linux-x86-64.so.2 (0x00007f2c8a6a1000)";
    }

    private String fileCmd(SessionState st, List<String> args) {
        String target = firstNonFlag(args);
        if (target.isEmpty()) return "Usage: file [OPTION...] [FILE...]";
        VNode node = st.fs.resolve(st.cwd, target);
        if (node == null) return target + ": cannot open `" + target + "' (No such file or directory)";
        if (node.directory) return target + ": directory";
        if (node.content().startsWith("#!")) return target + ": POSIX shell script, ASCII text executable";
        if (node.name.endsWith(".sh")) return target + ": Bourne-Again shell script, ASCII text executable";
        return target + ": ASCII text";
    }

    private String pathCmd(SessionState st, String name, List<String> args) {
        String p = firstNonFlag(args);
        if (p.isEmpty()) return name + ": missing operand";
        int slash = p.lastIndexOf('/');
        return switch (name) {
            case "dirname" -> slash <= 0 ? (slash == 0 ? "/" : ".") : p.substring(0, slash);
            case "basename" -> slash >= 0 ? p.substring(slash + 1) : p;
            case "readlink" -> "";
            default -> st.fs.normalize(st.cwd, p); // realpath：返回规范化后的绝对路径
        };
    }

    private String mktemp(SessionState st, List<String> args) {
        String tmpl = args.isEmpty() ? "/tmp/tmp.XXXXXXXXXX" : args.getFirst();
        if (!tmpl.contains("/")) tmpl = "/tmp/" + tmpl;
        // 统计模板末尾的 X 个数（真实 mktemp 要求至少 3 个）
        int xCount = 0;
        for (int i = tmpl.length() - 1; i >= 0 && tmpl.charAt(i) == 'X'; i--) xCount++;
        if (xCount < 3) return "mktemp: too few X's in template '" + tmpl + "'";
        // 用随机字符替换末尾的 X
        String chars = "abcdefghijklmnopqrstuvwxyz0123456789";
        StringBuilder rand = new StringBuilder(xCount);
        for (int i = 0; i < xCount; i++) rand.append(chars.charAt(RANDOM.nextInt(chars.length())));
        String abs = st.fs.normalize(st.cwd, tmpl.substring(0, tmpl.length() - xCount) + rand);
        // 父目录存在才落地假文件
        int slash = abs.lastIndexOf('/');
        if (slash > 0 && st.fs.resolve("/", abs.substring(0, slash)) != null) {
            st.fs.touch("/", abs, st.username);
        }
        return abs;
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
                if (!cur.isEmpty()) {
                    tokens.add(cur.toString());
                    cur.setLength(0);
                }
            } else {
                cur.append(c);
            }
        }
        if (!cur.isEmpty()) tokens.add(cur.toString());
        return tokens;
    }
}
