package com.honeypot.fs;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;

/**
 * 内存虚拟文件系统，伪装成一台常见的 Linux 服务器。
 * 支持路径解析（绝对/相对/./..）与 ls、cat、cd、touch、mkdir、rm 等操作。
 */
public class VirtualFileSystem {
    private final VNode root;

    public VirtualFileSystem() {
        this.root = buildFs();
    }

    public VNode root() {
        return root;
    }

    /* ------------------------------------------------------------------ */
    /* 路径解析                                                            */
    /* ------------------------------------------------------------------ */

    /**
     * 将 path 解析为节点。
     *
     * @param cwd 当前工作目录（绝对路径，如 "/root"）
     * @return 目标节点；不存在返回 null
     */
    public VNode resolve(String cwd, String path) {
        if (path == null || path.isEmpty() || path.equals(".")) {
            return resolve(cwd, cwd);
        }
        String combined = path.startsWith("/") ? path : cwd + "/" + path;
        String[] parts = combined.split("/");
        Deque<String> stack = new ArrayDeque<>();
        for (String p : parts) {
            if (p.isEmpty() || p.equals(".")) continue;
            if (p.equals("..")) {
                if (!stack.isEmpty()) stack.pollLast();
            } else {
                stack.offerLast(p);
            }
        }
        VNode node = root;
        for (String name : stack) {
            if (node == null || !node.directory) return null;
            node = node.child(name);
        }
        return node;
    }

    /** 规范化路径，返回以 / 开头的绝对路径 */
    public String normalize(String cwd, String path) {
        String combined = (path == null || path.isEmpty()) ? cwd : (path.startsWith("/") ? path : cwd + "/" + path);
        Deque<String> stack = new ArrayDeque<>();
        for (String p : combined.split("/")) {
            if (p.isEmpty() || p.equals(".")) continue;
            if (p.equals("..")) {
                if (!stack.isEmpty()) stack.pollLast();
            } else {
                stack.offerLast(p);
            }
        }
        if (stack.isEmpty()) return "/";
        return "/" + String.join("/", stack);
    }

    /* ------------------------------------------------------------------ */
    /* 文件操作（全部只影响内存中的树）                                       */
    /* ------------------------------------------------------------------ */

    public boolean touch(String cwd, String path, String user) {
        String abs = normalize(cwd, path);
        int idx = abs.lastIndexOf('/');
        VNode parent = resolve("/", idx == 0 ? "/" : abs.substring(0, idx));
        if (parent == null || !parent.directory) return false;
        String name = abs.substring(idx + 1);
        if (name.isEmpty() || parent.child(name) != null) return false;
        parent.add(VNode.file(name, "rw-r--r--", user, ""));
        return true;
    }

    public boolean mkdir(String cwd, String path, String user) {
        String abs = normalize(cwd, path);
        int idx = abs.lastIndexOf('/');
        VNode parent = resolve("/", idx == 0 ? "/" : abs.substring(0, idx));
        if (parent == null || !parent.directory) return false;
        String name = abs.substring(idx + 1);
        if (name.isEmpty() || parent.child(name) != null) return false;
        parent.add(VNode.dir(name, "rwxr-xr-x", user));
        return true;
    }

    public boolean remove(String cwd, String path) {
        String abs = normalize(cwd, path);
        if (abs.equals("/")) return false;
        int idx = abs.lastIndexOf('/');
        VNode parent = resolve("/", idx == 0 ? "/" : abs.substring(0, idx));
        if (parent == null || !parent.directory) return false;
        return parent.children().remove(abs.substring(idx + 1)) != null;
    }

    /* ------------------------------------------------------------------ */
    /* 构造伪装的 Linux 文件系统                                             */
    /* ------------------------------------------------------------------ */

    private VNode buildFs() {
        VNode root = VNode.dir("", "rwxr-xr-x", "root");

        // /bin
        VNode bin = VNode.dir("bin", "rwxr-xr-x", "root");
        for (String c : List.of("bash", "sh", "ls", "cat", "echo", "ps", "kill", "cp", "mv", "rm",
                "chmod", "chown", "tar", "gzip", "curl", "wget", "su", "sudo", "mount", "df", "dmesg",
                "uname", "whoami", "id", "date", "hostname", "ping", "netstat", "ss", "grep", "find",
                "awk", "sed", "vi", "nano", "touch", "mkdir", "pwd", "login", "env", "top")) {
            bin.add(VNode.exec(c, "root"));
        }

        // /sbin
        VNode sbin = VNode.dir("sbin", "rwxr-xr-x", "root");
        for (String c : List.of("ifconfig", "ip", "iptables", "reboot", "shutdown", "sshd", "fdisk", "mkfs", "service", "init")) {
            sbin.add(VNode.exec(c, "root"));
        }

        // /etc —— 诱饵文件，内容是精心伪造的
        VNode etc = VNode.dir("etc", "rwxr-xr-x", "root");
        etc.add(VNode.file("passwd", "rw-r--r--", "root",
                "root:x:0:0:root:/root:/bin/bash\n" +
                "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n" +
                "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n" +
                "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n" +
                "sync:x:4:65534:sync:/bin:/bin/sync\n" +
                "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n" +
                "mysql:x:109:117:MySQL Server,,,:/nonexistent:/bin/false\n" +
                "sshd:x:110:65534::/run/sshd:/usr/sbin/nologin\n" +
                "admin:x:1000:1000:admin,,,:/home/admin:/bin/bash\n"));
        etc.add(VNode.file("shadow", "rw-r-----", "root",
                "root:$6$K9x.qP3m$Z8fH2vLxNq0yT7wJcR5bUeA1sGdP4kM9oX3iF6hW8nQ2vC0zB5jY7tR1eU4aS9dG6mL3pN8xK2wV0hJ5cF7q:19520:0:99999:7:::\n" +
                "daemon:*:19000:0:99999:7:::\n" +
                "mysql:!:19312:0:99999:7:::\n" +
                "admin:$6$rT7vLm$H3kP9wX2nQ5vB8cZ1xM4jS7dF0gH6tY3uI9oL2kN5bV8cX1zA4qW7eR0tY3uI6oP9sD2fG5hJ8kL1mN4bV7:19520:0:99999:7:::\n"));
        etc.add(VNode.file("hostname", "rw-r--r--", "root", "svr01\n"));
        etc.add(VNode.file("hosts", "rw-r--r--", "root",
                "127.0.0.1\tlocalhost\n" +
                "127.0.1.1\tsvr01\n" +
                "10.0.0.15\tdb.internal\n" +
                "10.0.0.22\tbackup.internal\n" +
                "\n# The following lines are desirable for IPv6 capable hosts\n" +
                "::1     ip6-localhost ip6-loopback\n"));
        etc.add(VNode.file("issue", "rw-r--r--", "root", "Ubuntu 22.04.3 LTS \\n \\l\n"));
        etc.add(VNode.file("os-release", "rw-r--r--", "root",
                "PRETTY_NAME=\"Ubuntu 22.04.3 LTS\"\nNAME=\"Ubuntu\"\nVERSION_ID=\"22.04\"\nVERSION=\"22.04.3 LTS (Jammy Jellyfish)\"\nID=ubuntu\nID_LIKE=debian\n"));
        etc.add(VNode.file("motd", "rw-r--r--", "root", ""));
        VNode sshDir = VNode.dir("ssh", "rwxr-xr-x", "root");
        sshDir.add(VNode.file("sshd_config", "rw-r--r--", "root",
                "Port 22\nPermitRootLogin yes\nPasswordAuthentication yes\n#PubkeyAuthentication yes\nUsePAM yes\n"));
        etc.add(sshDir);
        VNode resolvConf = VNode.file("resolv.conf", "rw-r--r--", "root", "nameserver 10.0.0.2\nnameserver 8.8.8.8\n");
        etc.add(resolvConf);
        etc.add(VNode.file("crontab", "rw-r--r--", "root",
                "17 *\t* * *\troot    cd / && run-parts --report /etc/cron.hourly\n" +
                "25 6\t* * *\troot\ttest -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )\n"));

        // /root —— 攻击者"登录"后的家目录
        VNode rootHome = VNode.dir("root", "rwx------", "root");
        rootHome.add(VNode.file(".bash_history", "rw-------", "root",
                "apt update && apt upgrade -y\n" +
                "systemctl status mysql\n" +
                "tail -f /var/log/auth.log\n" +
                "scp backup.tar.gz admin@10.0.0.22:/backup/\n" +
                "mysql -u root -p\n" +
                "htop\n"));
        rootHome.add(VNode.file(".bashrc", "rw-r--r--", "root",
                "export PS1='\\u@\\h:\\w\\$ '\nalias ll='ls -alF'\nalias la='ls -A'\n"));
        rootHome.add(VNode.file(".profile", "rw-r--r--", "root",
                "if [ -n \"$BASH_VERSION\" ]; then\n    if [ -f \"$HOME/.bashrc\" ]; then\n\t. \"$HOME/.bashrc\"\n    fi\nfi\n"));
        rootHome.add(VNode.file("notes.txt", "rw-------", "root",
                "TODO:\n- rotate db credentials before Friday\n- check backup script on 10.0.0.22\n- mysql root password is in /root/.my.cnf\n"));
        rootHome.add(VNode.file(".my.cnf", "rw-------", "root",
                "[client]\nuser=root\npassword=Pr0d#Mysql!2024\n"));
        VNode sshKeys = VNode.dir(".ssh", "rwx------", "root");
        sshKeys.add(VNode.file("authorized_keys", "rw-------", "root",
                "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7...== deploy@ci-server\n"));
        rootHome.add(sshKeys);

        // /home/admin
        VNode home = VNode.dir("home", "rwxr-xr-x", "root");
        VNode adminHome = VNode.dir("admin", "rwxr-xr-x", "admin");
        adminHome.add(VNode.file(".bashrc", "rw-r--r--", "admin", "alias ll='ls -alF'\nexport PATH=$PATH:/opt/scripts\n"));
        adminHome.add(VNode.file("deploy.sh", "rwxr-xr-x", "admin",
                "#!/bin/bash\n# deploy to production\nrsync -avz ./dist/ admin@10.0.0.15:/var/www/app/\n"));
        home.add(adminHome);

        // /var/log 等
        VNode var = VNode.dir("var", "rwxr-xr-x", "root");
        VNode log = VNode.dir("log", "rwxr-xr-x", "root");
        log.add(VNode.file("auth.log", "rw-r-----", "root",
                "Aug 11 06:25:01 svr01 sshd[21841]: Accepted password for root from 203.0.113.44 port 51220 ssh2\n" +
                "Aug 11 06:25:03 svr01 sshd[21841]: pam_unix(sshd:session): session opened for user root\n"));
        log.add(VNode.file("syslog", "rw-r-----", "root",
                "Aug 11 06:25:01 svr01 systemd[1]: Starting Daily apt upgrade and clean activities...\n"));
        log.add(VNode.file("mysql.log", "rw-r-----", "mysql", ""));
        var.add(log);
        VNode www = VNode.dir("www", "rwxr-xr-x", "root");
        www.add(VNode.dir("html", "rwxr-xr-x", "www-data"));
        var.add(www);

        // /tmp、/proc、/dev 等骨架目录
        VNode tmp = VNode.dir("tmp", "rwxrwxrwx", "root");
        VNode proc = VNode.dir("proc", "r-xr-xr-x", "root");
        proc.add(VNode.file("cpuinfo", "r--r--r--", "root",
                "processor\t: 0\nmodel name\t: Intel(R) Xeon(R) Platinum 8375C CPU @ 2.90GHz\ncpu MHz\t\t: 2900.000\ncache size\t: 55296 KB\n"));
        proc.add(VNode.file("meminfo", "r--r--r--", "root",
                "MemTotal:        8161148 kB\nMemFree:         2415688 kB\nMemAvailable:    5341560 kB\n"));

        root.add(bin).add(sbin).add(etc).add(rootHome).add(home).add(var).add(tmp).add(proc)
            .add(VNode.dir("dev", "rwxr-xr-x", "root"))
            .add(VNode.dir("usr", "rwxr-xr-x", "root"))
            .add(VNode.dir("lib", "rwxr-xr-x", "root"))
            .add(VNode.dir("opt", "rwxr-xr-x", "root"))
            .add(VNode.dir("mnt", "rwxr-xr-x", "root"))
            .add(VNode.dir("media", "rwxr-xr-x", "root"))
            .add(VNode.dir("boot", "rwxr-xr-x", "root"))
            .add(VNode.dir("run", "rwxr-xr-x", "root"));

        return root;
    }
}
