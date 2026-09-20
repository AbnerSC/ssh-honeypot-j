package org.open.scdm.honeypot.shell;

import org.open.scdm.honeypot.fs.VirtualFileSystem;

import java.util.ArrayList;
import java.util.List;

/**
 * 单个攻击会话的状态：登录用户、当前目录、命令历史。
 * 每个连接一份，互不干扰（文件系统树是共享的，模拟多人攻击同一台机器）。
 */
public class SessionState {
    public final String sessionId;
    public final String ip;
    public final VirtualFileSystem fs;
    /** 伪装主机名，用于提示符（如 root@svr01:~#） */
    public final String hostname;
    public String username;
    public String cwd;
    public final List<String> history = new ArrayList<>();
    /** 用户主目录绝对路径，root 为 /root，普通用户为 /home/<username> */
    public final String homeDir;

    public SessionState(String sessionId, String ip, String username, VirtualFileSystem fs, String hostname) {
        this.sessionId = sessionId;
        this.ip = ip;
        // 用户名清洗：攻击者可提交任意字符串作用户名，未清洗的路径分隔符/控制字符
        // 会污染提示符与 /home 目录结构
        this.username = sanitizeUser(username);
        this.fs = fs;
        this.hostname = hostname;
        if ("root".equals(this.username)) {
            this.homeDir = "/root";
        } else {
            // 普通用户登录后自动创建 /home/<username>，避免找不到目录
            this.homeDir = "/home/" + this.username;
            fs.ensureHome(this.username);
        }
        this.cwd = this.homeDir;
    }

    /** 用户名清洗：仅保留常规 Linux 用户名字符，其余替换为下划线；清洗后为空回退 nobody */
    static String sanitizeUser(String name) {
        String s = name == null ? "" : name.replaceAll("[^a-zA-Z0-9._-]", "_").trim();
        return s.isEmpty() ? "nobody" : s;
    }

    /** 提示符，如 root@svr01:~# */
    public String prompt() {
        String dir = cwd;
        if (dir.equals(homeDir)) dir = "~";
        else if (dir.startsWith(homeDir + "/")) dir = "~" + dir.substring(homeDir.length());
        return username + "@" + hostname + ":" + dir + ("root".equals(username) ? "# " : "$ ");
    }
}
