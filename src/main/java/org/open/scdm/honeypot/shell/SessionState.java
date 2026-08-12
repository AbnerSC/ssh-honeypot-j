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
    public String username;
    public String cwd = "/root";
    public final List<String> history = new ArrayList<>();

    public SessionState(String sessionId, String ip, String username, VirtualFileSystem fs) {
        this.sessionId = sessionId;
        this.ip = ip;
        this.username = username;
        this.fs = fs;
        this.cwd = "root".equals(username) ? "/root" : "/home/" + username;
    }

    /** 提示符，如 root@svr01:~# */
    public String prompt() {
        String dir = cwd;
        String homeDir = "root".equals(username) ? "/root" : "/home/" + username;
        if (dir.equals(homeDir)) dir = "~";
        else if (dir.startsWith(homeDir + "/")) dir = "~" + dir.substring(homeDir.length());
        return username + "@svr01:" + dir + ("root".equals(username) ? "# " : "$ ");
    }
}
