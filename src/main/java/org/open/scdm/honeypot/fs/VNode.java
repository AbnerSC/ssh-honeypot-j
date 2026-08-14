package org.open.scdm.honeypot.fs;

import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 虚拟文件系统节点（文件或目录）。
 * 所有攻击者看到的文件都只存在于内存中，永远不会触碰真实磁盘。
 */
public class VNode {
    private static final DateTimeFormatter LS_DATE =
            DateTimeFormatter.ofPattern("MMM dd HH:mm", java.util.Locale.ENGLISH);

    public final String name;
    public final boolean directory;
    public final String owner;
    public final String group;
    public final String perms;          // 例如 "rw-r--r--" / "rwxr-xr-x"
    public final LocalDateTime mtime;
    private String content;             // 文件内容（仅文件）
    private int cachedSize = -1;        // 内容字节数惰性缓存，避免 ls -l 重复 getBytes()
    private final Map<String, VNode> children = new LinkedHashMap<>(); // 子节点（仅目录）

    private VNode(String name, boolean directory, String perms, String owner, String group, LocalDateTime mtime) {
        this.name = name;
        this.directory = directory;
        this.perms = perms;
        this.owner = owner;
        this.group = group;
        this.mtime = mtime;
    }

    public static VNode dir(String name, String perms, String owner) {
        return new VNode(name, true, perms, owner, owner, LocalDateTime.now().minusDays(30));
    }

    public static VNode file(String name, String perms, String owner, String content) {
        VNode n = new VNode(name, false, perms, owner, owner, LocalDateTime.now().minusDays(7));
        n.content = content;
        return n;
    }

    public static VNode exec(String name, String owner) {
        VNode n = new VNode(name, false, "rwxr-xr-x", owner, owner, LocalDateTime.now().minusDays(60));
        n.content = "";
        return n;
    }

    public VNode add(VNode child) {
        children.put(child.name, child);
        return this;
    }

    public VNode child(String name) {
        return children.get(name);
    }

    public Map<String, VNode> children() {
        return children;
    }

    public String content() {
        return content == null ? "" : content;
    }

    public void content(String c) {
        this.content = c;
        this.cachedSize = -1;           // 内容变更，失效缓存
    }

    public long size() {
        if (directory) return 4096;
        if (content == null) return 128;
        int s = cachedSize;
        if (s < 0) cachedSize = s = content.getBytes(StandardCharsets.UTF_8).length;
        return s;
    }

    /**
     * 判断某用户对该节点是否拥有指定权限位。
     * perm 取 'r' / 'w' / 'x'（对应 Unix 的读/写/执行权限）。
     * 规则与 Linux 一致：root 用户绕过权限检查；否则按 owner / group / other 三类判断。
     */
    public boolean canAccess(String user, char perm) {
        if ("root".equals(user)) return true;           // root 无视权限位
        int idx;
        if (user.equals(owner)) idx = 0;                // 属主
        else if (user.equals(group)) idx = 3;           // 属组
        else idx = 6;                                   // 其他用户
        return perms.charAt(idx + (perm == 'r' ? 0 : perm == 'w' ? 1 : 2)) != '-';
    }

    /** ls -l 单行展示 */
    public String toLsLong() {
        String typeChar = directory ? "d" : "-";
        int links = directory ? 2 + (int) children.values().stream().filter(v -> v.directory).count() : 1;
        return String.format("%s%s %2d %-8s %-8s %8d %s %s",
                typeChar, perms, links, owner, group, size(), mtime.format(LS_DATE), name);
    }
}
