package com.honeypot.log;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Logger;

/**
 * 攻击日志记录器：JSON Lines 格式，每条事件一行，便于后续用 jq/ELK 分析。
 * 同时输出到控制台便于实时观察。
 *
 * 事件类型：session_open / auth_attempt / command / download / session_close
 */
public class AttackLogger implements AutoCloseable {
    private static final Logger LOG = Logger.getLogger(AttackLogger.class.getName());
    private static final DateTimeFormatter TS = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS");

    private final BufferedWriter writer;
    private final AtomicLong sessionSeq = new AtomicLong();

    public AttackLogger(Path logFile) throws IOException {
        Files.createDirectories(logFile.getParent());
        this.writer = Files.newBufferedWriter(logFile, StandardCharsets.UTF_8,
                StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        LOG.info("攻击日志写入: " + logFile.toAbsolutePath());
    }

    public String newSessionId() {
        return "s" + sessionSeq.incrementAndGet() + "-" + Long.toHexString(System.currentTimeMillis());
    }

    public synchronized void sessionOpen(String sessionId, String protocol, String ip, int port) {
        write(Map.of("event", "session_open", "session", sessionId,
                "protocol", protocol, "src_ip", ip, "src_port", String.valueOf(port)));
    }

    public synchronized void authAttempt(String sessionId, String protocol, String ip,
                                         String username, String password, boolean success) {
        write(Map.of("event", "auth_attempt", "session", sessionId, "protocol", protocol,
                "src_ip", ip, "username", username, "password", password,
                "success", String.valueOf(success)));
        System.out.printf("[%s] [%s] 登录尝试 %s 用户=%s 密码=%s -> %s%n",
                LocalDateTime.now().format(TS), protocol, ip, username, password,
                success ? "放行(蜜罐)" : "拒绝");
    }

    public synchronized void command(String sessionId, String ip, String username, String cmdline) {
        write(Map.of("event", "command", "session", sessionId,
                "src_ip", ip, "username", username, "command", cmdline));
        System.out.printf("[%s] [%s] %s$ %s%n", LocalDateTime.now().format(TS), ip, username, cmdline);
    }

    public synchronized void download(String sessionId, String ip, String username, String url) {
        write(Map.of("event", "download", "session", sessionId,
                "src_ip", ip, "username", username, "url", url));
        System.out.printf("[%s] [%s] 恶意下载: %s%n", LocalDateTime.now().format(TS), ip, url);
    }

    public synchronized void sessionClose(String sessionId, String ip, long durationMs) {
        write(Map.of("event", "session_close", "session", sessionId,
                "src_ip", ip, "duration_ms", String.valueOf(durationMs)));
    }

    private void write(Map<String, String> fields) {
        StringBuilder sb = new StringBuilder("{");
        sb.append("\"ts\":\"").append(LocalDateTime.now().format(TS)).append("\"");
        fields.forEach((k, v) -> sb.append(",\"").append(k).append("\":\"").append(escape(v)).append("\""));
        sb.append("}");
        try {
            writer.write(sb.toString());
            writer.newLine();
            writer.flush();
        } catch (IOException e) {
            LOG.warning("日志写入失败: " + e.getMessage());
        }
    }

    private static String escape(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");
    }

    @Override
    public synchronized void close() throws IOException {
        writer.close();
    }
}
