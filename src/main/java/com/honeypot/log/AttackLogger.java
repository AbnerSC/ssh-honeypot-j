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
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Logger;

/**
 * 攻击日志记录器：JSON Lines 格式，每条事件一行，便于后续用 jq/ELK 分析。
 * 同时输出到控制台便于实时观察。
 * <p>
 * 性能设计：日志事件提交到单线程异步写入队列，调用方（会话线程）零阻塞，
 * 磁盘 I/O 不会拖慢攻击会话响应；单线程写入保证 JSONL 行序不乱。
 *
 * 事件类型：session_open / auth_attempt / command / download / session_close
 */
public class AttackLogger implements AutoCloseable {
    private static final Logger LOG = Logger.getLogger(AttackLogger.class.getName());
    private static final DateTimeFormatter TS = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS");

    private final BufferedWriter writer;
    private final AtomicLong sessionSeq = new AtomicLong();
    /** 单线程写入器：串行刷盘，避免 synchronized 阻塞会话线程 */
    private final ExecutorService writePool =
            Executors.newSingleThreadExecutor(Thread.ofVirtual().name("attack-log-writer").factory());

    public AttackLogger(Path logFile) throws IOException {
        Files.createDirectories(logFile.getParent());
        this.writer = Files.newBufferedWriter(logFile, StandardCharsets.UTF_8,
                StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        LOG.info("攻击日志写入: " + logFile.toAbsolutePath());
    }

    public String newSessionId() {
        return "s" + sessionSeq.incrementAndGet() + "-" + Long.toHexString(System.currentTimeMillis());
    }

    public void sessionOpen(String sessionId, String protocol, String ip, int port) {
        write(Map.of("event", "session_open", "session", sessionId,
                "protocol", protocol, "src_ip", ip, "src_port", String.valueOf(port)));
    }

    public void authAttempt(String sessionId, String protocol, String ip,
                            String username, String password, boolean success) {
        write(Map.of("event", "auth_attempt", "session", sessionId, "protocol", protocol,
                "src_ip", ip, "username", username, "password", password,
                "success", String.valueOf(success)));
        System.out.printf("[%s] [%s] 登录尝试 %s 用户=%s 密码=%s -> %s%n",
                LocalDateTime.now().format(TS), protocol, ip, username, password,
                success ? "放行(蜜罐)" : "拒绝");
    }

    public void command(String sessionId, String ip, String username, String cmdline) {
        write(Map.of("event", "command", "session", sessionId,
                "src_ip", ip, "username", username, "command", cmdline));
        System.out.printf("[%s] [%s] %s$ %s%n", LocalDateTime.now().format(TS), ip, username, cmdline);
    }

    public void download(String sessionId, String ip, String username, String url) {
        write(Map.of("event", "download", "session", sessionId,
                "src_ip", ip, "username", username, "url", url));
        System.out.printf("[%s] [%s] 恶意下载: %s%n", LocalDateTime.now().format(TS), ip, url);
    }

    public void sessionClose(String sessionId, String ip, long durationMs) {
        write(Map.of("event", "session_close", "session", sessionId,
                "src_ip", ip, "duration_ms", String.valueOf(durationMs)));
    }

    private void write(Map<String, String> fields) {
        // 序列化在调用线程完成（纯内存操作），磁盘写入异步串行执行
        StringBuilder sb = new StringBuilder(128);
        sb.append('{').append("\"ts\":\"").append(LocalDateTime.now().format(TS)).append('"');
        fields.forEach((k, v) -> sb.append(",\"").append(k).append("\":\"").append(escape(v)).append('"'));
        sb.append('}');
        String line = sb.toString();
        try {
            writePool.execute(() -> {
                try {
                    writer.write(line);
                    writer.newLine();
                    writer.flush();
                } catch (IOException e) {
                    LOG.warning("日志写入失败: " + e.getMessage());
                }
            });
        } catch (Exception e) {
            LOG.warning("日志提交失败(可能已关闭): " + e.getMessage());
        }
    }

    private static String escape(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");
    }

    @Override
    public void close() throws IOException {
        writePool.shutdown();
        try {
            if (!writePool.awaitTermination(5, TimeUnit.SECONDS)) writePool.shutdownNow();
        } catch (InterruptedException e) {
            writePool.shutdownNow();
            Thread.currentThread().interrupt();
        }
        writer.close();
    }
}
