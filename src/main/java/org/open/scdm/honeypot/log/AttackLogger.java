package org.open.scdm.honeypot.log;

import org.open.scdm.honeypot.geo.IpLocator;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.sql.SQLException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Logger;

/**
 * 攻击日志记录器：JSON Lines 格式，每条事件一行，便于后续用 jq/ELK 分析。
 * 同时输出到控制台便于实时观察。
 * 同一份数据另外双写到 SQLite 数据库（SqliteLogStore），供后续 Web 可视化查询。
 * <p>
 * 性能设计：日志事件提交到单线程异步写入队列，调用方（会话线程）零阻塞，
 * 磁盘 I/O 不会拖慢攻击会话响应；单线程写入保证 JSONL 行序不乱，
 * 也保证了 SQLite 单连接写用的线程安全。
 *
 * 事件类型：session_open / auth_attempt / command / download / session_close
 */
public class AttackLogger implements AutoCloseable {
    private static final Logger LOG = Logger.getLogger(AttackLogger.class.getName());
    private static final DateTimeFormatter TS = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS");

    private final BufferedWriter writer;
    /** SQLite 持久化存储；初始化失败时为 null，退化为仅写 JSONL */
    private final SqliteLogStore db;
    /** IP 归属地定位器（可为 null，此时归属地留空） */
    private final IpLocator ipLocator;
    private final AtomicLong sessionSeq = new AtomicLong();
    /** 单线程写入器：串行刷盘，避免 synchronized 阻塞会话线程 */
    private final ExecutorService writePool =
            Executors.newSingleThreadExecutor(Thread.ofVirtual().name("attack-log-writer").factory());

    /** SQLite 写入动作：与对应 JSONL 记录共用同一时间戳，在单线程写入器中串行执行 */
    @FunctionalInterface
    private interface DbSink {
        void write(SqliteLogStore store, LocalDateTime ts) throws SQLException;
    }

    public AttackLogger(Path logFile, Path dbFile, IpLocator ipLocator) throws IOException {
        this.ipLocator = ipLocator;
        Files.createDirectories(logFile.getParent());
        this.writer = Files.newBufferedWriter(logFile, StandardCharsets.UTF_8,
                StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        SqliteLogStore store = null;
        try {
            store = new SqliteLogStore(dbFile);
            LOG.info("SQLite 数据库: " + dbFile.toAbsolutePath());
        } catch (Exception e) {
            LOG.warning("SQLite 数据库初始化失败，仅写入 JSONL 日志: " + e.getMessage());
        }
        this.db = store;
        LOG.info("攻击日志写入: " + logFile.toAbsolutePath());
    }

    public String newSessionId() {
        return "s" + sessionSeq.incrementAndGet() + "-" + Long.toHexString(System.currentTimeMillis());
    }

    /** SQLite 存储是否初始化成功（Web 控制台依赖数据库，不可用时不启动） */
    public boolean isDbHealthy() {
        return db != null;
    }

    public void sessionOpen(String sessionId, String protocol, String ip, int port) {
        // 归属地在会话线程同步解析：xdb 全内存检索微秒级，另有进程内缓存
        String location = (ipLocator == null) ? null : ipLocator.locate(ip);
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("event", "session_open");
        fields.put("session", sessionId);
        fields.put("protocol", protocol);
        fields.put("src_ip", ip);
        fields.put("src_port", String.valueOf(port));
        if (location != null) fields.put("location", location);
        write(fields, (store, ts) -> store.recordSessionOpen(ts, sessionId, protocol, ip, port, location));
    }

    public void authAttempt(String sessionId, String protocol, String ip,
                            String username, String password, boolean success) {
        write(Map.of("event", "auth_attempt", "session", sessionId, "protocol", protocol,
                "src_ip", ip, "username", username, "password", password,
                "success", String.valueOf(success)),
                (store, ts) -> store.recordAuthAttempt(ts, sessionId, protocol, ip, username, password, success));
        System.out.printf("[%s] [%s] 登录尝试 %s 用户=%s 密码=%s -> %s%n",
                LocalDateTime.now().format(TS), protocol, ip, username, password,
                success ? "放行(蜜罐)" : "拒绝");
    }

    public void ipLocked(String ip, long untilMillis) {
        String until = LocalDateTime.ofInstant(Instant.ofEpochMilli(untilMillis), ZoneId.systemDefault())
                .format(TS);
        write(Map.of("event", "ip_locked", "src_ip", ip, "until", until),
                (store, ts) -> store.recordIpLocked(ts, ip, untilMillis));
        System.out.printf("[%s] 源 IP %s 连续登录失败已达上限，锁定至 %s%n",
                LocalDateTime.now().format(TS), ip, until);
    }

    public void command(String sessionId, String ip, String username, String cmdline) {
        write(Map.of("event", "command", "session", sessionId,
                "src_ip", ip, "username", username, "command", cmdline),
                (store, ts) -> store.recordCommand(ts, sessionId, ip, username, cmdline));
        System.out.printf("[%s] [%s] %s$ %s%n", LocalDateTime.now().format(TS), ip, username, cmdline);
    }

    public void download(String sessionId, String ip, String username, String url) {
        write(Map.of("event", "download", "session", sessionId,
                "src_ip", ip, "username", username, "url", url),
                (store, ts) -> store.recordDownload(ts, sessionId, ip, username, url));
        System.out.printf("[%s] [%s] 恶意下载: %s%n", LocalDateTime.now().format(TS), ip, url);
    }

    public void sessionClose(String sessionId, String ip, long durationMs) {
        write(Map.of("event", "session_close", "session", sessionId,
                "src_ip", ip, "duration_ms", String.valueOf(durationMs)),
                (store, ts) -> store.recordSessionClose(ts, sessionId, durationMs));
    }

    private void write(Map<String, String> fields, DbSink dbSink) {
        // 序列化在调用线程完成（纯内存操作），磁盘写入异步串行执行
        LocalDateTime now = LocalDateTime.now();
        StringBuilder sb = new StringBuilder(128);
        sb.append('{').append("\"ts\":\"").append(now.format(TS)).append('"');
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
                if (db != null && dbSink != null) {
                    try {
                        dbSink.write(db, now);
                    } catch (SQLException e) {
                        LOG.warning("SQLite 写入失败: " + e.getMessage());
                    }
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
        if (db != null) {
            try {
                db.close();
            } catch (SQLException e) {
                LOG.warning("SQLite 关闭失败: " + e.getMessage());
            }
        }
    }
}
