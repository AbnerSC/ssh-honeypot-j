package org.open.scdm.honeypot.web;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * 系统操作审计日志仓库：记录 Web 控制台用户的全部 API 操作。
 * <p>
 * 与攻击日志共用同一 SQLite 文件（sys_audit_log 表，WAL 模式下与蜜罐写入互不阻塞）。
 * 写入走独立单线程执行器异步落库，不阻塞 Web 请求线程；
 * 查询走独立只读连接，与 {@link LogRepository} 互不影响。
 */
public class AuditLogRepository implements AutoCloseable {

    private static final Logger LOG = Logger.getLogger(AuditLogRepository.class.getName());
    private static final DateTimeFormatter TS = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    private static final Gson GSON = new Gson();

    private final Connection conn;
    private final ExecutorService writer;

    public AuditLogRepository(Path dbFile) throws SQLException {
        this.conn = DriverManager.getConnection("jdbc:sqlite:" + dbFile.toAbsolutePath());
        try (Statement st = conn.createStatement()) {
            st.execute("PRAGMA busy_timeout=5000");
            st.execute("""
                    CREATE TABLE IF NOT EXISTS sys_audit_log (
                        id          INTEGER PRIMARY KEY AUTOINCREMENT,
                        ts          TEXT    NOT NULL,                 -- 操作时间 yyyy-MM-dd HH:mm:ss
                        epoch_ms    INTEGER NOT NULL,                 -- 毫秒时间戳（排序/范围过滤）
                        username    TEXT,                            -- 操作用户名（未登录为 NULL）
                        src_ip      TEXT    NOT NULL,                 -- 来源 IP
                        method      TEXT    NOT NULL,                 -- HTTP 方法
                        path        TEXT    NOT NULL,                 -- 请求路径
                        query       TEXT,                            -- 查询串
                        req_body    TEXT,                            -- 请求体（敏感字段脱敏）
                        status      INTEGER NOT NULL,                 -- 响应状态码
                        resp_body   TEXT,                            -- 响应体摘要（截断）
                        duration_ms INTEGER NOT NULL,                 -- 处理耗时（毫秒）
                        ok          INTEGER NOT NULL                  -- 1 成功 / 0 失败
                    )""");
            st.execute("CREATE INDEX IF NOT EXISTS idx_audit_epoch ON sys_audit_log(epoch_ms)");
            st.execute("CREATE INDEX IF NOT EXISTS idx_audit_user ON sys_audit_log(username)");
        }
        ThreadFactory tf = r -> {
            Thread t = new Thread(r, "audit-log-writer");
            t.setDaemon(true);
            return t;
        };
        this.writer = Executors.newSingleThreadExecutor(tf);
    }

    /** 异步记录一条审计日志（脱敏 + 截断在调用前完成） */
    public void record(String username, String srcIp, String method, String path, String query,
                       String reqBody, int status, String respBody, long durationMs, boolean ok) {
        String ts = LocalDateTime.now().format(TS);
        long epoch = System.currentTimeMillis();
        writer.submit(() -> {
            try (PreparedStatement ps = conn.prepareStatement(
                    "INSERT INTO sys_audit_log(ts, epoch_ms, username, src_ip, method, path, query,"
                            + " req_body, status, resp_body, duration_ms, ok)"
                            + " VALUES(?,?,?,?,?,?,?,?,?,?,?,?)")) {
                ps.setString(1, ts);
                ps.setLong(2, epoch);
                ps.setString(3, username);
                ps.setString(4, srcIp);
                ps.setString(5, method);
                ps.setString(6, path);
                ps.setString(7, query);
                ps.setString(8, reqBody);
                ps.setInt(9, status);
                ps.setString(10, respBody);
                ps.setLong(11, durationMs);
                ps.setInt(12, ok ? 1 : 0);
                ps.executeUpdate();
            } catch (SQLException e) {
                LOG.log(Level.WARNING, "审计日志写入失败", e);
            }
        });
    }

    /** 审计日志明细（分页，支持用户名 / 来源 IP / 方法 / 路径关键字 / 时间范围过滤） */
    public Map<String, Object> list(String username, String srcIp, String method, String pathKeyword,
                                    Long start, Long end, int page, int size) throws SQLException {
        StringBuilder where = new StringBuilder(" WHERE 1=1");
        List<Object> params = new ArrayList<>();
        if (username != null && !username.isBlank()) {
            where.append(" AND username LIKE ?");
            params.add("%" + username.trim() + "%");
        }
        if (srcIp != null && !srcIp.isBlank()) {
            where.append(" AND src_ip LIKE ?");
            params.add("%" + srcIp.trim() + "%");
        }
        if (method != null && !method.isBlank()) {
            where.append(" AND method = ?");
            params.add(method.trim().toUpperCase());
        }
        if (pathKeyword != null && !pathKeyword.isBlank()) {
            where.append(" AND path LIKE ?");
            params.add("%" + pathKeyword.trim() + "%");
        }
        if (start != null) {
            where.append(" AND epoch_ms >= ?");
            params.add(start);
        }
        if (end != null) {
            where.append(" AND epoch_ms <= ?");
            params.add(end);
        }

        long total;
        try (PreparedStatement ps = conn.prepareStatement(
                "SELECT COUNT(*) FROM sys_audit_log" + where)) {
            bind(ps, params);
            try (ResultSet rs = ps.executeQuery()) {
                total = rs.next() ? rs.getLong(1) : 0;
            }
        }

        String sql = "SELECT * FROM sys_audit_log" + where
                + " ORDER BY epoch_ms DESC, id DESC LIMIT ? OFFSET ?";
        List<Map<String, Object>> rows = new ArrayList<>();
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            bind(ps, params);
            ps.setInt(params.size() + 1, size);
            ps.setLong(params.size() + 2, (long) (page - 1) * size);
            try (ResultSet rs = ps.executeQuery()) {
                int n = rs.getMetaData().getColumnCount();
                while (rs.next()) {
                    Map<String, Object> row = new LinkedHashMap<>();
                    for (int i = 1; i <= n; i++) {
                        row.put(rs.getMetaData().getColumnLabel(i), rs.getObject(i));
                    }
                    rows.add(row);
                }
            }
        }
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("total", total);
        result.put("page", page);
        result.put("size", size);
        result.put("rows", rows);
        return result;
    }

    /** 审计日志按日趋势（近 N 天）：总操作数 / 失败数 */
    public List<Map<String, Object>> trend(int days) throws SQLException {
        String since = LocalDateTime.now().minusDays(days - 1L).format(DateTimeFormatter.ISO_LOCAL_DATE);
        List<Map<String, Object>> rows = new ArrayList<>();
        try (PreparedStatement ps = conn.prepareStatement(
                "SELECT substr(ts,1,10) d, COUNT(*) c, SUM(ok = 0) f"
                        + " FROM sys_audit_log WHERE substr(ts,1,10) >= ? GROUP BY d ORDER BY d")) {
            ps.setString(1, since);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    Map<String, Object> m = new LinkedHashMap<>();
                    m.put("day", rs.getString(1));
                    m.put("total", rs.getLong(2));
                    m.put("failures", rs.getLong(3));
                    rows.add(m);
                }
            }
        }
        return rows;
    }

    private static void bind(PreparedStatement ps, List<Object> params) throws SQLException {
        for (int i = 0; i < params.size(); i++) {
            ps.setString(i + 1, String.valueOf(params.get(i)));
        }
    }

    @Override
    public void close() {
        writer.shutdown();
        try {
            if (!writer.awaitTermination(2, TimeUnit.SECONDS)) writer.shutdownNow();
        } catch (InterruptedException e) {
            writer.shutdownNow();
            Thread.currentThread().interrupt();
        }
        try {
            conn.close();
        } catch (SQLException ignored) {
        }
    }

    // ============================ 脱敏工具 ============================

    /**
     * 请求体脱敏：JSON 对象中 password / oldPassword / newPassword 字段替换为 ***。
     * 非 JSON 或解析失败时原样返回（截断由调用方负责）。
     */
    public static String maskBody(String body) {
        if (body == null || body.isBlank()) return null;
        try {
            JsonObject obj = JsonParser.parseString(body).getAsJsonObject();
            for (String key : new String[]{"password", "oldPassword", "newPassword"}) {
                if (obj.has(key) && !obj.get(key).isJsonNull()) {
                    obj.addProperty(key, "***");
                }
            }
            return GSON.toJson(obj);
        } catch (Exception e) {
            return body;
        }
    }

    /** 响应体摘要：仅保留 ok / error 字段，截断至 2000 字符，避免大列表撑爆日志 */
    public static String maskResponse(String body) {
        if (body == null || body.isBlank()) return null;
        try {
            JsonObject obj = JsonParser.parseString(body).getAsJsonObject();
            JsonObject out = new JsonObject();
            if (obj.has("ok")) out.add("ok", obj.get("ok"));
            if (obj.has("error")) out.add("error", obj.get("error"));
            if (obj.has("user")) out.add("user", obj.get("user"));
            if (obj.has("data")) {
                // 列表类 data 仅记录条数，避免存储大量业务数据
                if (obj.get("data").isJsonObject()
                        && obj.getAsJsonObject("data").has("rows")) {
                    JsonObject d = obj.getAsJsonObject("data");
                    JsonObject dd = new JsonObject();
                    for (String k : d.keySet()) {
                        if (!"rows".equals(k)) dd.add(k, d.get(k));
                    }
                    dd.addProperty("rowsCount", d.getAsJsonArray("rows").size());
                    out.add("data", dd);
                } else {
                    out.add("data", obj.get("data"));
                }
            }
            return truncate(GSON.toJson(out));
        } catch (Exception e) {
            return truncate(body);
        }
    }

    private static String truncate(String s) {
        return s.length() > 2000 ? s.substring(0, 2000) + "…(truncated)" : s;
    }
}
