package org.open.scdm.honeypot.web;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.open.scdm.honeypot.geo.IpLocator;

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

    /** 路径 → 中文描述映射：键为 "METHOD 路由模式"（数字路径段归一为 {id}），覆盖 ApiController 全部路由 */
    private static final Map<String, String> PATH_DESC = Map.ofEntries(
            // 认证
            Map.entry("POST /api/login", "用户登录"),
            Map.entry("POST /api/logout", "退出登录"),
            Map.entry("GET /api/me", "获取当前用户信息"),
            Map.entry("PUT /api/password", "修改登录密码"),
            // 攻击日志统计
            Map.entry("GET /api/stats/overview", "攻击总览统计"),
            Map.entry("GET /api/stats/trend", "攻击趋势统计"),
            Map.entry("GET /api/stats/protocol", "协议分布统计"),
            Map.entry("GET /api/stats/top-ips", "攻击源 IP TOP 统计"),
            Map.entry("GET /api/stats/top-locations", "攻击源地区 TOP 统计"),
            Map.entry("GET /api/stats/top-usernames", "高频爆破用户名统计"),
            Map.entry("GET /api/stats/top-passwords", "高频尝试口令统计"),
            // 攻击日志明细
            Map.entry("GET /api/sessions", "会话记录查询"),
            Map.entry("GET /api/auth-attempts", "登录尝试查询"),
            Map.entry("GET /api/commands", "命令记录查询"),
            Map.entry("GET /api/downloads", "恶意下载查询"),
            Map.entry("GET /api/ip-locks", "IP 锁定记录查询"),
            // 操作审计
            Map.entry("GET /api/audit-logs", "审计日志查询"),
            Map.entry("GET /api/audit-logs/trend", "审计日志趋势统计"),
            // 系统用户管理
            Map.entry("GET /api/users", "用户列表查询"),
            Map.entry("POST /api/users", "新增用户"),
            Map.entry("PUT /api/users/{id}/status", "启用/禁用用户"),
            Map.entry("PUT /api/users/{id}/password", "重置用户密码"),
            Map.entry("DELETE /api/users/{id}", "删除用户")
    );

    private final Connection conn;
    private final ExecutorService writer;
    /** IP 归属地定位器（可为 null，此时归属地留空） */
    private final IpLocator ipLocator;

    public AuditLogRepository(Path dbFile, IpLocator ipLocator) throws SQLException {
        this.ipLocator = ipLocator;
        this.conn = DriverManager.getConnection("jdbc:sqlite:" + dbFile.toAbsolutePath());
        try (Statement st = conn.createStatement()) {
            st.execute("PRAGMA busy_timeout=5000");
            st.execute("PRAGMA cache_size=-600"); // 页缓存收紧至约 600KB，降低常驻原生内存
            st.execute("""
                    CREATE TABLE IF NOT EXISTS sys_audit_log (
                        id          INTEGER PRIMARY KEY AUTOINCREMENT,
                        ts          TEXT    NOT NULL,                 -- 操作时间 yyyy-MM-dd HH:mm:ss
                        epoch_ms    INTEGER NOT NULL,                 -- 毫秒时间戳（排序/范围过滤）
                        username    TEXT,                            -- 操作用户名（未登录为 NULL）
                        src_ip      TEXT    NOT NULL,                 -- 来源 IP
                        method      TEXT    NOT NULL,                 -- HTTP 方法
                        path        TEXT    NOT NULL,                 -- 请求路径
                        path_desc   TEXT,                            -- 路径中文描述（按方法+路由模式映射）
                        query       TEXT,                            -- 查询串
                        req_body    TEXT,                            -- 请求体（敏感字段脱敏）
                        status      INTEGER NOT NULL,                 -- 响应状态码
                        resp_body   TEXT,                            -- 响应体摘要（截断）
                        duration_ms INTEGER NOT NULL,                 -- 处理耗时（毫秒）
                        ok          INTEGER NOT NULL,                 -- 1 成功 / 0 失败
                        location    TEXT                             -- 来源 IP 归属地（国家 省份 城市，ip2region 库解析）
                    )""");
            st.execute("CREATE INDEX IF NOT EXISTS idx_audit_epoch ON sys_audit_log(epoch_ms)");
            st.execute("CREATE INDEX IF NOT EXISTS idx_audit_user ON sys_audit_log(username)");
            // 存量表迁移：旧表无 location / path_desc 列时补加（新建表 DDL 已含这两列）
            boolean hasLocation = false;
            boolean hasPathDesc = false;
            try (ResultSet rs = st.executeQuery("PRAGMA table_info(sys_audit_log)")) {
                while (rs.next()) {
                    String col = rs.getString("name");
                    if ("location".equals(col)) hasLocation = true;
                    if ("path_desc".equals(col)) hasPathDesc = true;
                }
            }
            if (!hasLocation) {
                st.execute("ALTER TABLE sys_audit_log ADD COLUMN location TEXT");
            }
            if (!hasPathDesc) {
                st.execute("ALTER TABLE sys_audit_log ADD COLUMN path_desc TEXT");
            }
        }
        ThreadFactory tf = r -> {
            Thread t = new Thread(r, "audit-log-writer");
            t.setDaemon(true);
            return t;
        };
        this.writer = Executors.newSingleThreadExecutor(tf);
    }

    /** 异步记录一条审计日志（脱敏 + 截断在调用前完成）；归属地在写入线程内解析，不阻塞 Web 请求 */
    public void record(String username, String srcIp, String method, String path, String query,
                       String reqBody, int status, String respBody, long durationMs, boolean ok) {
        String ts = LocalDateTime.now().format(TS);
        long epoch = System.currentTimeMillis();
        String pathDesc = pathDesc(method, path);
        writer.submit(() -> {
            String location = (ipLocator == null) ? null : ipLocator.locate(srcIp);
            try (PreparedStatement ps = conn.prepareStatement(
                    "INSERT INTO sys_audit_log(ts, epoch_ms, username, src_ip, method, path, path_desc, query,"
                            + " req_body, status, resp_body, duration_ms, ok, location)"
                            + " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)")) {
                ps.setString(1, ts);
                ps.setLong(2, epoch);
                ps.setString(3, username);
                ps.setString(4, srcIp);
                ps.setString(5, method);
                ps.setString(6, path);
                ps.setString(7, pathDesc);
                ps.setString(8, query);
                ps.setString(9, reqBody);
                ps.setInt(10, status);
                ps.setString(11, respBody);
                ps.setLong(12, durationMs);
                ps.setInt(13, ok ? 1 : 0);
                ps.setString(14, location);
                ps.executeUpdate();
            } catch (SQLException e) {
                LOG.log(Level.WARNING, "审计日志写入失败", e);
            }
        });
    }

    /** 解析路径中文描述：数字路径段归一为 {id}（如 /api/users/3/status）后查映射表，未命中返回 null */
    static String pathDesc(String method, String path) {
        if (method == null || path == null) return null;
        return PATH_DESC.get(method + " " + path.replaceAll("/\\d+", "/{id}"));
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
            // 路径关键字同时匹配原始路径与中文描述，支持按中文（如「登录」）检索
            where.append(" AND (path LIKE ? OR path_desc LIKE ?)");
            params.add("%" + pathKeyword.trim() + "%");
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
        List<Map<String, Object>> rows = new ArrayList<>(Math.min(size, 200));
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            bind(ps, params);
            ps.setInt(params.size() + 1, size);
            ps.setLong(params.size() + 2, (long) (page - 1) * size);
            try (ResultSet rs = ps.executeQuery()) {
                // 元数据与列标签只取一次，避免原先每行重复调用 rs.getMetaData()
                java.sql.ResultSetMetaData md = rs.getMetaData();
                int n = md.getColumnCount();
                String[] labels = new String[n];
                for (int i = 0; i < n; i++) labels[i] = md.getColumnLabel(i + 1);
                while (rs.next()) {
                    Map<String, Object> row = new LinkedHashMap<>(n * 2);
                    for (int i = 0; i < n; i++) {
                        row.put(labels[i], rs.getObject(i + 1));
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
            // 保留原始类型（String / Long）绑定，交由驱动处理，避免全部退化字符串增加转换开销
            ps.setObject(i + 1, params.get(i));
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
