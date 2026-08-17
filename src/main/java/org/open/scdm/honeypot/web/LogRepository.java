package org.open.scdm.honeypot.web;

import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 攻击日志只读查询仓库：Web 控制台统计与明细查询的数据源。
 * <p>
 * 独立于 AttackLogger 的写入连接，另开只读连接查询同一 SQLite 文件；
 * WAL 模式下读写互不阻塞，蜜罐写入不受 Web 查询影响。
 * 由 Web 请求线程并发调用，所有方法内部各自持有 PreparedStatement，无共享可变状态。
 */
public class LogRepository implements AutoCloseable {

    private final Connection conn;

    public LogRepository(Path dbFile) throws SQLException {
        this.conn = DriverManager.getConnection("jdbc:sqlite:" + dbFile.toAbsolutePath());
        try (Statement st = conn.createStatement()) {
            st.execute("PRAGMA busy_timeout=5000");
            st.execute("PRAGMA query_only=ON"); // 防御性设置：本连接永不允许写
        }
    }

    /** 总览统计：各事件总量、独立攻击源 IP 数、今日新增、当前生效锁定 IP 数 */
    public Map<String, Object> overview() throws SQLException {
        long todayStart = LocalDate.now().atStartOfDay()
                .atZone(java.time.ZoneId.systemDefault()).toInstant().toEpochMilli();
        Map<String, Object> m = new LinkedHashMap<>();
        try (PreparedStatement ps = conn.prepareStatement("""
                SELECT (SELECT COUNT(*) FROM sessions)                                    AS total_sessions,
                       (SELECT COUNT(*) FROM auth_attempts)                               AS total_auth,
                       (SELECT COUNT(*) FROM commands)                                    AS total_commands,
                       (SELECT COUNT(*) FROM downloads)                                   AS total_downloads,
                       (SELECT COUNT(DISTINCT src_ip) FROM auth_attempts)                 AS unique_ips,
                       (SELECT COUNT(*) FROM sessions     WHERE opened_epoch_ms >= ?)     AS today_sessions,
                       (SELECT COUNT(*) FROM auth_attempts WHERE ts_epoch_ms   >= ?)      AS today_auth,
                       (SELECT COUNT(*) FROM commands      WHERE ts_epoch_ms   >= ?)      AS today_commands,
                       (SELECT COUNT(*) FROM downloads     WHERE ts_epoch_ms   >= ?)      AS today_downloads,
                       (SELECT COUNT(DISTINCT src_ip) FROM ip_locks WHERE locked_until > datetime('now','localtime')) AS active_locks""")) {
            for (int i = 1; i <= 4; i++) ps.setLong(i, todayStart);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    m.put("totalSessions", rs.getLong(1));
                    m.put("totalAuth", rs.getLong(2));
                    m.put("totalCommands", rs.getLong(3));
                    m.put("totalDownloads", rs.getLong(4));
                    m.put("uniqueIps", rs.getLong(5));
                    m.put("todaySessions", rs.getLong(6));
                    m.put("todayAuth", rs.getLong(7));
                    m.put("todayCommands", rs.getLong(8));
                    m.put("todayDownloads", rs.getLong(9));
                    m.put("activeLocks", rs.getLong(10));
                }
            }
        }
        return m;
    }

    /** 最近 N 天按日趋势：会话 / 登录尝试 / 命令执行 */
    public List<Map<String, Object>> trend(int days) throws SQLException {
        Map<String, long[]> byDay = new LinkedHashMap<>();
        collectDaily(byDay, "SELECT substr(opened_at,1,10) d, COUNT(*) c FROM sessions WHERE substr(opened_at,1,10) >= ? GROUP BY d", days, 0);
        collectDaily(byDay, "SELECT substr(ts,1,10) d, COUNT(*) c FROM auth_attempts WHERE substr(ts,1,10) >= ? GROUP BY d", days, 1);
        collectDaily(byDay, "SELECT substr(ts,1,10) d, COUNT(*) c FROM commands WHERE substr(ts,1,10) >= ? GROUP BY d", days, 2);
        List<Map<String, Object>> rows = new ArrayList<>();
        byDay.forEach((day, arr) -> rows.add(Map.of("day", day, "sessions", arr[0], "auth", arr[1], "commands", arr[2])));
        rows.sort((a, b) -> ((String) a.get("day")).compareTo((String) b.get("day")));
        return rows;
    }

    private void collectDaily(Map<String, long[]> byDay, String sql, int days, int idx) throws SQLException {
        String since = LocalDate.now().minusDays(days - 1L).toString();
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, since);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    byDay.computeIfAbsent(rs.getString(1), k -> new long[3])[idx] = rs.getLong(2);
                }
            }
        }
    }

    /** 会话数按协议分布 */
    public List<Map<String, Object>> protocolDist() throws SQLException {
        return list("SELECT protocol AS name, COUNT(*) AS value FROM sessions GROUP BY protocol ORDER BY value DESC");
    }

    /** 攻击源 IP 排行（按登录尝试次数） */
    public List<Map<String, Object>> topIps(int limit) throws SQLException {
        return listLimit("SELECT src_ip AS name, COUNT(*) AS value FROM auth_attempts GROUP BY src_ip ORDER BY value DESC LIMIT ?", limit);
    }

    /** 攻击源地区排行（按登录尝试次数，国内按省份、国外按国家聚合，空值归入“未知”） */
    public List<Map<String, Object>> topLocations(int limit) throws SQLException {
        Map<String, Long> byRegion = new LinkedHashMap<>();
        try (Statement st = conn.createStatement(); ResultSet rs = st.executeQuery(
                "SELECT location, COUNT(*) FROM auth_attempts GROUP BY location")) {
            while (rs.next()) {
                byRegion.merge(regionOf(rs.getString(1)), rs.getLong(2), Long::sum);
            }
        }
        return byRegion.entrySet().stream()
                .sorted(Map.Entry.<String, Long>comparingByValue().reversed())
                .limit(limit)
                .map(e -> Map.<String, Object>of("name", e.getKey(), "value", e.getValue()))
                .toList();
    }

    /** location（国家 省份 城市）取地区名：国内取省份，国外取国家；非地域值（如内网IP）原样返回；空值返回“未知” */
    private static String regionOf(String location) {
        if (location == null || location.isBlank()) return "未知";
        String[] parts = location.trim().split("\\s+");
        if ("中国".equals(parts[0])) {
            return parts.length >= 2 ? parts[1] : parts[0]; // 国内按省份统计
        }
        return parts[0]; // 国外按国家统计
    }

    /** 被爆破用户名排行 */
    public List<Map<String, Object>> topUsernames(int limit) throws SQLException {
        return listLimit("SELECT username AS name, COUNT(*) AS value FROM auth_attempts GROUP BY username ORDER BY value DESC LIMIT ?", limit);
    }

    /** 被尝试口令排行 */
    public List<Map<String, Object>> topPasswords(int limit) throws SQLException {
        return listLimit("SELECT password AS name, COUNT(*) AS value FROM auth_attempts GROUP BY password ORDER BY value DESC LIMIT ?", limit);
    }

    /** 会话明细（分页，支持来源 IP / 协议 / 时间范围过滤） */
    public Map<String, Object> sessions(String srcIp, String protocol, Long start, Long end, int page, int size) throws SQLException {
        Where w = new Where();
        w.like("src_ip", srcIp);
        w.eq("protocol", protocol);
        w.range("opened_epoch_ms", start, end);
        return pageQuery("sessions", w, page, size, "ORDER BY opened_epoch_ms DESC, id DESC");
    }

    /** 登录尝试明细（分页，支持来源 IP / 用户名 / 协议 / 是否成功 / 时间范围过滤） */
    public Map<String, Object> authAttempts(String srcIp, String username, String protocol,
                                            Boolean success, Long start, Long end, int page, int size) throws SQLException {
        Where w = new Where();
        w.like("src_ip", srcIp);
        w.eq("username", username);
        w.eq("protocol", protocol);
        if (success != null) w.raw("success = " + (success ? 1 : 0));
        w.range("ts_epoch_ms", start, end);
        return pageQuery("auth_attempts", w, page, size, "ORDER BY ts_epoch_ms DESC, id DESC");
    }

    /** 命令执行明细（分页，支持来源 IP / 用户名 / 命令行关键字 / 时间范围过滤） */
    public Map<String, Object> commands(String srcIp, String username, String keyword,
                                        Long start, Long end, int page, int size) throws SQLException {
        Where w = new Where();
        w.like("src_ip", srcIp);
        w.eq("username", username);
        w.like("command", keyword);
        w.range("ts_epoch_ms", start, end);
        return pageQuery("commands", w, page, size, "ORDER BY ts_epoch_ms DESC, id DESC");
    }

    /** 恶意下载明细（分页，支持来源 IP / URL 关键字 / 时间范围过滤） */
    public Map<String, Object> downloads(String srcIp, String keyword,
                                         Long start, Long end, int page, int size) throws SQLException {
        Where w = new Where();
        w.like("src_ip", srcIp);
        w.like("url", keyword);
        w.range("ts_epoch_ms", start, end);
        return pageQuery("downloads", w, page, size, "ORDER BY ts_epoch_ms DESC, id DESC");
    }

    /** IP 锁定记录（分页，支持来源 IP 过滤；locked_active 表示当前是否仍在锁定中） */
    public Map<String, Object> ipLocks(String srcIp, int page, int size) throws SQLException {
        Where w = new Where();
        w.like("src_ip", srcIp);
        Map<String, Object> result = pageQuery("ip_locks", w, page, size, "ORDER BY ts_epoch_ms DESC, id DESC");
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> rows = (List<Map<String, Object>>) result.get("rows");
        try (PreparedStatement ps = conn.prepareStatement(
                "SELECT locked_until > datetime('now','localtime') FROM ip_locks WHERE id = ?")) {
            for (Map<String, Object> row : rows) {
                ps.setLong(1, ((Number) row.get("id")).longValue());
                try (ResultSet rs = ps.executeQuery()) {
                    row.put("lockedActive", rs.next() && rs.getInt(1) == 1);
                }
            }
        }
        return result;
    }

    // ============================ 内部工具 ============================

    /** 参数化 WHERE 条件构造器，所有过滤值均走占位符，杜绝 SQL 注入 */
    private static final class Where {
        final StringBuilder sql = new StringBuilder();
        final List<Object> params = new ArrayList<>();

        void raw(String cond) {
            sql.append(sql.isEmpty() ? " WHERE " : " AND ").append(cond);
        }

        void eq(String col, String value) {
            if (value != null && !value.isBlank()) {
                raw(col + " = ?");
                params.add(value.trim());
            }
        }

        void like(String col, String value) {
            if (value != null && !value.isBlank()) {
                raw(col + " LIKE ?");
                params.add("%" + value.trim() + "%");
            }
        }

        void range(String col, Long start, Long end) {
            if (start != null) { raw(col + " >= ?"); params.add(start); }
            if (end != null) { raw(col + " <= ?"); params.add(end); }
        }
    }

    private Map<String, Object> pageQuery(String table, Where w, int page, int size,
                                          String orderClause) throws SQLException {
        long total;
        try (PreparedStatement ps = conn.prepareStatement("SELECT COUNT(*) FROM " + table + w.sql)) {
            bind(ps, w.params);
            try (ResultSet rs = ps.executeQuery()) {
                total = rs.next() ? rs.getLong(1) : 0;
            }
        }
        List<Map<String, Object>> rows = new ArrayList<>();
        String sql = "SELECT * FROM " + table + w.sql + " " + orderClause + " LIMIT ? OFFSET ?";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            bind(ps, w.params);
            ps.setInt(w.params.size() + 1, size);
            ps.setLong(w.params.size() + 2, (long) (page - 1) * size);
            try (ResultSet rs = ps.executeQuery()) {
                int n = rs.getMetaData().getColumnCount();
                while (rs.next()) {
                    Map<String, Object> row = new LinkedHashMap<>();
                    for (int i = 1; i <= n; i++) row.put(rs.getMetaData().getColumnLabel(i), rs.getObject(i));
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

    private static void bind(PreparedStatement ps, List<Object> params) throws SQLException {
        for (int i = 0; i < params.size(); i++) {
            Object v = params.get(i);
            if (v instanceof Long l) ps.setLong(i + 1, l);
            else ps.setString(i + 1, String.valueOf(v));
        }
    }

    private List<Map<String, Object>> list(String sql) throws SQLException {
        List<Map<String, Object>> rows = new ArrayList<>();
        try (Statement st = conn.createStatement(); ResultSet rs = st.executeQuery(sql)) {
            while (rs.next()) {
                rows.add(Map.of("name", rs.getString(1), "value", rs.getLong(2)));
            }
        }
        return rows;
    }

    private List<Map<String, Object>> listLimit(String sql, int limit) throws SQLException {
        List<Map<String, Object>> rows = new ArrayList<>();
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setInt(1, limit);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    rows.add(Map.of("name", rs.getString(1), "value", rs.getLong(2)));
                }
            }
        }
        return rows;
    }

    @Override
    public void close() throws SQLException {
        conn.close();
    }
}
