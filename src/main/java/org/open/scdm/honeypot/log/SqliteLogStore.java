package org.open.scdm.honeypot.log;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

/**
 * SQLite 攻击日志持久化存储：将 JSONL 文件中的同一份数据再结构化保存一份，
 * 供后续 Web 可视化直接 SQL 查询。
 * <p>
 * 表结构与 JSONL 事件类型对应关系：
 * <ul>
 *   <li>session_open  -> sessions（插入）</li>
 *   <li>session_close -> sessions（更新 closed_at / duration_ms）</li>
 *   <li>auth_attempt  -> auth_attempts</li>
 *   <li>command       -> commands</li>
 *   <li>download      -> downloads</li>
 *   <li>ip_locked     -> ip_locks</li>
 * </ul>
 * user_version 3 起，所有含来源 IP 的事件表均带 location 归属地列。
 * 线程安全说明：所有写入均由 AttackLogger 的单线程异步写入器串行调用，
 * 共享单个 Connection 是安全的；WAL 模式允许 Web 端并发只读而不阻塞写入。
 */
public class SqliteLogStore implements AutoCloseable {

    private static final DateTimeFormatter TS = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS");

    /** 建表与建索引语句（幂等）；数据库版本通过 user_version 管理，便于以后迁移 */
    private static final String[] SCHEMA = {
            """
            CREATE TABLE IF NOT EXISTS sessions (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id      TEXT    NOT NULL UNIQUE,   -- 会话编号（对应 JSONL 的 session 字段）
                protocol        TEXT    NOT NULL,          -- 协议: ssh / telnet / mysql / postgresql / redis
                src_ip          TEXT    NOT NULL,          -- 攻击者来源 IP
                src_port        INTEGER,                   -- 攻击者来源端口
                opened_at       TEXT    NOT NULL,          -- 会话开始时间 yyyy-MM-dd HH:mm:ss.SSS
                opened_epoch_ms INTEGER NOT NULL,          -- 会话开始时间（epoch 毫秒，便于时间范围统计）
                closed_at       TEXT,                      -- 会话结束时间（异常断开时为 NULL）
                duration_ms     INTEGER,                   -- 会话持续时长（毫秒）
                location        TEXT                       -- 来源 IP 归属地（国家 省份 城市，ip2region 库解析）
            )""",
            "CREATE INDEX IF NOT EXISTS idx_sessions_src_ip ON sessions(src_ip)",
            "CREATE INDEX IF NOT EXISTS idx_sessions_opened ON sessions(opened_epoch_ms)",
            """
            CREATE TABLE IF NOT EXISTS auth_attempts (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ts          TEXT    NOT NULL,              -- 事件时间 yyyy-MM-dd HH:mm:ss.SSS
                ts_epoch_ms INTEGER NOT NULL,              -- 事件时间（epoch 毫秒）
                session_id  TEXT,                          -- 所属会话编号
                protocol    TEXT,                          -- 协议: ssh / telnet / mysql / postgresql / redis
                src_ip      TEXT    NOT NULL,              -- 攻击者来源 IP
                username    TEXT    NOT NULL,              -- 尝试登录的用户名
                password    TEXT    NOT NULL,              -- 尝试登录的口令
                success     INTEGER NOT NULL CHECK (success IN (0, 1)),  -- 是否登录成功(蜜罐放行)
                location    TEXT                           -- 来源 IP 归属地（国家 省份 城市，ip2region 库解析）
            )""",
            "CREATE INDEX IF NOT EXISTS idx_auth_src_ip ON auth_attempts(src_ip)",
            "CREATE INDEX IF NOT EXISTS idx_auth_username ON auth_attempts(username)",
            "CREATE INDEX IF NOT EXISTS idx_auth_ts ON auth_attempts(ts_epoch_ms)",
            """
            CREATE TABLE IF NOT EXISTS commands (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ts          TEXT    NOT NULL,
                ts_epoch_ms INTEGER NOT NULL,
                session_id  TEXT,
                src_ip      TEXT    NOT NULL,
                username    TEXT,
                command     TEXT    NOT NULL,              -- 执行的完整命令行
                location    TEXT                           -- 来源 IP 归属地（国家 省份 城市，ip2region 库解析）
            )""",
            "CREATE INDEX IF NOT EXISTS idx_commands_session ON commands(session_id)",
            "CREATE INDEX IF NOT EXISTS idx_commands_src_ip ON commands(src_ip)",
            "CREATE INDEX IF NOT EXISTS idx_commands_ts ON commands(ts_epoch_ms)",
            """
            CREATE TABLE IF NOT EXISTS downloads (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ts          TEXT    NOT NULL,
                ts_epoch_ms INTEGER NOT NULL,
                session_id  TEXT,
                src_ip      TEXT    NOT NULL,
                username    TEXT,
                url         TEXT    NOT NULL,              -- 恶意下载 URL
                location    TEXT                           -- 来源 IP 归属地（国家 省份 城市，ip2region 库解析）
            )""",
            "CREATE INDEX IF NOT EXISTS idx_downloads_src_ip ON downloads(src_ip)",
            "CREATE INDEX IF NOT EXISTS idx_downloads_ts ON downloads(ts_epoch_ms)",
            """
            CREATE TABLE IF NOT EXISTS ip_locks (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                ts           TEXT    NOT NULL,
                ts_epoch_ms  INTEGER NOT NULL,
                src_ip       TEXT    NOT NULL,             -- 被锁定的源 IP
                locked_until TEXT    NOT NULL,             -- 锁定解除时间
                location     TEXT                          -- 来源 IP 归属地（国家 省份 城市，ip2region 库解析）
            )""",
            "CREATE INDEX IF NOT EXISTS idx_ip_locks_src_ip ON ip_locks(src_ip)",
            "CREATE INDEX IF NOT EXISTS idx_ip_locks_ts ON ip_locks(ts_epoch_ms)"
    };

    private final Connection conn;
    private final PreparedStatement insertSession;
    private final PreparedStatement closeSession;
    private final PreparedStatement insertAuth;
    private final PreparedStatement insertCommand;
    private final PreparedStatement insertDownload;
    private final PreparedStatement insertIpLock;

    public SqliteLogStore(Path dbFile) throws IOException, SQLException {
        Path abs = dbFile.toAbsolutePath();
        if (abs.getParent() != null) {
            Files.createDirectories(abs.getParent());
        }
        this.conn = DriverManager.getConnection("jdbc:sqlite:" + abs);
        try (Statement st = conn.createStatement()) {
            st.execute("PRAGMA journal_mode=WAL");   // 读写并发：Web 端查询不阻塞蜜罐写入
            st.execute("PRAGMA synchronous=NORMAL"); // WAL 模式下兼顾写入性能与可靠性
            st.execute("PRAGMA busy_timeout=5000");
            for (String ddl : SCHEMA) {
                st.execute(ddl);
            }
            // 版本迁移（user_version < 2 的旧库）：sessions 补加 location 列；
            // （user_version < 3 的旧库）：其余含来源 IP 的事件表补加 location 列。
            // 新建库的 DDL 已含该列，重复 ALTER 报错时忽略即可
            int version = 0;
            try (var rs = st.executeQuery("PRAGMA user_version")) {
                if (rs.next()) version = rs.getInt(1);
            }
            if (version < 2) {
                try {
                    st.execute("ALTER TABLE sessions ADD COLUMN location TEXT");
                } catch (SQLException ignored) {
                    // 列已存在（新建库）
                }
            }
            if (version < 3) {
                for (String table : new String[]{"auth_attempts", "commands", "downloads", "ip_locks"}) {
                    try {
                        st.execute("ALTER TABLE " + table + " ADD COLUMN location TEXT");
                    } catch (SQLException ignored) {
                        // 列已存在（新建库）
                    }
                }
            }
            st.execute("PRAGMA user_version=3");
        }
        insertSession = conn.prepareStatement(
                "INSERT INTO sessions(session_id, protocol, src_ip, src_port, opened_at, opened_epoch_ms, location) VALUES(?,?,?,?,?,?,?)");
        closeSession = conn.prepareStatement(
                "UPDATE sessions SET closed_at = ?, duration_ms = ? WHERE session_id = ?");
        insertAuth = conn.prepareStatement(
                "INSERT INTO auth_attempts(ts, ts_epoch_ms, session_id, protocol, src_ip, username, password, success, location) VALUES(?,?,?,?,?,?,?,?,?)");
        insertCommand = conn.prepareStatement(
                "INSERT INTO commands(ts, ts_epoch_ms, session_id, src_ip, username, command, location) VALUES(?,?,?,?,?,?,?)");
        insertDownload = conn.prepareStatement(
                "INSERT INTO downloads(ts, ts_epoch_ms, session_id, src_ip, username, url, location) VALUES(?,?,?,?,?,?,?)");
        insertIpLock = conn.prepareStatement(
                "INSERT INTO ip_locks(ts, ts_epoch_ms, src_ip, locked_until, location) VALUES(?,?,?,?,?)");
    }

    public void recordSessionOpen(LocalDateTime ts, String sessionId, String protocol,
                                  String ip, int port, String location) throws SQLException {
        insertSession.setString(1, sessionId);
        insertSession.setString(2, protocol);
        insertSession.setString(3, ip);
        insertSession.setInt(4, port);
        insertSession.setString(5, ts.format(TS));
        insertSession.setLong(6, toEpochMs(ts));
        insertSession.setString(7, location);
        insertSession.executeUpdate();
    }

    public void recordSessionClose(LocalDateTime ts, String sessionId, long durationMs) throws SQLException {
        closeSession.setString(1, ts.format(TS));
        closeSession.setLong(2, durationMs);
        closeSession.setString(3, sessionId);
        closeSession.executeUpdate();
    }

    public void recordAuthAttempt(LocalDateTime ts, String sessionId, String protocol, String ip,
                                  String username, String password, boolean success,
                                  String location) throws SQLException {
        insertAuth.setString(1, ts.format(TS));
        insertAuth.setLong(2, toEpochMs(ts));
        insertAuth.setString(3, sessionId);
        insertAuth.setString(4, protocol);
        insertAuth.setString(5, ip);
        insertAuth.setString(6, username);
        insertAuth.setString(7, password);
        insertAuth.setInt(8, success ? 1 : 0);
        insertAuth.setString(9, location);
        insertAuth.executeUpdate();
    }

    public void recordCommand(LocalDateTime ts, String sessionId, String ip,
                              String username, String cmdline, String location) throws SQLException {
        insertCommand.setString(1, ts.format(TS));
        insertCommand.setLong(2, toEpochMs(ts));
        insertCommand.setString(3, sessionId);
        insertCommand.setString(4, ip);
        insertCommand.setString(5, username);
        insertCommand.setString(6, cmdline);
        insertCommand.setString(7, location);
        insertCommand.executeUpdate();
    }

    public void recordDownload(LocalDateTime ts, String sessionId, String ip,
                               String username, String url, String location) throws SQLException {
        insertDownload.setString(1, ts.format(TS));
        insertDownload.setLong(2, toEpochMs(ts));
        insertDownload.setString(3, sessionId);
        insertDownload.setString(4, ip);
        insertDownload.setString(5, username);
        insertDownload.setString(6, url);
        insertDownload.setString(7, location);
        insertDownload.executeUpdate();
    }

    public void recordIpLocked(LocalDateTime ts, String ip, long untilMillis,
                               String location) throws SQLException {
        String until = LocalDateTime.ofInstant(Instant.ofEpochMilli(untilMillis),
                ZoneId.systemDefault()).format(TS);
        insertIpLock.setString(1, ts.format(TS));
        insertIpLock.setLong(2, toEpochMs(ts));
        insertIpLock.setString(3, ip);
        insertIpLock.setString(4, until);
        insertIpLock.setString(5, location);
        insertIpLock.executeUpdate();
    }

    private static long toEpochMs(LocalDateTime ts) {
        return ts.atZone(ZoneId.systemDefault()).toInstant().toEpochMilli();
    }

    @Override
    public void close() throws SQLException {
        conn.close();
    }
}
